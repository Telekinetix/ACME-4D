# Code Review Findings — `tk-acme`

**Reviewed:** commits `510a3ad`..`8b2b010` (Thomas Bartram, 28 Aug – 2 Sep 2026) against `ece3d57` (initial commit)
**Reviewer:** Claude (Opus 5), for J. Cryer
**Date:** 4 September 2026
**Scope:** correctness review of the component sources plus an accuracy audit of `README.md` and `Documentation/`.

No code was changed as part of this review. Every item below is recorded here rather than filed as a
GitHub issue, by request. Documentation and README corrections arising from these findings *have*
been applied — see the "Documentation changes applied" section at the end.

---

## 1. What Tom fixed (verified correct)

The bulk of this branch is genuine correctness work, not cosmetics. Confirmed:

| # | Change | Assessment |
|---|--------|-----------|
| 1 | `ACMECsr._signBlob()` now calls `.sign($vb_data; {hash:"SHA256"; encoding:"Base64"})` with the raw DER blob | **Correct — and it closes the project's headline blocker.** The [4D.CryptoKey docs](https://developer.4d.com/docs/API/CryptoKeyClass) document a Blob overload: `.sign(message : Blob; options : Object) : Text`. The old code signed the *base64 text* of the DER, which does not produce a standards-compliant PKCS#10. Kickoff spike §7.1 is resolved. |
| 2 | `ACMEJwsSigner._buildJws()` argument order corrected to `sign($message; $options)` | **Correct.** The original had the arguments reversed (`sign($options; $input)`), which would have failed on every single ACME request. |
| 3 | `ACMEJwsSigner._buildPublicJwk()` replaced with a real PEM → DER → ASN.1 parse producing `{kty, n, e}` | **Correct.** 4D exposes no JWK/JWKS export, so hand-parsing `SubjectPublicKeyInfo` was the only route. The DER walk (outer SEQUENCE → skip AlgorithmIdentifier → BIT STRING + unused-bits byte → inner SEQUENCE → two INTEGERs, with the leading-zero pad stripped) is right. Resolves the second open spike. |
| 4 | `_sha256Blob()` reworked; new `_hexToInt()` helper | **Correct, and a real bug fix.** The original hex-decoded `Generate digest` output with `Num("0x"+$vt_byte)`, which does not parse hex in 4D and would have silently produced a zeroed digest — i.e. a wrong JWK thumbprint and a `keyAuthorization` the CA would always reject. |
| 5 | `_derExtensionRequestAttr()` — removed a redundant `SEQUENCE` wrapper | **Correct.** PKCS#9 `extensionRequest` is `SET { Extensions }`, and `Extensions ::= SEQUENCE OF Extension`. The old code wrapped `Extensions` in a second SEQUENCE, producing a malformed SAN attribute. |
| 6 | `File()` / `Folder()` calls throughout now pass `fk platform path` | **Correct and necessary.** `certPath` / `keyPath` / `storePath` are documented as native platform paths; without the selector 4D interprets them as POSIX paths relative to the project. |
| 7 | Lower-case header fallbacks for `replay-nonce` and `location` | **Correct** — see finding B below, which is the half of this fix that was missed. |
| 8 | `_downloadCertificate()` and `_executeWithRetry()` handle a Blob/object response body | Pragmatic. The inline comment is honest about the uncertainty. |
| 9 | `ACMEAccount.register()` — extra `$vo_response.headers.location` fallback | Harmless belt-and-braces. |
| 10 | `Resources/en.lproj/syntaxEN.json` added (1241 lines) | **Good addition, previously undocumented.** Gives the host application IDE autocomplete for `cs.acme.*`. Its contents match the current public API exactly. Now mentioned in the README. |

Hex literals were also normalised to 4-digit form (`0x30` → `0x0030`) and the `Else If` chain in
`_derTLV()` became a `Case of`. Both are 4D-idiomatic, no behaviour change.

---

## 2. Findings

### A. Regression — `ACMEScheduler._computeNextCheck()` never seeds the base date

**Severity: high.** `Project/Sources/Classes/ACMEScheduler.4dm`, `_computeNextCheck()`.

```4d
var $vd_next : Date
If ((This._checkIntervalHours\24)=0)
    $vd_next:=Current date+1
Else
    $vd_next:=Add to date($vd_next; 0; 0; This._checkIntervalHours\24)
End if
return $vd_next
```

`$vd_next` is declared but never assigned before the `Add to date()` call, so it is the null date
`!00-00-00!`. With the default `_checkIntervalHours` of 24, `24\24` is `1`, not `0` — so the `Else`
branch is always the one taken, and the function returns roughly `!00-00-00!` + 1 day rather than
tomorrow's date.

The original code was correct:

```4d
$vd_next:=Current date+This._checkIntervalHours\24
If (This._checkIntervalHours\24=0)
    $vd_next:=Current date+1
End if
```

**Impact:** `Storage.acme.scheduler.nextCheck` and the `nextCheck` field in `acme-cert-meta.json`
both report a nonsense date. This is the fleet-monitoring surface described in kickoff §9, so the
monitoring value is lost. It does *not* stop renewals — `check()` is driven by the host's timer, and
`nextCheck` is never read back as a gate.

**Fix:** seed `$vd_next:=Current date` before the `Add to date()`, or restore the original one-liner.

---

### B. `_captureNonce()` still only matches the capitalised header name

**Severity: medium.** `Project/Sources/Classes/ACMETransport.4dm`, `_captureNonce()`.

```4d
If ($headers#Null) && (OB Is defined($headers; "Replay-Nonce"))
    This._nonce:=String($headers["Replay-Nonce"])
End if
```

Tom added a lower-case fallback to `freshNonce()` and to the `Location` capture in
`_executeWithRetry()`, which is strong evidence that 4D surfaces response headers lower-cased in
practice. `_captureNonce()` was not given the same treatment, so the nonce cache is never populated.

**Impact:** every signed request falls through to the `HEAD newNonce` path in `freshNonce()`,
roughly doubling the request count against the CA. Functionally correct, but it burns rate-limit
budget and adds a round-trip to each step. It also means the "avoids an extra round-trip on each
call" behaviour described in `Documentation/Classes/ACMETransport.md` never actually happens.

**Fix:** mirror the `freshNonce()` pattern — check `"replay-nonce"` then `"Replay-Nonce"`.

---

### C. Retries replay a consumed nonce

**Severity: medium.** Pre-existing, not introduced by this branch.
`Project/Sources/Classes/ACMETransport.4dm`, `_executeWithRetry()`.

Both retry paths (network failure, and HTTP 5xx) re-invoke `_executeWithRetry()` with the *same*
`$vo_options` object — including the already-built JWS body, whose `protected` header carries the
nonce that was just consumed. RFC 8555 nonces are strictly single-use, so the retry will be rejected
with `urn:ietf:params:acme:error:badNonce`.

`Documentation/Classes/ACMETransport.md` claims "If the CA returns `badNonce` the caller should
discard the nonce and retry (handled by the back-off path)" — nothing implements that.

**Impact:** the retry policy is effectively dead for signed requests. It works correctly for
`_rawGet()` (directory fetch), which carries no JWS.

**Fix:** move the retry loop above JWS construction so each attempt gets a fresh nonce, or special-case
`badNonce` in `_signedRequest()` and re-sign.

---

### D. `File append` is not a 4D constant

**Severity: medium (dormant).** `Project/Sources/Classes/ACMELogger.4dm:140`.

```4d
$vf.setText($vt_line; "utf-8"; File append)
```

`4D.File.setText()` takes `(text {; charSet {; breakMode}})` — there is no append mode, and no
`File append` constant exists. Corroborating evidence: every other 4D constant in the codebase
carries its token (`fk platform path:K87:2`, `UTF8 text without length:K22:17`), but `File append`
does not — 4D did not recognise it, which is exactly what you would expect from a name invented by
the original generation pass.

**Impact:** currently dormant. `logToFile` defaults to `False`, so the branch never runs. Anyone who
turns the file sink on hits a runtime error — silently, because the surrounding `Try`/`Catch` swallows
it by design. The sink would simply never write.

**Fix:** read-modify-write the existing file contents, or use `4D.FileHandle` for true appends.
`Documentation/Classes/ACMELogger.md` has been updated to warn that the sink is unverified.

---

### E. `ACME_Challenge_Handler` takes a parameter the documented call sites do not pass

**Severity: medium.** `Project/Sources/Methods/ACME_Challenge_Handler.4dm`.

The method declares `#DECLARE($vt_url : Text)`, but both the README and
`Documentation/Methods/ACME_Challenge_Handler.md` showed it being called with no arguments:

```4d
If (Match regex("^\/.well-known\/acme-challenge\/"; $1; 1; $pos; $len))
    ACME_Challenge_Handler          // ← no $1 passed
    return
End if
```

`$vt_url` would be empty, `Position()` returns 0, and every challenge request redirects to `/`.
The CA then fails validation and the certificate is never issued.

The method documentation also claimed the method "reads `WEB GET HTTP HEADER("url")` to get the
request URL, or falls back to `$1`". It does neither — the URL only ever arrives as a parameter.

**Documentation fixed:** both call sites now show `ACME_Challenge_Handler($1)`, and the invented
`WEB GET HTTP HEADER` behaviour has been removed.

**Secondary code point, not fixed:** on a token miss the method issues `WEB SEND HTTP REDIRECT("/")`
— a 302, not the 404 the comment claims. A redirect on `/.well-known/acme-challenge/*` is worth
avoiding; some ACME servers treat a 2xx-after-redirect as a validation attempt with the wrong body,
which produces a more confusing failure than a clean 404. `WEB SEND RAW DATA` with a 404 status, or
`WEB SET HTTP HEADER`, would be clearer.

---

### F. Crash-safe order resume is not wired up

**Severity: medium.** `Project/Sources/Classes/ACMEOrder.4dm` / `ACMEClient.4dm`.

`ACMEOrder.loadOrderState()` is fully implemented and `_saveOrderState()` is called after
`_createOrder()` and after a successful `_pollOrder()`. But **nothing ever calls
`loadOrderState()`** — `ACMEClient.renew()` constructs a fresh `ACMEOrder` and always starts at
`_createOrder()`.

This contradicts:
- Kickoff §4 hard constraint 4 — "A renewal interrupted mid-flight must recover cleanly on next run".
- Kickoff §9 — "resume an interrupted order".
- The README feature bullet "Crash-safe — … interrupted runs resume cleanly".
- `Documentation/Classes/ACMEOrder.md` — "Called by `ACMEClient` to detect and resume interrupted runs".

**Impact:** an interrupted run starts a brand-new order. Not dangerous (LE tolerates abandoned
pending orders, and existing valid authorizations are reused via the `status="valid"` short-circuit
in `_processAuthorization`), but it consumes `newOrder` rate-limit budget and the stale
`order-<host>.json` files accumulate and are never cleaned up.

**Documentation fixed:** README and `ACMEOrder.md` now describe state persistence as written-but-not-yet-
consumed, rather than claiming working resume.

---

### G. Jitter is not implemented anywhere

**Severity: medium.** `Project/Sources/Classes/ACMEScheduler.4dm`, `_applyAriJitter()`.

```4d
$vo_jittered:=New object("start"; String($vo_window.start); "end"; String($vo_window.end))
// Jitter: shift start forward by a random 0–30% of the window duration.
// Full implementation requires date arithmetic in seconds — use as-is for now.
return $vo_jittered
```

The function copies the window and returns it unchanged. There is no jitter in the time-based
fallback path either — `ACMECertStore.needsRenewal()` uses a flat ⅔-of-lifetime threshold, and the
comment there ("+ jitter (jitter applied in scheduler)") points at a scheduler that does not apply any.

This contradicts kickoff §9 ("Jitter on renewal timing to avoid synchronised CA hits across many
systems sharing this component"), the README feature bullet "Fleet-friendly — jitter prevents
synchronised CA hits across many deployments", and `Documentation/Classes/ACMEScheduler.md`.

**Impact:** for a single deployment, none. For the fleet this component is explicitly built for, every
system with the same cert lifetime renews on the same day. Also note `_applyAriJitter()` is only ever
reached from `_checkAri()`, which currently always short-circuits (see H), so today it is unreachable
regardless.

**Documentation fixed:** the jitter claims are now marked as not-yet-implemented in both the README and
`ACMEScheduler.md`.

---

### H. ARI remains a stub (unchanged, still accurately documented)

**Severity: known gap, no action needed beyond tracking.**

`ACMEScheduler._buildAriUrl()` still returns `""` unconditionally, so `_checkAri()` always returns
`False` and the scheduler always uses the time-based fallback. Same root cause as I below: the ARI
URL needs `issuerKeyHash` and `serial` from the issued certificate's DER.

The good news is that the ASN.1 reader Tom wrote for `ACMEJwsSigner` (`_derExpectTag`,
`_derReadLength`, `_derReadInteger`) is most of the machinery needed. Lifting those into a shared
helper would unblock both this and I.

---

### I. `notAfter` parsing remains a stub (unchanged, still accurately documented)

**Severity: known gap.**

`ACMECertStore._extractNotAfterFromPem()` returns `!00-00-00!` unconditionally, so every issued
certificate is recorded with `notAfter = today + 90 days`.

**Impact is now larger than the README implied.** Because ARI never returns a window (H), the
time-based fallback is the *only* renewal trigger, and it is computed from an assumed lifetime rather
than the real one. That assumption is safe for today's 90-day Let's Encrypt certificates and stays safe
as lifetimes shrink (a shorter real lifetime means the assumed date is later than the truth, but the
⅔ threshold on the assumed 90 days — day 60 — would then fall *after* a 47-day cert has already
expired). **This becomes a correctness bug, not just an imprecision, once cert lifetimes drop below
~90 days** — which under SC-081v3 is March 2027 for 100-day certs and is already the case if the CA
issues shorter. Worth treating as the next blocker after this branch.

The README and `ACMECertStore.md` now state this consequence explicitly rather than describing it as
a mere precision gap.

---

### J. Multi-identifier config is accepted but only the first identifier is certified

**Severity: medium.**

`ACMEConfig` offers `addIdentifier()` and `setIdentifiers()`, and `ACMEOrder._createOrder()`
faithfully sends every identifier in the `newOrder` payload — so the CA issues one authorization per
name and the component dutifully validates all of them. But `_finalize()` builds the CSR from
`identifiers[0]` only:

```4d
$vt_hostname:=String(This._config.identifiers[0])
$vt_csrB64url:=$vo_csr.build($vt_certPrivKeyPem; $vt_hostname)
```

`ACMECsr.build()` likewise takes a single `$vt_hostname` and emits one CN and one SAN `dNSName`.

**Impact:** configuring two hostnames does the full HTTP-01 dance for both, then submits a CSR that
covers one — and the CA rejects finalize with a CSR/identifier mismatch. The failure comes late, after
all the validation work, and the error message from the CA is not obviously about this.

Nothing in `ACMEConfig`'s validation or in `Documentation/Classes/ACMEConfig.md` warned about this;
only an inline `// MVP: single hostname` comment in `_finalize()` did. Kickoff §3 does list SAN
certificates as "Later", so the limitation is intended — it is the silent acceptance that is the problem.

**Fix suggestion:** have `ACMEConfig.isValid()` reject more than one identifier until SAN support
lands, so the failure is immediate and legible.

**Documentation fixed:** README, `ACMEConfig.md` and `ACMECsr.md` now state the single-hostname limit
explicitly.

---

### K. `sign()` options use an undocumented `algorithm` key in one place and `hash` in another

**Severity: low.**

- `ACMEJwsSigner._buildJws()` → `New object("algorithm"; "RS256"; "encoding"; "Base64URL")`
- `ACMECsr._signBlob()` → `New object("hash"; "SHA256"; "encoding"; "Base64")`

The [4D.CryptoKey documentation](https://developer.4d.com/docs/API/CryptoKeyClass) lists `hash`,
`encoding`, and `pss` as the option keys for `.sign()`. `algorithm` is not among them, so the JWS
path is almost certainly relying on the default digest happening to be SHA-256 rather than on the
option it thinks it is passing. It works, but it works by accident, and it will keep working only as
long as that default holds.

**Fix:** use `hash: "SHA256"` in both places for consistency and explicitness.

---

### L. Dead code left behind

**Severity: low (tidy-up).**

1. `ACMECsr.build()` — `$vo_signOpts` and `$vt_criB64` are declared and assigned (including a
   `BASE64 ENCODE($vb_cri; $vt_criB64; *)` call) and then never used. Leftovers from the pre-fix
   base64-signing workaround.
2. `ACMEJwsSigner` — ~60 lines of the old `_buildPublicJwk()` remain as a commented-out block,
   including a stale "SPIKE RESULT" narrative that now contradicts the working implementation
   sitting directly above it. It reads as current guidance to anyone skimming the file.
3. `ACMEJwsSigner.jwkThumbprint()` — the now-unused `$vb_hash` declaration and a commented-out
   `//return This._base64urlBlob($vb_hash)`.
4. `ACMECsr._derIA5String()` is defined but never called (the SAN uses `_derTLV(0x0082; …)` directly).

---

### M. `ACMEJwsSigner._pos` is a parser cursor stored as instance state

**Severity: low (latent).**

The DER reader keeps its position in `This._pos` rather than threading it through the helpers. It is
safe today — `_parseRsaPublicKey()` is called once from the constructor and resets `_pos` to 0 — but
it makes the four `_der*` helpers non-reentrant, and it means a signer instance carries a stale cursor
for its whole life. If the ASN.1 helpers are lifted into a shared parser for findings H and I, this
should be refactored to pass position explicitly.

---

### N. Class-header usage examples show the wrong class-store path

**Severity: low, but it is the first thing an integrator reads.**

`Project/Sources/settings.4DSettings` sets `component_classStore_name="acme"`, so a host application
must write `cs.acme.ACMEClient`. Internal component code correctly uses bare `cs.ACMEClient`.

However the *host-facing usage examples* in the class header comments were rewritten to the internal
form during Tom's pass:

```4d
// Usage (host application):
//   var $cfg : cs.ACMEConfig        ← wrong for a host; needs cs.acme.ACMEConfig
```

This appears in `ACMEConfig.4dm` and `ACMEClient.4dm`. The `.md` documentation and the README both
use the correct `cs.acme.*` form throughout, so the source comments are now the odd ones out.

---

### O. Duplicate `//%attributes` line in `ACME_Challenge_Handler.4dm`

**Severity: low.** The file opens with `//%attributes = {"shared":true}` and then carries a second
`//%attributes = {}` after the comment block. 4D reads the first, and `syntaxEN.json` confirms the
method is correctly exported as shared — but the stray second line looks like it is un-sharing the
method and should be deleted.

---

### P. Unresolved — actual minimum 4D version

**Severity: high, blocking accurate documentation. Needs Tom.**

The component uses `Try` / `Catch` / `End try` blocks extensively (`ACMEAccount.load()`, `.save()`,
`ACMECsr.build()`, `._publicKeyDerFromPem()`, `._signBlob()`, `ACMECertStore` throughout,
`ACMEOrder._saveOrderState()`, `ACMELogger._log()`, and more), plus the `Try(expression)` form in
`ACMETransport._executeWithRetry()` and `ACMEScheduler._checkAri()`.

Try/Catch blocks were introduced in **4D 20 R5**. The
[4D v20 LTS error-handling documentation](https://developer.4d.com/docs/20/Concepts/error-handling)
documents only `ON ERR CALL` — no Try, no Catch. R-release features are not backported into the
20.x LTS line.

But `Project/4D 20.2.lnk` resolves to `C:\Program Files\4D\4D v20.2\4D\4D.exe`, and both the README
and kickoff §4 state 4D v20.0 LTS as a hard floor.

These cannot all be true. Either the shortcut is stale and Tom ran a newer 4D, or the Try blocks are
not doing what the code assumes on 20.2. Since every one of them wraps a filesystem or crypto call
whose failure is meant to be caught, a silent mismatch here would show up as unexplained errors
escaping to the host's error handler.

**Action:** confirm with Tom which 4D build produced the successful run. Until then the README
Requirements section records the version as unverified and flags the kickoff constraint as at risk.

---

## 3. Documentation changes applied

All of the following were corrected as part of this review. No source files were touched.

| File | Change |
|------|--------|
| `README.md` | Status line rewritten (spikes 1 and 2 resolved, first successful issuance). Open Spikes section reduced to the two genuinely open items (`notAfter`, ARI) with H/I consequences spelled out. Requirements section rewritten around the unresolved version question (P). `ACME_Challenge_Handler` example fixed to pass `$1` (E). Jitter (G) and crash-safe resume (F) feature bullets qualified. Single-hostname limit stated (J). `syntaxEN.json` documented. |
| `Documentation/Classes/ACMECsr.md` | "Known Limitation — Signing Raw DER" replaced with the resolved implementation. CSR structure diagram corrected to match the fixed `extensionRequest` encoding (5). Single-hostname limit made explicit (J). |
| `Documentation/Classes/ACMEJwsSigner.md` | Stale JWKS spike note replaced with the DER-parsing implementation (3). New internal helpers documented. `_sha256Blob` return type corrected to Text (4). Note added on the `algorithm`/`hash` option inconsistency (K). |
| `Documentation/Classes/ACMEScheduler.md` | Jitter described as not implemented (G). `_computeNextCheck` regression noted (A). ARI limitation kept, cross-referenced to this file. |
| `Documentation/Classes/ACMEOrder.md` | Resume described accurately as written-but-unused (F). State-persistence write points corrected. Single-hostname finalize limit stated (J). |
| `Documentation/Classes/ACMECertStore.md` | `needsRenewal()` flow corrected — it keys off the metadata file, not the certificate file, and an ARI "not yet" verdict short-circuits everything else. `notAfter` limitation escalated per I. |
| `Documentation/Classes/ACMETransport.md` | Nonce-caching claim corrected (B). Retry policy corrected — signed requests replay a consumed nonce (C). |
| `Documentation/Classes/ACMELogger.md` | File sink flagged as unverified (D). `LOG EVENT` destination corrected to the 4D commands log. |
| `Documentation/Classes/ACMEConfig.md` | Single-identifier limitation documented (J). |
| `Documentation/Classes/ACMEClient.md` | `_isSetup` added to the properties table; `_regenerateKeyViaJwks` description corrected — there is no JWKS path, it regenerates and re-parses. |
| `Documentation/Methods/ACME_Challenge_Handler.md` | Call signature corrected to `ACME_Challenge_Handler($1)`; invented `WEB GET HTTP HEADER` behaviour removed; redirect-vs-404 behaviour described accurately (E). |

`docs/tk-acme-component-kickoff.md` was deliberately **not** edited. It is a dated kickoff brief and
reads as a historical record; its §4 constraints are now partly unmet (see F, G, P), which is exactly
the sort of drift a brief should preserve rather than hide.

---

## 4. Suggested priority

1. **P** — confirm the 4D version with Tom. Everything else is documented against an unknown floor.
2. **A** — one-line fix, restores the monitoring surface.
3. **I** — real `notAfter` parsing. Becomes a correctness bug, not a nicety, as lifetimes shorten.
4. **B**, **C** — nonce handling. Halves CA traffic and makes retries actually work.
5. **J** — reject multi-identifier config in `isValid()` until SAN support lands.
6. **F**, **G** — deliver the two kickoff constraints that are currently claimed but absent.
7. **D**, **E** (redirect), **K** — small correctness cleanups.
8. **L**, **M**, **N**, **O** — tidy-up.
