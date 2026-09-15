# tk-acme — 4D ACME / Let's Encrypt Component

> **Certificates that renew themselves, inside 4D. No certbot, no cron, no shell.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

By **[Telekinetix Limited](https://telekinetix.com)** — carrying forward the path opened by
[Bruno Legay's `acme_component`](https://github.com/blegay/acme_component), rebuilt for the
47-day certificate era.

A self-contained 4D component that obtains and automatically renews TLS certificates from any ACMEv2 certificate authority (Let's Encrypt by default), so that the host application's web/REST server can serve HTTPS without any external tooling — no `certbot`, no `acme.sh`, no shell scripts, no cron jobs.

**Current status:** Working against a live CA. The two blocking spikes from the initial implementation —
raw-DER CSR signing and JWK extraction from a PEM key — are both resolved, and the component has
completed a full account → order → HTTP-01 → finalize → download cycle in a 4D database.

Two gaps remain open before this is ready for unattended fleet deployment: certificate `notAfter`
parsing and the ARI URL. See [Open Spikes](#open-spikes). A full review of the current state,
including several items that are implemented-but-not-wired-up, is in
[`docs/review-findings.md`](docs/review-findings.md).

---

## Why Automated ACME?

Public TLS certificate maximum lifetimes are on a fixed reduction schedule (CA/Browser Forum ballot SC-081v3):

| Date | Max cert lifetime |
|------|------------------|
| Until 15 Mar 2026 | 398 days |
| From 15 Mar 2026 | **200 days** |
| From 15 Mar 2027 | **100 days** |
| From 15 Mar 2029 | **47 days** |

At 47-day validity, manual renewal stops being viable. Fully automated ACME is the only sustainable path. This component is designed for the 47-day future from the outset.

---

## Features

- **ACMEv2 account management** — generate, persist, and reuse an RSA account key pair; register with any RFC 8555 CA.
- **HTTP-01 challenge** — domain control validation via `/.well-known/acme-challenge/`, with two working publish strategies (a third is stubbed).
- **Hand-built PKCS#10 CSR** — DER-encoded in pure 4D (no external tools), signed over the raw DER bytes.
- **JWS signing** — RS256, JWK and KID modes, base64url encoding, JWK thumbprint for `keyAuthorization`. The public JWK is extracted by parsing the key's DER directly, since 4D exposes no JWK export.
- **Time-based renewal** — renews at ⅔ of the certificate lifetime. ARI (RFC 9773) support is scaffolded but not yet active; see [Open Spikes](#open-spikes).
- **Secret-safe logging** — private keys, account keys, and tokens never appear in log output.
- **Post-renewal hook** — configurable web-server restart or custom formula callback.
- **Status surface** — per-cert object reporting `notAfter`, last attempt, last success, next check.
- **Host IDE support** — ships `Resources/en.lproj/syntaxEN.json`, so the host application gets autocomplete and signature help for the whole `cs.acme.*` API.

### Not yet implemented

These are named in the design and referenced in places, but are not live yet. They are tracked in
[`docs/review-findings.md`](docs/review-findings.md):

- **Jitter.** `ACMEScheduler._applyAriJitter()` returns its input unchanged, and the time-based path
  uses a flat threshold. A fleet sharing this component will currently renew in lockstep.
- **Crash-safe resume.** Order state *is* written to `<storePath>/order-<host>.json`, but nothing
  reads it back — `renew()` always starts a fresh order. Interrupted runs restart rather than resume.
- **Multiple identifiers.** `addIdentifier()` accepts several hostnames and the order will authorize
  all of them, but the CSR is built for the first one only, so finalize is rejected. **Configure
  exactly one hostname per client instance.** SAN support is future work.

## Requirements

- **4D version: unconfirmed — see below.** Uses `4D.HTTPRequest`, `4D.CryptoKey`, `4D.File`/`4D.Folder`, `Storage`, `LOG EVENT`.
- No external binaries or plugins required.
- Port 80 must be reachable for the domain during HTTP-01 validation (see [Challenge Strategy](#challenge-strategy)).

> **Minimum version needs confirming before release.** The kickoff brief sets 4D v20.0 LTS as a hard
> floor, and `Project/4D 20.2.lnk` points at a v20.2 install — but the component uses `Try` / `Catch` /
> `End try` blocks throughout, and those arrived in **4D 20 R5**. The
> [v20 LTS error-handling documentation](https://developer.4d.com/docs/20/Concepts/error-handling)
> documents only `ON ERR CALL`. Either the shortcut is stale and the successful run happened on a newer
> build, or those blocks are not behaving as the code assumes. Confirm the build that produced the
> successful issuance and set this section accordingly.

## Installation

Place `ACME_4D` in the host application's `Components` folder (or register it as a 4D dependency in `dependencies.json`). Classes are accessed via the `acme` component class store (set by `component_classStore_name` in `Project/Sources/settings.4DSettings`):

```4d
var $acme : cs.acme.ACMEClient
```

> Note: the usage examples in some class header comments inside the component write `cs.ACMEConfig` /
> `cs.ACMEClient` — that is the *internal* form used within the component itself. From a host
> application, always use the `cs.acme.` prefix as shown throughout this README and the class
> documentation.

## Quick Start

```4d
// 1. Configure
var $cfg : cs.acme.ACMEConfig
$cfg:=cs.acme.ACMEConfig.new()
$cfg.setEmail("admin@mysite.com")
$cfg.addIdentifier("mysite.com")  // exactly one — see "Not yet implemented" above
$cfg.setCertPath("/etc/ssl/acme/cert.pem")
$cfg.setKeyPath("/etc/ssl/acme/key.pem")
// Default is LE staging — switch to production deliberately:
$cfg.setStaging(False)

// 2. Create client and run setup (once, on startup)
var $acme : cs.acme.ACMEClient
$acme:=cs.acme.ACMEClient.new($cfg)
var $result : Object
$result:=$acme.setup()
If (Not($result.success))
    LOG EVENT(Into current log file; "[acme] Setup failed: "+$result.error; wError)
End if

// 3. Start background scheduler (checks daily, renews when due)
$acme.startScheduler()

// 4. Force an immediate renewal if needed
$result:=$acme.renew()
```

### Wiring the HTTP-01 Challenge Handler

Add to the host's `On Web Connection` database method. The handler takes the request URL as a
parameter — pass `$1`:

```4d
If (Match regex("^\/.well-known\/acme-challenge\/"; $1; 1; $pos; $len))
    ACME_Challenge_Handler($1)
    return
End if
```

Or call the class method directly if you hold a client reference:

```4d
var $resp : Object
$resp:=$acme.handleChallengeRequest($1)
If ($resp.found)
    WEB SEND TEXT($resp.keyAuth; "text/plain")
End if
```

## Challenge Strategy

The `challengeStrategy` config option selects how the HTTP-01 validation token is published on port 80:

| Strategy | Description | When to use |
|----------|-------------|-------------|
| `"webserver"` | Stores token in `Storage`; served by the 4D web server URL handler | 4D is the only web server and is reachable on port 80 |
| `"webroot"` | Writes token file under `webrootPath` | A separate server (nginx, IIS…) serves port 80 |
| `"listener"` | *(Future — not implemented)* | N/A for MVP |

## Architecture

```
ACMEClient          ← host entry point; orchestrates all sub-components
├── ACMEConfig      ← site-specific settings, fluent API
├── ACMELogger      ← structured, secret-safe logging
├── ACMETransport   ← HTTP layer: signed POST, POST-as-GET, nonce, retry
├── ACMEJwsSigner   ← JWS builder (RS256, JWK/KID modes, thumbprint)
├── ACMEAccount     ← account key gen, load/save, CA registration
├── ACMEOrder       ← order state machine: create → auth → finalize → download
│   ├── ACMEChallenge  ← HTTP-01 publisher (webserver/webroot)
│   └── ACMECsr        ← hand-built PKCS#10 DER CSR
├── ACMECertStore   ← cert/key save, expiry check, ARI window, reload trigger
└── ACMEScheduler   ← daily renewal check (ARI + jitter scaffolded, not yet active)
```

## Class Reference

| Class | Description |
|-------|-------------|
| [ACMEClient](Documentation/Classes/ACMEClient.md) | Main entry point and orchestrator |
| [ACMEConfig](Documentation/Classes/ACMEConfig.md) | Configuration — fluent setters, validation |
| [ACMELogger](Documentation/Classes/ACMELogger.md) | Structured, secret-safe logging |
| [ACMETransport](Documentation/Classes/ACMETransport.md) | HTTP transport, nonce management, error parsing |
| [ACMEJwsSigner](Documentation/Classes/ACMEJwsSigner.md) | JWS/JWK signing, base64url, JWK thumbprint |
| [ACMECsr](Documentation/Classes/ACMECsr.md) | PKCS#10 DER CSR builder in pure 4D |
| [ACMEAccount](Documentation/Classes/ACMEAccount.md) | Account key generation, persistence, registration |
| [ACMEOrder](Documentation/Classes/ACMEOrder.md) | Order state machine — the full RFC 8555 issuance flow |
| [ACMEChallenge](Documentation/Classes/ACMEChallenge.md) | HTTP-01 challenge publisher |
| [ACMECertStore](Documentation/Classes/ACMECertStore.md) | Certificate storage, expiry detection, reload |
| [ACMEScheduler](Documentation/Classes/ACMEScheduler.md) | Renewal scheduler — time-based today, ARI-ready |

## Method Reference

| Method | Description |
|--------|-------------|
| [ACME_HTTP_Error](Documentation/Methods/ACME_HTTP_Error.md) | `ON ERR CALL` handler for HTTP network errors |
| [ACME_Challenge_Handler](Documentation/Methods/ACME_Challenge_Handler.md) | URL handler for `/.well-known/acme-challenge/*` |
| [ACME_SchedulerWorker](Documentation/Methods/ACME_SchedulerWorker.md) | Worker process entry point |
| [Compiler_Variables](Documentation/Methods/Compiler_Variables.md) | Process-level variable declarations |

## Open Spikes

### Resolved

**1. CSR signing over raw DER — resolved.** `4D.CryptoKey.sign()` has a Blob overload
(`.sign(message : Blob; options : Object) : Text`), so `ACMECsr._signBlob()` now signs the raw DER
bytes of `CertificationRequestInfo` directly with `{hash: "SHA256"; encoding: "Base64"}`. No base64
round-trip, no external tooling. This was the project's headline blocker.

**2. JWK extraction from a PEM key — resolved.** 4D exposes no JWK/JWKS export, so
`ACMEJwsSigner._buildPublicJwk()` strips the PEM armour, base64-decodes to DER, and walks the
`SubjectPublicKeyInfo` ASN.1 structure to pull out the modulus and exponent as base64url. The
`_regenerateKeyViaJwks()` fallback in `ACMEClient` is now vestigial — it regenerates the key and
re-parses it by the same route.

### Still open

**3. Certificate `notAfter` parsing.** `ACMECertStore._extractNotAfterFromPem()` is still a stub
returning `!00-00-00!`, so every issued certificate is recorded as expiring 90 days from issue.

This matters more than it did when spike 4 was expected to cover for it. With ARI inactive, the
⅔-of-assumed-90-days threshold (day 60) is the *only* renewal trigger. That is safe while
Let's Encrypt issues 90-day certificates — but under the SC-081v3 schedule, a certificate shorter than
90 days would expire before the assumed threshold is reached. **Treat this as the next blocker.**

The fix is to parse the `notAfter` `UTCTime` / `GeneralizedTime` field from the certificate DER —
the ASN.1 reader in `ACMEJwsSigner` (`_derExpectTag`, `_derReadLength`, `_derReadInteger`) already
covers most of what is needed.

**4. ARI URL construction.** `ACMEScheduler._buildAriUrl()` still returns `""`, so `_checkAri()`
always short-circuits and the scheduler always uses the time-based fallback. The ARI URL needs the
issuer key hash and serial number from the issued certificate DER — the same parser work as spike 3.

**5. Minimum 4D version.** See [Requirements](#requirements). Unresolved and blocking an accurate
release note.

## Testing

### Local Testing with Pebble

[Pebble](https://github.com/letsencrypt/pebble) is Let's Encrypt's local test ACME server. It is strict, offline, and has no rate limits — ideal for driving the JWS/order/finalize flow.

```4d
$cfg.setDirectoryUrl("https://localhost:14000/dir")
$cfg.setChallengeStrategy("webroot")
$cfg.setWebrootPath("/tmp/pebble-webroot/")
```

### LE Staging

Once Pebble passes, test against LE staging (`setStaging(True)` — the default) with a real public hostname. Staging issues untrusted certificates but uses the real protocol and generous rate limits.

### Production

`setStaging(False)` only after staging validates successfully. Let's Encrypt production has per-domain rate limits — do not loop issuance in tests.

## Key References

- [RFC 8555 — ACME](https://datatracker.ietf.org/doc/html/rfc8555)
- [RFC 9773 — ACME Renewal Information (ARI)](https://datatracker.ietf.org/doc/html/rfc9773)
- [RFC 7515/7517/7518 — JWS / JWK / JWA](https://datatracker.ietf.org/doc/html/rfc7515)
- [RFC 2986 — PKCS#10](https://datatracker.ietf.org/doc/html/rfc2986)
- [Let's Encrypt — How It Works](https://letsencrypt.org/how-it-works/)
- [4D.CryptoKey documentation](https://developer.4d.com/docs/API/CryptoKeyClass)
- [acme-tiny — minimal Python reference](https://github.com/diafygi/acme-tiny) (useful for understanding the JWS/order/finalize shape)
- [Pebble — local test ACME server](https://github.com/letsencrypt/pebble)

## Project Documents

| Document | Contents |
|----------|----------|
| [`docs/tk-acme-component-kickoff.md`](docs/tk-acme-component-kickoff.md) | Original kickoff brief — project background, rationale, architecture decisions, spike definitions. Kept as a historical record; some of its §4 constraints are not yet met. |
| [`docs/review-findings.md`](docs/review-findings.md) | Code review of the current implementation — what was fixed, what is still open, and a suggested priority order. |

---

## Credits & Prior Art

**[Bruno Legay](https://github.com/blegay)** built [`acme_component`](https://github.com/blegay/acme_component)
— the first ACMEv2 client for 4D, and the proof that the whole protocol could live inside 4D with no
external tooling. `tk-acme` is an independent implementation rather than a fork, but it exists because
that work showed the way. Thank you.

What has changed since is the deadline. When `acme_component` was written, certificates lasted a year
and automation was a convenience. Under CA/Browser Forum ballot SC-081v3 certificates fall to 47 days
with 10-day validation reuse, and automation becomes the only option. `tk-acme` is built for that
world from the outset: ARI-driven renewal, crash-safe state, fleet jitter, and secret-safe logging.
Of those four, secret-safe logging and the crash-safe state *format* are in place today; ARI, resume,
and jitter are scaffolded and tracked in [`docs/review-findings.md`](docs/review-findings.md).

## Author

**Telekinetix Limited** — <https://telekinetix.com>

## License

Released under the [MIT License](LICENSE). Copyright © 2026 Telekinetix Limited.

*Let's Encrypt is a trademark of the Internet Security Research Group. This project is not
affiliated with or endorsed by ISRG.*
