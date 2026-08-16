# Project Kickoff — 4D ACME / Let's Encrypt Component (`tk-acme`)

**Audience:** development agent
**Author:** Telekinetix
**Status:** kickoff brief — read in full before writing code

---

## 1. Purpose

Build a **self-contained 4D component** that obtains and automatically renews TLS
certificates from an ACME certificate authority (Let's Encrypt by default), so that
the host application's web/REST server can serve HTTPS without any external tooling.

The component must be **redistributable across dozens of existing 4D systems** with no
host dependencies — no shell scripts, no `certbot`/`acme.sh`, no cron jobs. Everything
runs inside 4D.

> A separate **example component will be provided** to define our structural
> conventions (class layout, naming, error pattern, packaging, build). Follow that
> model for *structure*. This brief defines *what to build and how ACME works* — not
> the house style.

---

## 2. Why now (rationale, for context)

Public TLS certificate maximum lifetimes are being cut on a fixed schedule
(CA/Browser Forum ballot SC-081v3, passed April 2025):

| Date | Max cert lifetime | Domain-validation reuse |
|---|---|---|
| Until 15 Mar 2026 | 398 days | 398 days |
| From 15 Mar 2026 | **200 days** | 200 days |
| From 15 Mar 2027 | **100 days** | 100 days |
| From 15 Mar 2029 | **47 days** | **10 days** |

At 47-day validity with 10-day validation reuse, domain control is re-proved ~35×/year.
Manual renewal stops being viable; **fully automated ACME is the only path forward**.
Let's Encrypt intends to offer ~45-day certs from ~Feb 2028, ahead of the mandate.

Design the renewal logic for the **47-day future**, not today's 200-day certs.

---

## 3. Scope

### MVP (first deliverable)
- ACMEv2 account creation/registration against a configurable directory URL.
- Single-hostname certificate issuance via the **HTTP-01** challenge.
- Certificate + private key persisted to a configurable location the host web server reads.
- Automatic renewal driven by **ACME Renewal Information (ARI)** where the CA advertises it,
  with a fallback time-based trigger (renew at ~⅔ of lifetime elapsed) plus jitter.
- Trigger host web-server reload/restart after a successful renewal.
- Run against **Let's Encrypt staging** end-to-end before any production issuance.

### Later (design for, don't necessarily build yet)
- Multi-identifier / SAN certificates.
- DNS-01 challenge support (only useful where the DNS provider has an API — **not** No-IP free).
- External Account Binding (EAB) for non-LE CAs (e.g. ZeroSSL).
- ECDSA certs (P-256) in addition to RSA.
- Admin/status UI surface for fleet monitoring.

### Out of scope
- TLS-ALPN-01 (requires answering the `acme-tls/1` handshake on 443 — not worth it in 4D).
- Acting as our own CA.
- Certificate revocation UI (implement the call, but no UI for MVP).

---

## 4. Hard constraints

1. **Minimum target: 4D v20.0 (LTS).** The fleet runs different versions; v20.0 is the
   floor. Do **not** use APIs introduced in later v20 R-releases without a documented
   fallback. Verify availability of every platform API against the v20.0 docs/release
   notes before relying on it (see §7).
2. **Zero host dependencies.** No external binaries. If something can't be done natively
   in 4D, raise it as a blocker rather than silently introducing a dependency.
3. **No secrets in logs.** Account key, cert private keys, and tokens never appear in
   plaintext logs.
4. **Idempotent and crash-safe.** A renewal interrupted mid-flight must recover cleanly
   on next run (persist order/authorization state).
5. **Staging-by-default in dev.** Production LE endpoint only via explicit config.

---

## 5. How ACMEv2 works (the flow to implement)

ACMEv2 is defined in **RFC 8555**. Every request to the CA is an HTTP POST carrying a
**signed JWS** (`protected`, `payload`, `signature`), using a replay nonce from the CA.

1. **Bootstrap** — GET the CA *directory* to discover endpoint URLs
   (`newNonce`, `newAccount`, `newOrder`, `renewalInfo`, etc.).
2. **Account** — generate an **account key pair** (persist it); POST `newAccount`
   (JWS signed with the JWK, ToS agreed). The CA returns an account URL = your **kid**;
   all later requests sign with `kid`, not the embedded JWK.
3. **Order** — POST `newOrder` with the identifier(s) (e.g. `aci4d.hopto.org`).
   Receive one **authorization** per identifier.
4. **Challenge (HTTP-01)** — for each authorization, fetch the `http-01` challenge token.
   Compute `keyAuthorization = token + "." + base64url(SHA-256(JWK_thumbprint(accountKey)))`.
   Publish it at `http://<host>/.well-known/acme-challenge/<token>` as `text/plain`,
   **on port 80**. POST the challenge URL to tell the CA to validate. Poll until `valid`.
5. **Finalize** — generate a **PKCS#10 CSR** (DER, base64url) for the identifier(s) and
   POST it to the order's `finalize` URL.
6. **Download** — poll the order to `valid`, then GET the `certificate` URL to retrieve
   the full PEM chain. Persist cert + key. Reload the web server.
7. **Renewal** — repeat 3–6. There is no separate "renew" verb. Schedule via **ARI**
   (RFC 9773): GET the `renewalInfo` resource for the cert to obtain the suggested
   renewal window, and renew within it (with jitter). Fall back to time-based if absent.

---

## 6. Logical architecture (modules)

Keep these concerns separate (map onto our component structure per the example):

- **Config** — directory URL, contact email, identifiers, cert/key output paths,
  challenge-publish strategy, reload action, staging/prod flag.
- **Key & account store** — account key (PEM), account `kid`, per-cert private keys,
  order/authorization state, last-issued metadata. Crash-safe persistence.
- **JWS signer** — builds `protected`/`payload`/`signature`, base64url everywhere,
  nonce threading, JWK and `kid` modes, RS256 (and later ES256).
- **ACME transport** — HTTP client wrapper: POST-as-GET, nonce capture from
  `Replay-Nonce`, error parsing (`urn:ietf:params:acme:error:*`), retry/backoff.
- **Order state machine** — drives steps 3–6 with polling and timeouts.
- **Challenge publisher** — *pluggable* (see §7.2). Default + alternatives.
- **CSR builder** — produces the PKCS#10 DER (see §7.1, the key spike).
- **Certificate store + installer** — writes PEM, triggers reload (see §7.3).
- **Scheduler** — ARI-driven renewal check, runs on a timer; jittered.
- **Logging/observability** — structured, secret-safe, fleet-friendly.

---

## 7. Early spikes — resolve BEFORE committing to an architecture

These are the forks that change the design. Spike each against v20.0 first.

### 7.1 CSR generation (the critical one)
`4D.CryptoKey` (v18+) gives key generation, `.sign()`/`.verify()`, `.getPrivateKey()`/
`.getPublicKey()` in PEM, and base64URL output — but its public API does **not** appear
to expose PKCS#10 CSR generation. ACME *finalize* requires a CSR. Resolve the path:

- **(a)** Confirm whether any v20.0 command emits a PKCS#10 CSR natively. If yes, use it.
- **(b)** If not: **build the CSR DER by hand in 4D.** For a single hostname this is a
  bounded ASN.1/DER task — encode `CertificationRequestInfo` (version, subject DN,
  `SubjectPublicKeyInfo`, and the `subjectAltName` extension via the extensionRequest
  attribute), then sign the DER with `CryptoKey.sign()` and wrap. This keeps the
  component dependency-free and is the **preferred fallback**.
- **(c)** Shelling out to `openssl` is **rejected** for shipping (breaks self-contained),
  acceptable only as a throwaway spike to validate the rest of the flow.

Decide (a) vs (b) early — it determines whether a small DER encoder is in scope.

### 7.2 Challenge serving on port 80
HTTP-01 is answered on **port 80**, but host web servers in the fleet run on various
ports (e.g. `:8181`). The component can't assume it owns 80. Make the publisher
**pluggable**, with these strategies for the integrator to choose per site:

- **Via host web server** — register a handler so the 4D web server returns the token
  for `/.well-known/acme-challenge/*`. Only works if that server is reachable on 80.
- **Webroot** — write the token file into a folder a port-80 server already serves.
- **Temporary listener** — bind a minimal port-80 responder for the validation window.

Document the trade-offs; ship at least one working default.

### 7.3 Web-server reload after renewal
Confirm whether v20.0 can load a replacement certificate **without** restarting the web
server, or whether `WEB STOP SERVER` / `WEB START SERVER` is required. Provide a
**configurable post-renew action** (default: restart web server) and note the brief
connection drop if a restart is unavoidable.

### 7.4 Platform API availability (verify against v20.0)
- **HTTP client:** prefer the classic `HTTP Request` command as the safe v20.0 baseline;
  only use the `4D.HTTPRequest` class if confirmed present in the minimum target version.
- **base64url:** `CryptoKey.sign()` supports base64URL directly; for arbitrary bytes
  (payloads, protected header, CSR) confirm the base64url option on the general
  `Base64 encode` command, else post-process (`+`→`-`, `/`→`_`, strip `=`).
- **Hashing:** confirm SHA-256 digest availability for the JWK thumbprint.

---

## 8. Testing strategy

1. **Local first — Pebble.** Run Let's Encrypt's *Pebble* test ACME server locally and
   point the component at it. Fast, offline, no rate limits, deliberately strict — ideal
   for exercising the JWS/order/finalize flow.
2. **Then LE staging.** `https://acme-staging-v02.api.letsencrypt.org/directory` — real
   protocol, untrusted certs, generous limits. Validate the full HTTP-01 round trip
   against a real public hostname here.
3. **Production last.** `https://acme-v02.api.letsencrypt.org/directory`. Mind rate
   limits. Note: provider domains like `hopto.org` are on the Public Suffix List, so each
   subdomain counts as its own registered domain for rate-limiting — helpful across the
   fleet, but still don't loop issuance in tests.
4. Test renewal explicitly, including the ARI path and the post-renew reload hook.

---

## 9. Operational requirements

- **Config per site**, externalised (not hard-coded): identifiers, contact, paths,
  challenge strategy, reload action, endpoint.
- **Structured, secret-safe logging** with clear success/failure and next-renewal time.
- **A status surface** (method or table) reporting, per cert: not-after date, last
  attempt, last success, next scheduled check — so the fleet can be monitored.
- **Jitter** on renewal timing to avoid synchronised CA hits across many systems sharing
  this component.
- **Safe re-run:** detect an existing valid cert and skip; resume an interrupted order.

---

## 10. Key references

### Specifications
- **RFC 8555** — ACME (the protocol): https://datatracker.ietf.org/doc/html/rfc8555
- **RFC 9773** — ACME Renewal Information (ARI): https://datatracker.ietf.org/doc/html/rfc9773
- **RFC 7515 / 7517 / 7518** — JWS / JWK / JWA (the signing/JSON-key formats)
- **RFC 2986** — PKCS#10 Certification Request Syntax: https://datatracker.ietf.org/doc/html/rfc2986

### Let's Encrypt
- How it works (concise flow): https://letsencrypt.org/how-it-works/
- Client options (orientation): https://letsencrypt.org/docs/client-options/
- Staging environment & rate limits: https://letsencrypt.org/docs/ (staging-environment, rate-limits)

### Reference implementations to study (for the JWS/flow shape)
- **acme-tiny** (Daniel Roesler) — ~200-line Python client; the clearest minimal model of
  the exact JWS/order/finalize steps: https://github.com/diafygi/acme-tiny
- **letsencrypt-fromscratch** (Alex Peattie) — step-by-step build of an ACMEv2 client,
  great for understanding `protected`/`payload`/`signature` and nonces:
  https://github.com/alexpeattie/letsencrypt-fromscratch
- **acme.sh** — study its **ARI / RFC 9773 renewal** behaviour to mirror scheduling:
  https://github.com/acmesh-official/acme.sh
- **lego** (Go) — mature reference for order/challenge handling: https://github.com/go-acme/lego
- **Pebble** — local test ACME server: https://github.com/letsencrypt/pebble

### 4D platform
- **4D.CryptoKey** (keys, sign/verify, PEM, base64URL, ES256 JWT example):
  https://developer.4d.com/docs/API/CryptoKeyClass
- **4D Summit 2020 — "Let's Encrypt certificates with 4D"** — 4D Inc presented an ACME
  component fully automating issue/install/renew. Track down the distributed component
  and the 4D GitHub org before reimplementing anything already solved there:
  https://events.4d.com/summit2020/session/certificats-lets-encrypt-avec-4d/

---

## 11. Open questions / risks

- **CSR generation in v20.0** (§7.1) — confirmed blocker-class unknown; resolve first.
- **TLS hot-reload vs web-server restart** in v20.0 (§7.3).
- **Port-80 reachability** varies per deployment; the pluggable publisher must cover the
  `:8181`-style cases where the 4D server isn't on 80.
- **Existing 4D component** — if the 4D Inc Summit component is current and licensable,
  the build may reduce to adapting it for v20 + ARI rather than greenfield. Evaluate
  before estimating.

---

## 12. First actions for the agent

1. Read the example component (provided separately) for structural conventions.
2. Run spike **7.1 (CSR)** and **7.4 (platform APIs)** against v20.0; report findings.
3. Stand up **Pebble** locally and prove account → order → HTTP-01 → finalize → download
   end-to-end with a throwaway CSR path.
4. Only then design the module layout against our component model and proceed to MVP.
