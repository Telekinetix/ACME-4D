# tk-acme — 4D ACME / Let's Encrypt Component

> **Certificates that renew themselves, inside 4D. No certbot, no cron, no shell.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

By **[Telekinetix Limited](https://telekinetix.com)** — carrying forward the path opened by
[Bruno Legay's `acme_component`](https://github.com/blegay/acme_component), rebuilt for the
47-day certificate era.

A self-contained 4D component that obtains and automatically renews TLS certificates from any ACMEv2 certificate authority (Let's Encrypt by default), so that the host application's web/REST server can serve HTTPS without any external tooling — no `certbot`, no `acme.sh`, no shell scripts, no cron jobs.

**Current status:** Initial implementation — core architecture complete; see [Open Spikes](#open-spikes) for blockers before first production run.

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
- **HTTP-01 challenge** — domain control validation via `/.well-known/acme-challenge/`, with three publish strategies.
- **Hand-built PKCS#10 CSR** — DER-encoded in pure 4D (no external tools).
- **JWS signing** — RS256, JWK and KID modes, base64url encoding, JWK thumbprint for `keyAuthorization`.
- **ARI-driven renewal** — queries ACME Renewal Information (RFC 9773) for the CA-suggested renewal window; falls back to ⅔-of-lifetime time-based trigger with jitter.
- **Crash-safe** — order and account state persisted to disk; interrupted runs resume cleanly.
- **Secret-safe logging** — private keys, account keys, and tokens never appear in log output.
- **Fleet-friendly** — jitter prevents synchronised CA hits across many deployments.
- **Post-renewal hook** — configurable web-server restart or custom formula callback.
- **Status surface** — per-cert object reporting `notAfter`, last attempt, last success, next check.

## Requirements

- **4D v20.0 LTS** minimum (tested target). Uses `4D.HTTPRequest`, `4D.CryptoKey`, `4D.File`/`4D.Folder`, `Storage`, `LOG EVENT`.
- No external binaries or plugins required.
- Port 80 must be reachable for the domain during HTTP-01 validation (see [Challenge Strategy](#challenge-strategy)).

## Installation

Place `ACME_4D` in the host application's `Components` folder (or register it as a 4D dependency in `dependencies.json`). Classes are accessed via the `acme` component class store:

```4d
var $acme : cs.acme.ACMEClient
```

## Quick Start

```4d
// 1. Configure
var $cfg : cs.acme.ACMEConfig
$cfg:=cs.acme.ACMEConfig.new()
$cfg.setEmail("admin@mysite.com")
$cfg.addIdentifier("mysite.com")
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

Add to the host's `On Web Connection` database method:

```4d
If (Match regex("^\/.well-known\/acme-challenge\/"; $1; 1; $pos; $len))
    ACME_Challenge_Handler
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
└── ACMEScheduler   ← ARI-driven daily renewal check with jitter
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
| [ACMEScheduler](Documentation/Classes/ACMEScheduler.md) | ARI-driven renewal scheduler with jitter |

## Method Reference

| Method | Description |
|--------|-------------|
| [ACME_HTTP_Error](Documentation/Methods/ACME_HTTP_Error.md) | `ON ERR CALL` handler for HTTP network errors |
| [ACME_Challenge_Handler](Documentation/Methods/ACME_Challenge_Handler.md) | URL handler for `/.well-known/acme-challenge/*` |
| [ACME_SchedulerWorker](Documentation/Methods/ACME_SchedulerWorker.md) | Worker process entry point |
| [Compiler_Variables](Documentation/Methods/Compiler_Variables.md) | Process-level variable declarations |

## Open Spikes

The following items must be resolved before the first production certificate issuance:

### 1. CSR Signing (Blocker — `ACMECsr._signBlob`)

`4D.CryptoKey.sign()` accepts a **Text** parameter. PKCS#10 requires signing the raw DER bytes of `CertificationRequestInfo`. The current implementation signs the base64 encoding of those bytes — this does not produce a standards-compliant CSR.

**Resolution path:**
- Confirm with the 4D platform team whether `sign()` will accept Blob input in a v20 patch.
- Or use `Generate digest` (SHA-256 of DER blob) followed by a raw RSA signature over the hash digest.

### 2. JWK Extraction from PEM Key

`ACMEJwsSigner._buildPublicJwk()` attempts `getPublicKey({format:"JWKS"})`. If that is unsupported in the target 4D build, `ACMEClient` falls back to regenerating the account key. This is safe before first registration but needs confirmation on the actual 4D v20.0 API surface.

### 3. Certificate `notAfter` Parsing

`ACMECertStore._extractNotAfterFromPem()` is a stub. Currently falls back to a 90-day assumption from the issue date. The ARI renewal window overrides this for CAs that provide it, but a correct parser is needed for full reliability.

### 4. ARI URL Construction

`ACMEScheduler._buildAriUrl()` returns `""` (time-based fallback) until the certificate's issuer key hash and serial number can be extracted from the issued certificate DER. This requires the same ASN.1 parser infrastructure already scaffolded in `ACMECsr`.

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

## Kickoff Brief

Full project background, rationale, architecture decisions, and spike definitions: [`docs/tk-acme-component-kickoff.md`](docs/tk-acme-component-kickoff.md).

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

## Author

**Telekinetix Limited** — <https://telekinetix.com>

## License

Released under the [MIT License](LICENSE). Copyright © 2026 Telekinetix Limited.

*Let's Encrypt is a trademark of the Internet Security Research Group. This project is not
affiliated with or endorsed by ISRG.*
