# ACMEClient

Main entry point and orchestrator for the `tk-acme` ACME / Let's Encrypt component.

Ties together all sub-components into a single API surface. The host application creates an [`ACMEConfig`](ACMEConfig.md), passes it to `ACMEClient.new()`, then calls `setup()` once on startup and `startScheduler()` to enable background automatic renewal.

## Constructor

```4d
var $acme : cs.acme.ACMEClient
$acme:=cs.acme.ACMEClient.new($config)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$config` | `cs.acme.ACMEConfig` | Fully populated configuration object |

## Typical Usage

```4d
// --- Host application startup ---
var $cfg : cs.acme.ACMEConfig
$cfg:=cs.acme.ACMEConfig.new()
$cfg.setEmail("admin@example.com")
$cfg.addIdentifier("myhost.example.com")
$cfg.setCertPath("/etc/ssl/acme/cert.pem")
$cfg.setKeyPath("/etc/ssl/acme/key.pem")
$cfg.setStaging(False)  // only when ready for production

var $acme : cs.acme.ACMEClient
$acme:=cs.acme.ACMEClient.new($cfg)

var $result : Object
$result:=$acme.setup()
If ($result.success)
    $acme.startScheduler()
End if

// Force an immediate issuance or renewal
$result:=$acme.renew()
```

## Properties

| Property | Type | Description |
|----------|------|-------------|
| `_config` | `cs.acme.ACMEConfig` | Configuration reference |
| `_logger` | `cs.acme.ACMELogger` | Shared logger (access via `logger()`) |
| `_transport` | `cs.acme.ACMETransport` | HTTP transport |
| `_signer` | `cs.acme.ACMEJwsSigner` | JWS signer (wired after `setup()`) |
| `_account` | `cs.acme.ACMEAccount` | Account key and registration state |
| `_challenge` | `cs.acme.ACMEChallenge` | HTTP-01 challenge publisher |
| `_certStore` | `cs.acme.ACMECertStore` | Certificate and key persistence |
| `_scheduler` | `cs.acme.ACMEScheduler` | Renewal scheduler (Null until `startScheduler()`) |
| `_version` | Text | Component version string |

## Public Functions

### version

```4d
$v:=$acme.version()  // "0.1.0"
```

| | Type | Description |
|---|---|---|
| **Return** | Text | Component version |

---

### setLogLevel

```4d
$acme.setLogLevel(3)  // 0=ERROR 1=WARN 2=INFO 3=DEBUG
```

Returns `cs.acme.ACMEClient` for chaining.

---

### logger

```4d
var $log : cs.acme.ACMELogger
$log:=$acme.logger()
```

Returns the [`ACMELogger`](ACMELogger.md) instance for querying recent log entries.

---

### setup

Initialises the component for use. Must be called before `renew()` or `startScheduler()`.

Steps performed:
1. Validates the config object.
2. Fetches the ACME directory from the configured CA (verifies reachability).
3. Loads or generates the account key pair.
4. Creates the [`ACMEJwsSigner`](ACMEJwsSigner.md).
5. Registers the account with the CA, or confirms an existing registration.

```4d
var $result : Object
$result:=$acme.setup()
If (Not($result.success))
    ALERT("ACME setup failed: "+$result.error)
End if
```

| | Type | Description |
|---|---|---|
| **Return** | Object | Standard result: `{ success, error, data }` |

---

### renew

Obtains a new certificate or renews the existing one. Runs the full ACMEv2 order → HTTP-01 → finalize → download → install cycle. Always generates a fresh certificate key pair (distinct from the account key).

```4d
var $result : Object
$result:=$acme.renew()
If ($result.success)
    // Certificate written to $cfg.certPath; web server reloaded
End if
```

| | Type | Description |
|---|---|---|
| **Return** | Object | `{ success, error, certPath, skipped }` |

`skipped` is always `False` from `renew()` — use `renewIfNeeded()` for conditional execution.

---

### renewIfNeeded

Calls `renew()` only if the cert store indicates renewal is due. Skips silently when the current certificate is still healthy.

```4d
$result:=$acme.renewIfNeeded()
// $result.skipped = True when no renewal was necessary
```

---

### startScheduler

Starts the background ARI-driven renewal scheduler. Call from the host's `onHostDatabaseEvent` / startup hook.

```4d
$acme.startScheduler()
```

Returns `cs.acme.ACMEClient` for chaining.

---

### stopScheduler

Stops the scheduler and marks it as not running in `Storage`.

```4d
$acme.stopScheduler()
```

---

### runSchedulerCheck

Triggers an immediate scheduler check cycle. Intended to be called from a worker process on a timer.

```4d
// From a worker process:
$acme.runSchedulerCheck()
```

---

### status

Returns a composite status object for fleet monitoring.

```4d
var $s : Object
$s:=$acme.status()
// $s.hostname, $s.notAfter, $s.certExists, $s.needsRenewal,
// $s.lastSuccess, $s.lastAttempt, $s.nextCheck,
// $s.staging, $s.isSetup, $s.scheduler
```

| | Type | Description |
|---|---|---|
| **Return** | Object | Combined cert-store and scheduler state; see [`ACMECertStore.status()`](ACMECertStore.md) |

---

### handleChallengeRequest

Entry point for the host web server's URL handler for `/.well-known/acme-challenge/<token>` requests. Used when `challengeStrategy = "webserver"`.

```4d
// In the host's On Web Connection or URL handler:
If (Match regex("^\/.well-known\/acme-challenge\/"; $1URL; 1; $pos; $len))
    var $resp : Object
    $resp:=$acme.handleChallengeRequest($1URL)
    If ($resp.found)
        WEB SEND TEXT($resp.keyAuth; "text/plain")
    End if
End if
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$vt_requestUrl` | Text | The full URL path from the web request |
| **Return** | Object | `{ found: Boolean, keyAuth: Text }` |

> Alternatively, use the standalone [`ACME_Challenge_Handler`](../Methods/ACME_Challenge_Handler.md) project method.

## Standard Result Object

All public methods return:

| Property | Type | Description |
|----------|------|-------------|
| `success` | Boolean | True on success |
| `error` | Text | Human-readable error description on failure |
| `data` | Variant | Method-specific payload (Null when unused) |

## Internal Methods

`_regenerateKeyViaJwks` — fallback key regeneration when JWK extraction fails on a loaded PEM key. Safe only before account registration.
