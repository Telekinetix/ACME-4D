# ACMEConfig

Configuration container for the `tk-acme` ACME / Let's Encrypt component.

All site-specific settings live here; nothing is hard-coded in any other class. Provides a fluent setter API — every setter returns `This` so calls can be chained.

> **Default is staging.** `ACMEConfig` defaults to the Let's Encrypt **staging** directory so accidental runs during development never consume production rate-limit quota. Call `setStaging(False)` only when ready for production issuance.

## Constructor

```4d
var $cfg : cs.acme.ACMEConfig
$cfg:=cs.acme.ACMEConfig.new()
```

No parameters. All settings have safe defaults.

## Properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `directoryUrl` | Text | LE staging URL | Active ACME directory endpoint |
| `contactEmail` | Text | `""` | Contact e-mail registered with the CA |
| `identifiers` | Collection | `[]` | Domain names to certify (first = CN) |
| `certPath` | Text | `""` | Output path for the PEM certificate chain |
| `keyPath` | Text | `""` | Output path for the private key PEM |
| `storePath` | Text | `""` | Directory for account key and order state (derived from `certPath` if blank) |
| `challengeStrategy` | Text | `"webserver"` | `"webserver"` \| `"webroot"` \| `"listener"` |
| `webrootPath` | Text | `""` | Directory for webroot strategy |
| `postRenewAction` | Text | `"restart"` | `"restart"` \| `"none"` |
| `postRenewFormula` | `4D.Function` | `Null` | Formula called after renewal when `postRenewAction = "none"` |
| `staging` | Boolean | `True` | `True` = LE staging, `False` = LE production |
| `timeout` | Integer | `30` | HTTP request timeout in seconds |
| `maxPollAttempts` | Integer | `20` | Maximum authorization/order poll iterations |
| `pollIntervalSecs` | Integer | `5` | Seconds between poll attempts |

## Fluent Setters

All setters return `cs.acme.ACMEConfig` for chaining.

### setEmail

```4d
$cfg.setEmail("admin@example.com")
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$email` | Text | Contact e-mail registered with the CA (`mailto:` URI assembled internally) |

---

### addIdentifier / setIdentifiers

```4d
$cfg.addIdentifier("myhost.example.com")
// or replace the entire list:
$cfg.setIdentifiers(New collection("host1.example.com"; "host2.example.com"))
```

`addIdentifier` appends one hostname; `setIdentifiers` replaces the collection. The first identifier becomes the certificate CN.

> **Configure exactly one identifier.** Multi-name (SAN) certificates are future work, and nothing here
> currently stops you from setting several. If you do, `ACMEOrder._createOrder()` sends them all and the
> CA authorizes each one — but `_finalize()` builds the CSR from `identifiers[0]` alone, so finalize is
> rejected for a CSR/identifier mismatch *after* every HTTP-01 validation has already run. `isValid()`
> does not catch this. Tracked in [`docs/review-findings.md`](../../docs/review-findings.md).

---

### setCertPath / setKeyPath

```4d
$cfg.setCertPath("/etc/ssl/acme/cert.pem")
$cfg.setKeyPath("/etc/ssl/acme/key.pem")
```

Paths where the issued certificate chain and private key will be written. The private key path is never logged.

---

### setStorePath

```4d
$cfg.setStorePath("/var/acme/state/")
```

Directory for persisting the account key pair and order state between runs. If not set, derived automatically from the `certPath` parent directory as `acme-state/`.

---

### setChallengeStrategy

```4d
$cfg.setChallengeStrategy("webroot")
```

| Value | Description |
|-------|-------------|
| `"webserver"` | Token served via the 4D web server's URL handler (requires port 80 on this server). Default. |
| `"webroot"` | Token written as a file under `webrootPath`; requires a separate port-80 web server already serving that directory. |
| `"listener"` | *(Future — not implemented in MVP)* Temporary port-80 responder bound for the validation window. |

---

### setWebrootPath

```4d
$cfg.setWebrootPath("/var/www/html/")
```

Required when `challengeStrategy = "webroot"`. The component creates `.well-known/acme-challenge/` under this path automatically.

---

### setPostRenewAction

```4d
$cfg.setPostRenewAction("none")
```

| Value | Description |
|-------|-------------|
| `"restart"` | `WEB STOP SERVER` / `WEB START SERVER` after renewal (brief connection drop). Default. |
| `"none"` | No built-in action; call `setPostRenewFormula` to supply your own handler. |

---

### setPostRenewFormula

```4d
$cfg.setPostRenewAction("none")
$cfg.setPostRenewFormula(Formula(MyApp_OnCertRenewed($1)))
```

Formula called with the reload result object after a successful renewal. Only used when `postRenewAction = "none"`.

---

### setStaging

```4d
$cfg.setStaging(False)  // switch to production — do this deliberately
```

Passing `False` switches the `directoryUrl` to `https://acme-v02.api.letsencrypt.org/directory`. Passing `True` (the default) uses `https://acme-staging-v02.api.letsencrypt.org/directory`.

---

### setDirectoryUrl

```4d
$cfg.setDirectoryUrl("https://localhost:14000/dir")  // local Pebble instance
```

Override with any ACME-compliant directory URL. Use this for testing with [Pebble](https://github.com/letsencrypt/pebble).

---

### setTimeout / setPollIntervalSecs / setMaxPollAttempts

```4d
$cfg.setTimeout(60)
$cfg.setPollIntervalSecs(10)
$cfg.setMaxPollAttempts(30)
```

---

## Validation

### isValid

```4d
If ($cfg.isValid())
    // contactEmail, identifiers, certPath, keyPath all present
End if
```

| | Type | Description |
|---|---|---|
| **Return** | Boolean | `True` when all required fields are populated |

Checks `contactEmail`, `identifiers` (non-empty), `certPath` and `keyPath`. It does **not** validate
`challengeStrategy`, `webrootPath` (even when the strategy is `"webroot"`), `postRenewAction`, or the
single-identifier limit described above — those failures surface later, at publish or finalize time.

---

### validationError

```4d
ALERT($cfg.validationError())  // e.g. "certPath is required"
```

| | Type | Description |
|---|---|---|
| **Return** | Text | Human-readable description of the first problem found, or `""` if valid |

---

### effectiveStorePath

```4d
var $path : Text
$path:=$cfg.effectiveStorePath()
```

Returns `storePath` if set; otherwise derives a path alongside `certPath` as `<certParent>/acme-state/`.
