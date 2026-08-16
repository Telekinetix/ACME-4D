# ACMECertStore

Certificate and private key storage, expiry detection, ARI renewal window tracking, and post-renewal reload for the `tk-acme` component.

## Constructor

```4d
var $store : cs.acme.ACMECertStore
$store:=cs.acme.ACMECertStore.new($config; $logger)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$config` | `cs.acme.ACMEConfig` | Configuration (used for `certPath`, `keyPath`, `postRenewAction`, `postRenewFormula`) |
| `$logger` | `cs.acme.ACMELogger` | Shared logger |

## Files Written

| File | Description |
|------|-------------|
| `<certPath>` | Full PEM certificate chain (cert + intermediates) |
| `<keyPath>` | Private key PEM. **Contents never logged.** |
| `<certParent>/acme-cert-meta.json` | Renewal metadata (see below) |

### Metadata Schema (`acme-cert-meta.json`)

```json
{
  "hostname":    "myhost.example.com",
  "notAfter":    "2026-05-14",
  "issuedAt":    "2026-03-15",
  "lastSuccess": "2026-03-15T14:22:01",
  "lastAttempt": "2026-03-15T14:21:58",
  "nextCheck":   "2026-03-16",
  "renewalWindow": {
    "start": "2026-05-01",
    "end":   "2026-05-10"
  }
}
```

`renewalWindow` is populated from ARI data when available; absent otherwise.

## Public Functions

### saveCertificate

Writes the certificate chain and private key to their configured paths. Creates parent directories if needed.

```4d
var $result : Object
$result:=$store.saveCertificate($certPem; $keyPem)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$vt_certPem` | Text | Full PEM certificate chain from the CA |
| `$vt_keyPem` | Text | Certificate private key PEM. **Never log.** |
| **Return** | Object | `{ success: Boolean, error: Text }` |

---

### needsRenewal

Returns `True` if the certificate should be renewed. Checks in order:
1. No cert file on disk → renew.
2. ARI renewal window in metadata with a start date ≤ today → renew.
3. No ARI data → time-based fallback: renew at ≥ 2/3 of lifetime elapsed.
4. No date metadata → renew (safe default).

```4d
If ($store.needsRenewal())
    $acme.renew()
End if
```

| | Type | Description |
|---|---|---|
| **Return** | Boolean | `True` when renewal is due |

---

### certExists

```4d
If ($store.certExists())
    // certificate file is present
End if
```

---

### triggerReload

Executes the post-renewal action configured in `ACMEConfig.postRenewAction`.

```4d
var $result : Object
$result:=$store.triggerReload()
```

| `postRenewAction` | Behaviour |
|-------------------|-----------|
| `"restart"` | `WEB STOP SERVER` → 1-second pause → `WEB START SERVER`. Brief connection drop; necessary to load the replacement certificate in 4D v20.0. |
| `"none"` | Calls `config.postRenewFormula` if set; otherwise no action. |

| | Type | Description |
|---|---|---|
| **Return** | Object | `{ success: Boolean, error: Text }` |

---

### updateAriRenewalWindow

Stores the ARI-suggested renewal window from a `renewalInfo` response into the metadata file.

```4d
$store.updateAriRenewalWindow(New object("start"; "2026-05-01"; "end"; "2026-05-10"))
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$vo_ariWindow` | Object | `{ start: Text, end: Text }` (ISO 8601 date strings) |

---

### status

Returns a status object for fleet monitoring.

```4d
var $s : Object
$s:=$store.status()
```

| Property | Type | Description |
|----------|------|-------------|
| `hostname` | Text | First identifier from config |
| `certPath` | Text | Configured certificate path |
| `certExists` | Boolean | Whether the cert file exists on disk |
| `needsRenewal` | Boolean | Whether renewal is currently due |
| `notAfter` | Text | ISO 8601 certificate expiry date |
| `issuedAt` | Text | ISO 8601 date the cert was last issued |
| `lastSuccess` | Text | ISO 8601 datetime of last successful renewal |
| `lastAttempt` | Text | ISO 8601 datetime of last renewal attempt |
| `nextCheck` | Text | ISO 8601 date of next scheduled check |

---

### recordAttempt / recordSuccess / recordNextCheck

Update the `lastAttempt`, `lastSuccess`, and `nextCheck` fields in the metadata file. Called by `ACMEClient.renew()` and the scheduler.

```4d
$store.recordAttempt()   // call before starting a renewal
$store.recordSuccess()   // call after a successful renewal
$store.recordNextCheck(Current date+1)
```

## Known Limitation — `notAfter` Parsing

`_extractNotAfterFromPem()` is a stub. 4D v20.0 does not include a native PEM/X.509 parser, so the `notAfter` date cannot be parsed directly from the certificate. The current fallback assumes a 90-day validity from the issue date.

The correct fix is one of:
- Use a 4D v20 R-release API for certificate info (if available).
- Parse the `notAfter` UTCTime / GeneralizedTime field from the certificate DER directly (shares the ASN.1 infrastructure already present in `ACMECsr`).

The ARI renewal window (when provided by the CA) overrides the time-based trigger and makes the precise `notAfter` value less critical.
