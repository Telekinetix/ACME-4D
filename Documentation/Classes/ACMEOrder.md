# ACMEOrder

ACMEv2 order state machine (RFC 8555 §7.3–7.5).

Drives the full certificate issuance flow for one order, from creating the order through authorizing the domain via HTTP-01, finalizing with a CSR, and downloading the signed certificate chain.

## Constructor

```4d
var $order : cs.acme.ACMEOrder
$order:=cs.acme.ACMEOrder.new($config; $logger; $transport; $challenge; $signer)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$config` | `cs.acme.ACMEConfig` | Configuration |
| `$logger` | `cs.acme.ACMELogger` | Shared logger |
| `$transport` | `cs.acme.ACMETransport` | Wired transport |
| `$challenge` | `cs.acme.ACMEChallenge` | Challenge publisher |
| `$signer` | `cs.acme.ACMEJwsSigner` | Wired signer (in KID mode) |

## Public Functions

### issueCertificate

Runs the complete issuance flow. This is the only method the host needs to call directly (via `ACMEClient.renew()`).

```4d
var $result : Object
$result:=$order.issueCertificate($certPrivateKeyPem)
If ($result.success)
    // $result.certPem contains the full PEM certificate chain
End if
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$vt_privateKeyPem` | Text | The **certificate** private key PEM. Must be different from the account key. **Never log.** |
| **Return** | Object | `{ success, certPem, error, orderUrl }` |

### loadOrderState

Attempts to load a previously-persisted order state from disk. Returns `True` if a resumable order was found for the first configured identifier. Called by `ACMEClient` to detect and resume interrupted runs.

```4d
var $resumed : Boolean
$resumed:=$order.loadOrderState()
```

## Order Flow

```
POST newOrder → { orderUrl, authUrls[], finalizeUrl }
    ↓ for each authUrl:
POST-as-GET authUrl → find http-01 challenge
publish keyAuthorization
POST challengeUrl {}  ← notify CA to validate
poll authUrl          ← wait for "valid"
unpublish token
    ↓
POST finalizeUrl { csr: <base64url DER> }
poll orderUrl         ← wait for "valid"
POST-as-GET certUrl   ← download PEM chain
```

## State Persistence

After each significant step, the order state is written to:

```
<storePath>/order-<sanitised-hostname>.json
```

Schema:
```json
{
  "orderUrl":    "https://acme-v02.api.letsencrypt.org/acme/order/...",
  "finalizeUrl": "https://acme-v02.api.letsencrypt.org/acme/order/.../finalize",
  "certUrl":     "https://acme-v02.api.letsencrypt.org/acme/cert/...",
  "authUrls":    ["https://acme-v02.api.letsencrypt.org/acme/authz/..."],
  "status":      "valid",
  "savedAt":     "2026-03-15T14:22:01"
}
```

If a renewal is interrupted mid-flight, `ACMEClient.renew()` detects the stale state file on the next run and can resume from the finalize step rather than starting a new order.

## Polling

Authorization and order polling are controlled by `ACMEConfig.maxPollAttempts` and `ACMEConfig.pollIntervalSecs`. Default: 20 attempts × 5-second intervals = 100-second maximum wait per authorization. Increase `maxPollAttempts` if the HTTP-01 challenge takes longer to propagate (e.g. behind a CDN or with slow DNS).

## HTTP-01 Challenge Lifecycle

For each authorization:
1. `_processAuthorization` fetches the authorization object and locates the `http-01` challenge.
2. Computes `keyAuthorization = token + "." + signer.jwkThumbprint()`.
3. Calls `ACMEChallenge.publish()` to make the token reachable.
4. POSTs the challenge URL to notify the CA.
5. Polls until `valid` or `invalid`.
6. Always calls `ACMEChallenge.unpublish()` — even on failure — to clean up the token.

## Internal Methods

`_createOrder`, `_processAuthorization`, `_findHttp01Challenge`, `_pollAuthorization`, `_finalize`, `_pollOrder`, `_downloadCertificate`, `_saveOrderState`.
