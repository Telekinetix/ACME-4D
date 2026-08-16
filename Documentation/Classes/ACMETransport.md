# ACMETransport

HTTP transport layer for the ACMEv2 protocol (RFC 8555).

Wraps `4D.HTTPRequest` to provide signed POST requests, POST-as-GET requests, automatic nonce management, ACME directory caching, and transient-error retry with exponential back-off. All ACME requests must be signed JWS; this class delegates signing to an [`ACMEJwsSigner`](ACMEJwsSigner.md) instance injected via `setSigner()`.

## Constructor

```4d
var $transport : cs.acme.ACMETransport
$transport:=cs.acme.ACMETransport.new($config; $logger)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$config` | `cs.acme.ACMEConfig` | Configuration (used for `directoryUrl`, `timeout`) |
| `$logger` | `cs.acme.ACMELogger` | Shared logger |

## Standard Result Object

All public methods return:

| Property | Type | Description |
|----------|------|-------------|
| `success` | Boolean | `True` if the HTTP status is 2xx |
| `status` | Integer | HTTP status code (`0` on network error) |
| `body` | Variant | Parsed JSON object, plain text, or `Null` |
| `headers` | Object | Response headers |
| `location` | Text | `Location` header value (for new account / new order responses) |
| `error` | Text | Human-readable error string |
| `errorType` | Text | ACME error `type` URN (e.g. `urn:ietf:params:acme:error:badNonce`) |
| `errorCode` | Integer | 4D error number on a network-level failure, else `0` |
| `url` | Text | Full request URL |

## Public Functions

### directory

Fetches and caches the ACME directory object from `config.directoryUrl`. Returns the cached copy on subsequent calls.

```4d
var $dir : Object
$dir:=$transport.directory()
// $dir.newNonce, $dir.newAccount, $dir.newOrder, $dir.renewalInfo, ...
```

| | Type | Description |
|---|---|---|
| **Return** | Object | ACME directory JSON, or `Null` on failure |

---

### directoryUrl

Convenience accessor for a single named URL from the directory.

```4d
var $url : Text
$url:=$transport.directoryUrl("newOrder")
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$key` | Text | Directory key name (e.g. `"newNonce"`, `"newAccount"`, `"newOrder"`, `"renewalInfo"`) |
| **Return** | Text | URL string, or `""` if the directory has not been fetched or the key is absent |

---

### freshNonce

Returns the next usable `Replay-Nonce`. Uses the cached nonce from the last response, or makes a `HEAD` request to `newNonce` when the cache is empty.

```4d
var $nonce : Text
$nonce:=$transport.freshNonce()
```

| | Type | Description |
|---|---|---|
| **Return** | Text | Base64url nonce string, or `""` on failure |

---

### post

Issues a signed POST request with a JSON payload. Used for all standard ACME operations: `newAccount`, `newOrder`, challenge notification, finalize.

```4d
var $result : Object
$result:=$transport.post($url; $payloadObject)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$vt_url` | Text | Target ACME endpoint URL |
| `$vo_payload` | Object | JSON payload (pass `New object` for an empty payload `{}`) |
| **Return** | Object | Standard result |

---

### postAsGet

Issues an RFC 8555 §6.3 POST-as-GET request (empty string payload in JWS). Used to fetch authorization and order objects after creation.

```4d
var $result : Object
$result:=$transport.postAsGet($authorizationUrl)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$vt_url` | Text | Resource URL to fetch |
| **Return** | Object | Standard result |

---

### setSigner

Injects the [`ACMEJwsSigner`](ACMEJwsSigner.md) instance. Called by `ACMEClient` after the account key is loaded.

```4d
$transport.setSigner($signer)
```

## Retry Policy

Transient failures (network error / timeout / HTTP 5xx) are retried up to 3 times with 2-second and 4-second back-off delays. Non-transient errors (4xx) are returned immediately — retrying a rejected payload wastes quota.

## Nonce Management

The transport captures the `Replay-Nonce` header from every response and caches it for the next request. This avoids an extra round-trip on each call. If the CA returns `badNonce` the caller should discard the nonce and retry (handled by the back-off path).

## Internal Methods

`_signedRequest`, `_rawGet`, `_executeWithRetry` — the HTTP pipeline. `_parseError` extracts detail from ACME problem documents (`application/problem+json`). `_captureNonce` updates the cached nonce from response headers. `_emptyResult` builds a zeroed result template.
