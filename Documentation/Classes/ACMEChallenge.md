# ACMEChallenge

HTTP-01 challenge publisher for the `tk-acme` component (RFC 8555 §8.3).

Handles publishing and cleanup of the `keyAuthorization` value that the CA fetches from:

```
http://<domain>/.well-known/acme-challenge/<token>
```

## Constructor

```4d
var $challenge : cs.acme.ACMEChallenge
$challenge:=cs.acme.ACMEChallenge.new($config; $logger)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$config` | `cs.acme.ACMEConfig` | Configuration (used for `challengeStrategy` and `webrootPath`) |
| `$logger` | `cs.acme.ACMELogger` | Shared logger |

## Public Functions

### publish

Publishes the `keyAuthorization` for the given token using the configured strategy.

```4d
var $result : Object
$result:=$challenge.publish($token; $keyAuth)
// $result.success = True if the token was published successfully
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$vt_token` | Text | Token string from the CA's challenge object. **Not logged.** |
| `$vt_keyAuth` | Text | `token + "." + jwkThumbprint`. **Not logged.** |
| **Return** | Object | `{ success: Boolean, error: Text }` |

---

### unpublish

Removes the published token after the challenge has been validated (or failed). Always called — even on failure — to avoid leaving stale tokens.

```4d
$challenge.unpublish($token)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$vt_token` | Text | The token to remove |

---

### serveWebServerChallenge

Looks up the `keyAuthorization` for a given token from `Storage`. Called by the host web server's URL handler (or `ACMEClient.handleChallengeRequest()`).

```4d
var $keyAuth : Text
$keyAuth:=$challenge.serveWebServerChallenge($requestUrl; $token)
If (Length($keyAuth)>0)
    WEB SEND TEXT($keyAuth; "text/plain")
End if
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$vt_url` | Text | Full request URL (informational) |
| `$vt_token` | Text | Token extracted from the URL path |
| **Return** | Text | `keyAuthorization` string, or `""` if no active challenge for this token |

## Challenge Strategies

### `"webserver"` (default)

Stores the `keyAuthorization` in `Storage.acme.challenges[<token>]`. The host web server's URL handler reads from Storage and returns the value as `text/plain` on port 80.

**Requirements:**
- The 4D web server must be reachable on port 80 for the domain being validated.
- The host must route `/.well-known/acme-challenge/*` requests to either:
  - `ACMEClient.handleChallengeRequest()` (method call), or
  - The `ACME_Challenge_Handler` project method (see [Methods documentation](../Methods/ACME_Challenge_Handler.md)).

**Storage layout:**
```
Storage.acme.challenges = shared object {
  "<token1>": "<keyAuth1>",
  "<token2>": "<keyAuth2>"
}
```

---

### `"webroot"`

Writes the `keyAuthorization` as a plain-text file at:
```
<webrootPath>/.well-known/acme-challenge/<token>
```

**Requirements:**
- `ACMEConfig.webrootPath` must point to the document root of a web server already serving port 80 for the domain.
- The `.well-known/acme-challenge/` directory is created automatically if absent.
- The web server must serve files without special authentication or redirection for this path.

**Cleanup:** The token file is deleted by `unpublish()`. If deletion fails, a warning is logged but the error is not propagated.

---

### `"listener"` *(Future — not implemented)*

A temporary minimal HTTP server bound to port 80 for the duration of the validation window. Not implemented in MVP. Use `"webserver"` or `"webroot"` for current deployments.

## Port 80 Requirement

The HTTP-01 challenge **must** be answered on port 80 regardless of which port the 4D application normally runs on. Choose the strategy that matches your deployment:

| Scenario | Recommended strategy |
|----------|---------------------|
| 4D server is the only web server and is reachable on port 80 | `"webserver"` |
| A separate web server (nginx, Apache, IIS) serves port 80 | `"webroot"` |
| Neither of the above (e.g. firewall blocks 80) | DNS-01 challenge *(future)* or reconfigure networking |
