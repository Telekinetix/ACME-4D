# ACME_Challenge_Handler

Project method URL handler for HTTP-01 ACME challenges.

Serves the `keyAuthorization` value for `/.well-known/acme-challenge/<token>` requests when the `"webserver"` challenge strategy is active. Reads the active challenge token from `Storage.acme.challenges` and returns the response as `text/plain`.

Use this method as an alternative to calling `ACMEClient.handleChallengeRequest()` — it reads from `Storage` directly and does not require a reference to the `ACMEClient` instance.

## Usage

Call from the host application's `On Web Connection` database method whenever the incoming URL matches the ACME challenge path:

```4d
// In On Web Connection:
If (Match regex("^\/.well-known\/acme-challenge\/"; $1; 1; $pos; $len))
    ACME_Challenge_Handler
    return
End if
```

The method reads `WEB GET HTTP HEADER("url")` to get the request URL, or falls back to `$1` (the URL parameter passed to `On Web Connection`). It then:

1. Extracts the token from the URL path after `/.well-known/acme-challenge/`.
2. Looks up `Storage.acme.challenges[<token>]`.
3. If found: sends the `keyAuthorization` text as `text/plain` with `WEB SEND TEXT`.
4. If not found: redirects to `/` (the CA will receive a 404-equivalent response).

## Storage Dependency

The challenge must have been published by `ACMEChallenge._publishViaWebServer()` before the CA makes its validation request. The `Storage.acme.challenges` shared object is populated by the challenge publisher and cleaned up by `unpublish()` after validation completes.

## Security Notes

- The `keyAuthorization` value stored in and returned from Storage is not a secret (it is intentionally served publicly), but it is not logged by this method.
- The method does not authenticate callers — it responds to any request matching the path pattern. This is correct ACME behaviour: the challenge response must be publicly accessible.

## Used By

- Host application `On Web Connection` — when `challengeStrategy = "webserver"`.
- See also: `ACMEClient.handleChallengeRequest()` for the class-method equivalent.
