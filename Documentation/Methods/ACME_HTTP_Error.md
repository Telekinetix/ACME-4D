# ACME_HTTP_Error

Error-handling callback registered with `ON ERR CALL` during `4D.HTTPRequest` calls inside the `tk-acme` component.

When a 4D error occurs during an HTTP request (network timeout, DNS resolution failure, SSL handshake error, connection refused), this method captures the error number and description into process variables that the calling `ACMETransport` method inspects to build an appropriate result object.

## Process Variables Set

| Variable | Type | Description |
|----------|------|-------------|
| `vl_acmeHttpError` | Integer | The 4D error number (`Error`) |
| `vt_acmeHttpError` | Text | `"{method} Line: {line} {formula}"` built from `Error method`, `Error line`, `Error formula` |

(Declared in [`Compiler_Variables`](Compiler_Variables.md).)

## Usage

Never called directly — registered and deregistered as an error handler around each HTTP call:

```4d
vl_acmeHttpError:=0
vt_acmeHttpError:=""
ON ERR CALL("ACME_HTTP_Error")
$vo_request:=4D.HTTPRequest.new($url; $options)
$vo_request.wait()
ON ERR CALL("")

If (vl_acmeHttpError#0)
    // Network-level failure — build error result from vt_acmeHttpError
End if
```

## Used By

- `cs.acme.ACMETransport._executeWithRetry()` — wraps every ACME HTTP call.
- `cs.acme.ACMEScheduler._checkAri()` — wraps the ARI GET request.
