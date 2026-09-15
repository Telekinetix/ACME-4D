# ACMELogger

Structured, secret-safe logger for the `tk-acme` component.

All log entries are objects (`{ timestamp, level, component, message, context }`). The logger enforces one hard rule: **private keys, account keys, and challenge tokens are never passed to any log method.** Callers are responsible for filtering sensitive values from context objects before logging.

## Constructor

```4d
var $log : cs.acme.ACMELogger
$log:=cs.acme.ACMELogger.new($logLevel)  // $logLevel optional; default INFO
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$logLevel` | Integer | Optional. Maximum verbosity: `0`=ERROR `1`=WARN `2`=INFO `3`=DEBUG. Default `2` (INFO). |

## Properties

| Property | Type | Description |
|----------|------|-------------|
| `ERROR` | Integer | Level constant `0` |
| `WARN` | Integer | Level constant `1` |
| `INFO` | Integer | Level constant `2` |
| `DEBUG` | Integer | Level constant `3` |
| `logToFile` | Boolean | When `True`, append entries to `logFilePath` as newline-delimited JSON |
| `logFilePath` | Text | Absolute path for the optional file sink |

## Level Constants

| Constant | Value | Used for |
|----------|-------|---------|
| `ERROR` | `0` | Failures requiring attention (issuance failed, transport error) |
| `WARN` | `1` | Recoverable issues (stale order file, poll failure, missing optional data) |
| `INFO` | `2` | Normal lifecycle events (account registered, cert issued, renewal scheduled) |
| `DEBUG` | `3` | Detailed flow tracing — noisy, for development and Pebble testing only |

## Public Functions

### setLevel

```4d
$log.setLevel($log.DEBUG)
```

Returns `cs.acme.ACMELogger` for chaining.

---

### error / warn / info / debug

```4d
$log.error("Order finalize failed"; New object("status"; 403; "error"; $errText))
$log.warn("Stale order state found; ignoring"; Null)
$log.info("Certificate issued"; New object("certPath"; $certPath))
$log.debug("Auth poll attempt"; New object("attempt"; $i; "authUrl"; $url))
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$message` | Text | Human-readable log message. Must not contain key material or tokens. |
| `$context` | Object | Optional safe context fields. Pass `Null` when there is no context. |

> **Security:** Never pass a private key PEM, account key PEM, challenge token, or `keyAuthorization` value as a `$message` or into a `$context` object.

---

### entries

```4d
var $all : Collection
$all:=$log.entries()
```

Returns a copy of all in-memory log entries (capped at 500; oldest are dropped when full).

---

### lastEntries

```4d
var $recent : Collection
$recent:=$log.lastEntries(20)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$count` | Integer | Number of most-recent entries to return |
| **Return** | Collection | Slice of the in-memory entry ring buffer |

---

### clearEntries

```4d
$log.clearEntries()
```

Empties the in-memory entry buffer (does not affect the file sink).

## Log Entry Format

Each entry in the collection has this shape:

```json
{
  "timestamp": "2026-03-15T14:22:01",
  "level":     "INFO",
  "component": "acme",
  "message":   "Certificate issued successfully",
  "context":   { "orderUrl": "https://acme-v02.api.letsencrypt.org/acme/order/..." }
}
```

## File Sink

```4d
$log.logToFile:=True
$log.logFilePath:="/var/log/acme/acme.log"
```

The intent is that entries are appended as newline-delimited JSON. File write errors are silently
swallowed so that a logging failure cannot interrupt a renewal.

> **The file sink is unverified and probably does not work.** `_log()` calls
> `$vf.setText($vt_line; "utf-8"; File append)`, but `4D.File.setText()` takes
> `(text {; charSet {; breakMode}})` — there is no append mode, and `File append` is not a 4D constant.
> (Every other constant in the codebase carries its token, e.g. `fk platform path:K87:2`; this one does
> not, because 4D did not recognise it.) The failure is invisible: `logToFile` defaults to `False`, and
> if you switch it on, the surrounding `Catch` swallows the error by design and the sink simply never
> writes. Leave `logToFile` off until this is fixed — see
> [`docs/review-findings.md`](../../docs/review-findings.md).

## 4D Event Log Integration

Entries at `INFO` level and below (i.e. `ERROR`, `WARN`, `INFO`) are also emitted via
`LOG EVENT(Into 4D commands log; …)` with `wInformation`. `DEBUG` entries are only written to the
in-memory buffer (and the optional file sink) — they do not appear in the 4D log.

> Note the destination: entries go to the **4D commands log**, not the current request log. If nothing
> appears where you expect it, check that command logging is enabled for the host.
