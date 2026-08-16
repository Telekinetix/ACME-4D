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

When enabled, entries are appended as newline-delimited JSON. File write errors are silently swallowed to avoid letting a logging failure interrupt a renewal.

## 4D Event Log Integration

Entries at `INFO` level and below are also emitted to the 4D application log via `LOG EVENT` with `wInformation`. `DEBUG` entries are only written to the in-memory buffer (and the optional file sink) — they do not appear in the 4D log.
