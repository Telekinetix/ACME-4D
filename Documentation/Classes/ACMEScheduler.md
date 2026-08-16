# ACMEScheduler

ARI-driven automatic renewal scheduler for the `tk-acme` component.

Checks once daily whether the certificate needs renewal, using ACME Renewal Information (RFC 9773) where the CA advertises it, with a time-based fallback (2/3 of lifetime elapsed). Jitter is applied so that many systems sharing this component do not hit the CA simultaneously.

## Constructor

```4d
var $scheduler : cs.acme.ACMEScheduler
$scheduler:=cs.acme.ACMEScheduler.new($config; $logger; $client)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$config` | `cs.acme.ACMEConfig` | Configuration |
| `$logger` | `cs.acme.ACMELogger` | Shared logger |
| `$client` | `cs.acme.ACMEClient` | Back-reference used to call `renew()` when due |

> Normally instantiated and managed via `ACMEClient.startScheduler()` rather than directly.

## Public Functions

### start

Marks the scheduler as running, initialises `Storage.acme.scheduler`, and records the first next-check date.

```4d
$scheduler.start()
```

---

### stop

Marks the scheduler as not running.

```4d
$scheduler.stop()
```

---

### setCheckIntervalHours

```4d
$scheduler.setCheckIntervalHours(12)  // default 24
```

Returns `cs.acme.ACMEScheduler` for chaining.

---

### check

Evaluates whether renewal is due and triggers it if so. Designed to be called from a background worker process on a timer.

```4d
// From a worker — called periodically
$scheduler.check()
```

Flow:
1. Queries ARI (`_checkAri`) — updates the cert metadata renewal window if data is returned.
2. Instantiates an `ACMECertStore` and calls `needsRenewal()`.
3. If renewal is needed: calls `ACMEClient.renew()`, updates Storage status.
4. Schedules the next check date (`_computeNextCheck`) and records it in the cert metadata.

## Storage State (`Storage.acme.scheduler`)

The scheduler writes its state to a shared object in `Storage` so the host application can query it without touching files.

```4d
var $state : Object
$state:=Storage.acme.scheduler
// $state.running, $state.status, $state.nextCheck, $state.lastCheck,
// $state.lastRenewal, $state.lastError
```

| Key | Description |
|-----|-------------|
| `running` | `"true"` / `"false"` |
| `status` | `"idle"` \| `"renewing"` \| `"ok"` \| `"error"` |
| `nextCheck` | ISO 8601 date of next scheduled check |
| `lastCheck` | ISO 8601 datetime of the most recent check |
| `lastRenewal` | ISO 8601 datetime of the last successful renewal |
| `lastError` | Error message from the last failed renewal attempt |

## ARI Support (RFC 9773)

When the CA's directory advertises a `renewalInfo` URL, `_checkAri` fetches the `suggestedWindow` for the current certificate and stores it in the cert metadata. The next call to `ACMECertStore.needsRenewal()` uses this window in preference to the time-based trigger.

Jitter is applied within the ARI window: the effective renewal start is shifted forward by a random fraction of the window duration so that a fleet of deployments does not all renew at exactly the same moment.

> **Current limitation:** `_buildAriUrl()` returns `""` (triggering the time-based fallback) until the DER parser spike is resolved. The ARI URL requires the certificate's issuer key hash and serial number, which need ASN.1 DER parsing of the issued certificate. See [kickoff §7.1](../../docs/tk-acme-component-kickoff.md).

## Renewal Timing Design

Designed for the 47-day certificate lifetime coming under CA/Browser Forum ballot SC-081v3:

| Cert lifetime | 2/3 threshold | → Renew within |
|--------------|---------------|---------------|
| 90 days (current LE) | Day 60 | 30-day window |
| 47 days (from Mar 2029) | Day 31 | 16-day window |

ARI further narrows the window with CA-provided guidance, making manual tuning unnecessary.

## Recommended Worker Pattern

```4d
// Host onHostDatabaseEvent (On before host database startup):
var $cfg : cs.acme.ACMEConfig
// ... build config ...
var $acme : cs.acme.ACMEClient
$acme:=cs.acme.ACMEClient.new($cfg)
$acme.setup()
$acme.startScheduler()

// On Timer event (e.g. every 6 hours) or via CALL WORKER:
$acme.runSchedulerCheck()
```
