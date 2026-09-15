# ACMEScheduler

ARI-driven automatic renewal scheduler for the `tk-acme` component.

Checks once daily whether the certificate needs renewal, using ACME Renewal Information (RFC 9773) where the CA advertises it, with a time-based fallback (2/3 of lifetime elapsed).

> **Two design goals are not live yet.** ARI always short-circuits (`_buildAriUrl()` returns `""`), so
> today every renewal decision comes from the time-based fallback. And **no jitter is applied anywhere** —
> `_applyAriJitter()` returns its input unchanged, and the time-based threshold is flat. A fleet sharing
> this component will renew in lockstep. Both are tracked in
> [`docs/review-findings.md`](../../docs/review-findings.md).

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

> **Known bug — `_computeNextCheck()` returns a nonsense date.** `$vd_next` is never seeded with
> `Current date` before the `Add to date()` call, so it starts from the null date `!00-00-00!`. With the
> default 24-hour interval the `Else` branch is always taken, so `nextCheck` — in both
> `Storage.acme.scheduler` and `acme-cert-meta.json` — is meaningless. Renewals are unaffected
> (`check()` is driven by the host's timer and `nextCheck` is never read back as a gate), but the
> monitoring surface is not usable until this is fixed.

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

The design intent is that jitter is then applied within the ARI window — the effective renewal start
shifted forward by a random fraction of the window duration, so a fleet of deployments does not all
renew at the same moment.

> **Neither half of this is active.**
>
> `_buildAriUrl()` returns `""` unconditionally, so `_checkAri()` always returns `False` and no ARI
> window is ever stored. The ARI URL needs the certificate's issuer key hash and serial number, which
> require ASN.1 DER parsing of the issued certificate — the same gap as
> [`ACMECertStore`](ACMECertStore.md)'s `notAfter` parsing. The ASN.1 reader written for
> [`ACMEJwsSigner`](ACMEJwsSigner.md) covers most of the machinery needed.
>
> `_applyAriJitter()` copies `start` and `end` and returns them unchanged. Its own comment says a real
> implementation needs second-precision date arithmetic. Since it is only reachable from `_checkAri()`,
> it is currently dead code either way.

## Renewal Timing Design

Designed for the 47-day certificate lifetime coming under CA/Browser Forum ballot SC-081v3:

| Cert lifetime | 2/3 threshold | → Renew within |
|--------------|---------------|---------------|
| 90 days (current LE) | Day 60 | 30-day window |
| 47 days (from Mar 2029) | Day 31 | 16-day window |

ARI is intended to narrow the window further with CA-provided guidance. Until it is active, note that
the ⅔ threshold is computed from `ACMECertStore`'s **assumed** 90-day lifetime, not the certificate's
real `notAfter` — which makes the table above optimistic for any certificate shorter than 90 days. See
[`ACMECertStore`](ACMECertStore.md).

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
