# ACME_SchedulerWorker

Worker process entry point for the `tk-acme` renewal scheduler.

This is a placeholder method that marks the named worker process used by the scheduler. The actual scheduler check logic lives in `ACMEClient.runSchedulerCheck()` and `ACMEScheduler.check()`.

## Worker Process Name

```
"ACME_Scheduler"
```

## Recommended Pattern

The host application holds the `ACMEClient` reference and drives the scheduler check from its own timer or worker mechanism:

```4d
// In the host's startup (onHostDatabaseEvent On before host database startup):
var $cfg : cs.acme.ACMEConfig
$cfg:=cs.acme.ACMEConfig.new()
// ... configure ...
var $acme : cs.acme.ACMEClient
$acme:=cs.acme.ACMEClient.new($cfg)
$acme.setup()
$acme.startScheduler()

// Store $acme in a process variable or in a shared context
// accessible to the timer/worker.
```

```4d
// On Timer (or from a host coordinator worker, every 6-24 hours):
$acme.runSchedulerCheck()
```

## Notes

- Since `Formula` objects cannot be stored in shared `Storage`, the host application must retain the `ACMEClient` reference in its own process context.
- `CALL WORKER("ACME_Scheduler"; "ACME_SchedulerWorker")` can be used to trigger a check from any process, but the worker method must be adapted to re-create or locate the `ACMEClient` instance in the worker's context.
- For simple single-process deployments (e.g. a dedicated 4D Server method), calling `$acme.runSchedulerCheck()` directly on a timer is simpler than a separate worker.
- `runSchedulerCheck()` is a no-op unless `startScheduler()` has been called on the same client instance — it returns immediately when `_scheduler` is `Null`, and `ACMEScheduler.check()` itself returns immediately unless `_running` is `True`.
- The method file carries two `//%attributes` lines (`{"shared":true}` at the top, then a stray `{}` further down). 4D reads the first, and the method is correctly exported as shared — the second line is a leftover and should be removed.
