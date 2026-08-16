// ----------------------------------------------------
// Method: ACME_SchedulerWorker
// Worker method for the ACME renewal scheduler.
// This method is called by CALL WORKER from the scheduler's check() method
// or from the host's database startup event.
//
// The host application starts the scheduler by calling:
//   CALL WORKER("ACME_Scheduler"; "ACME_SchedulerWorker")
//
// This method looks up the shared ACMEClient instance from Storage and
// triggers a scheduled renewal check. It is designed to be called
// periodically (e.g. via a timer or On Startup event).
//
// Storage entry point: Storage.acme.clientRef is set by the host after
// calling cs.acme.ACMEClient.new() and setup().
// Since Formula objects cannot be stored in shared Storage, the worker
// uses CALL WORKER to re-enter the host's coordinator method.
//
// For fleet deployments: each host application should implement its own
// ACME startup coordinator that:
//   1. Creates ACMEConfig with site-specific settings
//   2. Creates ACMEClient and calls setup()
//   3. Stores the client reference in a process variable
//   4. Calls startScheduler()
// ----------------------------------------------------
//%attributes = {}

// This method is a placeholder entry point.
// The host application's startup method creates and holds the ACMEClient
// reference. The scheduler's check is triggered by the host coordinator
// calling $acme.runSchedulerCheck() on its timer.
//
// See docs/tk-acme-component-kickoff.md §6 for the full architecture.
//
// Minimal implementation for testing:
//   Call CALL WORKER("ACME_Scheduler"; "ACME_SchedulerWorker")
//   from the host's On Timer event to drive the check cycle.
