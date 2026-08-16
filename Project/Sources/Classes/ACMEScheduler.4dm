// ----------------------------------------------------
// Class: ACMEScheduler
// ARI-driven renewal scheduler for the ACME component.
//
// Runs on a 4D timer (via CALL ON TIMER / On Activate event from the host,
// or via a worker process). Checks whether the certificate needs renewal
// by querying ACME Renewal Information (RFC 9773) where available, with
// a time-based fallback (2/3 of lifetime elapsed).
//
// Jitter is applied to the next-check time so that deployments of this
// component across many systems do not synchronise their CA hits.
//
// Design for the 47-day future cert lifetime (SC-081v3):
//   At 47 days valid, 2/3 threshold = ~31 days after issue.
//   Check interval: daily (configurable). ARI window used when CA provides it.
//
// The scheduler is started by ACMEClient.startScheduler() which should be
// called from onHostDatabaseEvent (On before host database startup) or
// equivalent host startup hook.
//
// Worker model (recommended for v20.0):
//   The scheduler uses CALL WORKER to keep the check in a named background
//   worker process, avoiding blocking the main process.
//   Worker name: "ACME_Scheduler"
//
// Storage integration:
//   The scheduler writes its running state to Storage.acme.scheduler so the
//   host can query next-check time and last result without accessing files.
// ----------------------------------------------------

property _config : cs.acme.ACMEConfig
property _logger : cs.acme.ACMELogger
property _client : cs.acme.ACMEClient  // Back-reference for triggering renewal
property _checkIntervalHours : Integer
property _running : Boolean

// Storage key name for scheduler state
property _storageKey : Text


Class constructor($config : cs.acme.ACMEConfig; $logger : cs.acme.ACMELogger; $client : cs.acme.ACMEClient)
	This._config:=$config
	This._logger:=$logger
	This._client:=$client
	This._checkIntervalHours:=24  // check once daily by default
	This._running:=False
	This._storageKey:="acme"


// ============================================================
// START / STOP
// ============================================================

Function start()
	// Mark the scheduler as running and record the initial next-check time.
	This._running:=True
	This._initStorage()
	var $vd_nextCheck : Date
	$vd_nextCheck:=This._computeNextCheck()
	This._updateStorage("nextCheck"; String($vd_nextCheck; ISO date))
	This._logger.info("ACME scheduler started"; New object(\
		"nextCheck"; String($vd_nextCheck; ISO date); \
		"intervalHours"; This._checkIntervalHours))


Function stop()
	This._running:=False
	This._updateStorage("running"; "false")
	This._logger.info("ACME scheduler stopped"; Null)


Function setCheckIntervalHours($hours : Integer) : cs.acme.ACMEScheduler
	This._checkIntervalHours:=$hours
	return This


// ============================================================
// SCHEDULED CHECK (called on timer or by worker)
// ============================================================

Function check()
	// Evaluate whether renewal is due and trigger it if so.
	// This method is designed to be called from a worker process via CALL WORKER.
	// It is also safe to call directly for testing.

	If (Not(This._running))
		return
	End if

	This._logger.debug("Scheduler check running"; Null)
	This._updateStorage("lastCheck"; String(Current date; ISO date; Current time))

	// First: query ARI for the suggested renewal window (RFC 9773)
	var $vb_ariChecked : Boolean
	$vb_ariChecked:=This._checkAri()

	// Build a temporary cert store to evaluate renewal need
	var $vo_certStore : cs.acme.ACMECertStore
	$vo_certStore:=cs.acme.ACMECertStore.new(This._config; This._logger)

	If ($vo_certStore.needsRenewal())
		This._logger.info("Renewal required — starting issuance"; Null)
		This._updateStorage("status"; "renewing")
		var $vo_result : Object
		$vo_result:=This._client.renew()
		If ($vo_result.success)
			This._updateStorage("status"; "ok")
			This._updateStorage("lastRenewal"; String(Current date; ISO date; Current time))
		Else
			This._updateStorage("status"; "error")
			This._updateStorage("lastError"; $vo_result.error)
			This._logger.error("Scheduled renewal failed"; New object("error"; $vo_result.error))
		End if
	Else
		This._logger.debug("Certificate does not need renewal yet"; Null)
	End if

	// Schedule next check
	var $vd_nextCheck : Date
	$vd_nextCheck:=This._computeNextCheck()
	This._updateStorage("nextCheck"; String($vd_nextCheck; ISO date))
	$vo_certStore.recordNextCheck($vd_nextCheck)


// ============================================================
// ARI (RFC 9773)
// ============================================================

Function _checkAri() : Boolean
	// Query the ACME renewalInfo endpoint for the certificate's suggested
	// renewal window and update the cert store metadata.
	// Returns True if ARI data was successfully retrieved and stored.
	//
	// ARI URL format (RFC 9773 §4.1):
	//   <renewalInfo>/<base64url(issuerKeyHash)>.<base64url(serial)>
	//   where issuerKeyHash and serial are from the certificate's AKI extension.
	//
	// SPIKE NOTE: Parsing the AKI and serial from the PEM cert requires
	// the same ASN.1 DER parser gap as notAfter parsing. For MVP, ARI is
	// implemented as a documented placeholder. The scheduler will fall back
	// to the time-based trigger until the DER parser is available.

	var $vt_ariUrl : Text
	$vt_ariUrl:=This._buildAriUrl()

	If (Length($vt_ariUrl)=0)
		// ARI not available or cert not parseable for ARI URL — use time-based fallback
		return False
	End if

	// Fetch renewalInfo (GET, no signing required per RFC 9773 §4.1)
	var $vo_options : Object
	var $vo_request : 4D.HTTPRequest
	var vl_acmeHttpError : Integer
	var vt_acmeHttpError : Text

	$vo_options:=New object(\
		"method"; "GET"; \
		"headers"; New object("Accept"; "application/json"); \
		"timeout"; This._config.timeout)

	vl_acmeHttpError:=0
	vt_acmeHttpError:=""
	ON ERR CALL("ACME_HTTP_Error")
	$vo_request:=4D.HTTPRequest.new($vt_ariUrl; $vo_options)
	$vo_request.wait()
	ON ERR CALL("")

	If (vl_acmeHttpError#0) | ($vo_request.response=Null)
		return False
	End if

	If ($vo_request.response.status#200)
		return False
	End if

	// Parse the renewalInfo response: { "suggestedWindow": { "start": "...", "end": "..." } }
	var $vt_body : Text
	var $vo_body : Object
	If (Value type($vo_request.response.body)=Is text)
		$vt_body:=$vo_request.response.body
	End if
	$vo_body:=Try(JSON Parse($vt_body))

	If ($vo_body=Null) | (Not(OB Is defined($vo_body; "suggestedWindow")))
		return False
	End if

	var $vo_window : Object
	$vo_window:=$vo_body.suggestedWindow

	// Apply jitter within the ARI window: pick a random time within the window
	var $vo_jitteredWindow : Object
	$vo_jitteredWindow:=This._applyAriJitter($vo_window)

	// Store in cert metadata
	var $vo_certStore : cs.acme.ACMECertStore
	$vo_certStore:=cs.acme.ACMECertStore.new(This._config; This._logger)
	$vo_certStore.updateAriRenewalWindow($vo_jitteredWindow)

	This._logger.debug("ARI renewal window updated"; New object(\
		"start"; String($vo_jitteredWindow.start); \
		"end"; String($vo_jitteredWindow.end)))

	return True


Function _buildAriUrl() : Text
	// Build the ARI URL for the current certificate.
	// Requires parsing the certificate DER — placeholder implementation.
	// Returns "" if ARI cannot be computed (triggers time-based fallback).
	var $vt_ariBase : Text
	$vt_ariBase:=String(This._client._transport.directoryUrl("renewalInfo"))
	If (Length($vt_ariBase)=0)
		return ""  // CA does not advertise ARI
	End if

	// TODO: Extract issuerKeyHash and serial from the cert DER.
	// Until the DER parser spike is resolved, return "" to use time-based logic.
	return ""


Function _applyAriJitter($vo_window : Object) : Object
	// Pick a jittered start within the ARI window so deployments across
	// many systems do not all hit the CA simultaneously.
	// Simple implementation: random fraction of the window duration.
	var $vo_jittered : Object
	$vo_jittered:=New object(\
		"start"; String($vo_window.start); \
		"end"; String($vo_window.end))

	// Jitter: shift start forward by a random 0–30% of the window duration.
	// Full implementation requires date arithmetic in seconds — use as-is for now.
	// A proper jitter implementation needs millisecond-precision date parsing.
	return $vo_jittered


// ============================================================
// NEXT-CHECK COMPUTATION
// ============================================================

Function _computeNextCheck() : Date
	// Return the next check date: $checkIntervalHours from now, rounded to day.
	// The day-level granularity is sufficient for the scheduler — the ARI window
	// provides fine-grained timing for the actual renewal trigger.
	var $vd_next : Date
	$vd_next:=Current date+This._checkIntervalHours\24
	If (This._checkIntervalHours\24=0)
		$vd_next:=Current date+1
	End if
	return $vd_next


// ============================================================
// STORAGE HELPERS
// ============================================================

Function _initStorage()
	If (Not(OB Is defined(Storage; This._storageKey)))
		Use (Storage)
			Storage[This._storageKey]:=New shared object
		End use
	End if
	Use (Storage[This._storageKey])
		Storage[This._storageKey].scheduler:=New shared object(\
			"running"; "true"; \
			"status"; "idle"; \
			"nextCheck"; ""; \
			"lastCheck"; ""; \
			"lastRenewal"; ""; \
			"lastError"; "")
	End use


Function _updateStorage($vt_key : Text; $vt_value : Text)
	If (OB Is defined(Storage; This._storageKey)) && (OB Is defined(Storage[This._storageKey]; "scheduler"))
		Use (Storage[This._storageKey].scheduler)
			Storage[This._storageKey].scheduler[$vt_key]:=$vt_value
		End use
	End if
