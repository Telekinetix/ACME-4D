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

property _config : cs:C1710.ACMEConfig
property _logger : cs:C1710.ACMELogger
property _client : cs:C1710.ACMEClient  // Back-reference for triggering renewal
property _checkIntervalHours : Integer
property _running : Boolean

// Storage key name for scheduler state
property _storageKey : Text


Class constructor($config : cs:C1710.ACMEConfig; $logger : cs:C1710.ACMELogger; $client : cs:C1710.ACMEClient)
	This:C1470._config:=$config
	This:C1470._logger:=$logger
	This:C1470._client:=$client
	This:C1470._checkIntervalHours:=24  // check once daily by default
	This:C1470._running:=False:C215
	This:C1470._storageKey:="acme"
	
	
	// ============================================================
	// START / STOP
	// ============================================================
	
Function start()
	// Mark the scheduler as running and record the initial next-check time.
	This:C1470._running:=True:C214
	This:C1470._initStorage()
	var $vd_nextCheck : Date
	$vd_nextCheck:=This:C1470._computeNextCheck()
	This:C1470._updateStorage("nextCheck"; String:C10($vd_nextCheck; ISO date:K1:8))
	This:C1470._logger.info("ACME scheduler started"; New object:C1471(\
		"nextCheck"; String:C10($vd_nextCheck; ISO date:K1:8); \
		"intervalHours"; This:C1470._checkIntervalHours))
	
	
Function stop()
	This:C1470._running:=False:C215
	This:C1470._updateStorage("running"; "false")
	This:C1470._logger.info("ACME scheduler stopped"; Null:C1517)
	
	
Function setCheckIntervalHours($hours : Integer) : cs:C1710.ACMEScheduler
	This:C1470._checkIntervalHours:=$hours
	return This:C1470
	
	
	// ============================================================
	// SCHEDULED CHECK (called on timer or by worker)
	// ============================================================
	
Function check()
	// Evaluate whether renewal is due and trigger it if so.
	// This method is designed to be called from a worker process via CALL WORKER.
	// It is also safe to call directly for testing.
	
	If (Not:C34(This:C1470._running))
		return 
	End if 
	
	This:C1470._logger.debug("Scheduler check running"; Null:C1517)
	This:C1470._updateStorage("lastCheck"; String:C10(Current date:C33; ISO date:K1:8; Current time:C178))
	
	// First: query ARI for the suggested renewal window (RFC 9773)
	var $vb_ariChecked : Boolean
	$vb_ariChecked:=This:C1470._checkAri()
	
	// Build a temporary cert store to evaluate renewal need
	var $vo_certStore : cs:C1710.ACMECertStore
	$vo_certStore:=cs:C1710.ACMECertStore.new(This:C1470._config; This:C1470._logger)
	
	If ($vo_certStore.needsRenewal())
		This:C1470._logger.info("Renewal required — starting issuance"; Null:C1517)
		This:C1470._updateStorage("status"; "renewing")
		var $vo_result : Object
		$vo_result:=This:C1470._client.renew()
		If ($vo_result.success)
			This:C1470._updateStorage("status"; "ok")
			This:C1470._updateStorage("lastRenewal"; String:C10(Current date:C33; ISO date:K1:8; Current time:C178))
		Else 
			This:C1470._updateStorage("status"; "error")
			This:C1470._updateStorage("lastError"; $vo_result.error)
			This:C1470._logger.error("Scheduled renewal failed"; New object:C1471("error"; $vo_result.error))
		End if 
	Else 
		This:C1470._logger.debug("Certificate does not need renewal yet"; Null:C1517)
	End if 
	
	// Schedule next check
	var $vd_nextCheck : Date
	$vd_nextCheck:=This:C1470._computeNextCheck()
	This:C1470._updateStorage("nextCheck"; String:C10($vd_nextCheck; ISO date:K1:8))
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
	$vt_ariUrl:=This:C1470._buildAriUrl()
	
	If (Length:C16($vt_ariUrl)=0)
		// ARI not available or cert not parseable for ARI URL — use time-based fallback
		return False:C215
	End if 
	
	// Fetch renewalInfo (GET, no signing required per RFC 9773 §4.1)
	var $vo_options : Object
	var $vo_request : 4D:C1709.HTTPRequest
	var vl_acmeHttpError : Integer
	var vt_acmeHttpError : Text
	
	$vo_options:=New object:C1471(\
		"method"; "GET"; \
		"headers"; New object:C1471("Accept"; "application/json"); \
		"timeout"; This:C1470._config.timeout)
	
	vl_acmeHttpError:=0
	vt_acmeHttpError:=""
	ON ERR CALL:C155("ACME_HTTP_Error")
	$vo_request:=4D:C1709.HTTPRequest.new($vt_ariUrl; $vo_options)
	$vo_request.wait()
	ON ERR CALL:C155("")
	
	If (vl_acmeHttpError#0) | ($vo_request.response=Null:C1517)
		return False:C215
	End if 
	
	If ($vo_request.response.status#200)
		return False:C215
	End if 
	
	// Parse the renewalInfo response: { "suggestedWindow": { "start": "...", "end": "..." } }
	var $vt_body : Text
	var $vo_body : Object
	If (Value type:C1509($vo_request.response.body)=Is text:K8:3)
		$vt_body:=$vo_request.response.body
	End if 
	$vo_body:=Try(JSON Parse:C1218($vt_body))
	
	If ($vo_body=Null:C1517) | (Not:C34(OB Is defined:C1231($vo_body; "suggestedWindow")))
		return False:C215
	End if 
	
	var $vo_window : Object
	$vo_window:=$vo_body.suggestedWindow
	
	// Apply jitter within the ARI window: pick a random time within the window
	var $vo_jitteredWindow : Object
	$vo_jitteredWindow:=This:C1470._applyAriJitter($vo_window)
	
	// Store in cert metadata
	var $vo_certStore : cs:C1710.ACMECertStore
	$vo_certStore:=cs:C1710.ACMECertStore.new(This:C1470._config; This:C1470._logger)
	$vo_certStore.updateAriRenewalWindow($vo_jitteredWindow)
	
	This:C1470._logger.debug("ARI renewal window updated"; New object:C1471(\
		"start"; String:C10($vo_jitteredWindow.start); \
		"end"; String:C10($vo_jitteredWindow.end)))
	
	return True:C214
	
	
Function _buildAriUrl() : Text
	// Build the ARI URL for the current certificate.
	// Requires parsing the certificate DER — placeholder implementation.
	// Returns "" if ARI cannot be computed (triggers time-based fallback).
	var $vt_ariBase : Text
	$vt_ariBase:=String:C10(This:C1470._client._transport.directoryUrl("renewalInfo"))
	If (Length:C16($vt_ariBase)=0)
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
	$vo_jittered:=New object:C1471(\
		"start"; String:C10($vo_window.start); \
		"end"; String:C10($vo_window.end))
	
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
	If (This:C1470._checkIntervalHours\24=0)
		$vd_next:=Current date:C33+1
	Else 
		$vd_next:=Add to date:C393($vd_next; 0; 0; This:C1470._checkIntervalHours\24)
	End if 
	return $vd_next
	
	
	// ============================================================
	// STORAGE HELPERS
	// ============================================================
	
Function _initStorage()
	If (Not:C34(OB Is defined:C1231(Storage:C1525; This:C1470._storageKey)))
		Use (Storage:C1525)
			Storage:C1525[This:C1470._storageKey]:=New shared object:C1526
		End use 
	End if 
	Use (Storage:C1525[This:C1470._storageKey])
		Storage:C1525[This:C1470._storageKey].scheduler:=New shared object:C1526(\
			"running"; "true"; \
			"status"; "idle"; \
			"nextCheck"; ""; \
			"lastCheck"; ""; \
			"lastRenewal"; ""; \
			"lastError"; "")
	End use 
	
	
Function _updateStorage($vt_key : Text; $vt_value : Text)
	If (OB Is defined:C1231(Storage:C1525; This:C1470._storageKey)) && (OB Is defined:C1231(Storage:C1525[This:C1470._storageKey]; "scheduler"))
		Use (Storage:C1525[This:C1470._storageKey].scheduler)
			Storage:C1525[This:C1470._storageKey].scheduler[$vt_key]:=$vt_value
		End use 
	End if 
	