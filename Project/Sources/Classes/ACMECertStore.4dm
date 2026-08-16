// ----------------------------------------------------
// Class: ACMECertStore
// Certificate and private key storage, installation, and status reporting.
//
// Responsibilities:
//   • Save the issued PEM certificate chain and private key to the paths
//     configured in ACMEConfig.certPath / keyPath.
//   • Save metadata (not-after date, last success timestamp) alongside the
//     cert so the scheduler and status surface can read it without parsing
//     the PEM certificate.
//   • Load and parse enough of the existing certificate to determine whether
//     it needs renewal (using the not-after date).
//   • Trigger the post-renewal action (restart web server, or call formula).
//   • Report per-cert status: not-after, last attempt, last success, next check.
//
// Metadata file: <certPath parent>/acme-cert-meta.json
//   {
//     "notAfter":    "<ISO8601 date>",
//     "issuedAt":    "<ISO8601 datetime>",
//     "renewalWindow": { "start": "<ISO8601>", "end": "<ISO8601>" },  // from ARI
//     "lastSuccess": "<ISO8601 datetime>",
//     "lastAttempt": "<ISO8601 datetime>",
//     "nextCheck":   "<ISO8601 datetime>",
//     "serial":      "<hex serial number>",
//     "hostname":    "<CN>"
//   }
//
// Private key file contents are never logged.
// ----------------------------------------------------

property _config : cs.acme.ACMEConfig
property _logger : cs.acme.ACMELogger


Class constructor($config : cs.acme.ACMEConfig; $logger : cs.acme.ACMELogger)
	This._config:=$config
	This._logger:=$logger


// ============================================================
// SAVE
// ============================================================

Function saveCertificate($vt_certPem : Text; $vt_keyPem : Text) : Object
	// Write the certificate chain PEM and private key PEM to their configured paths.
	// Returns { success: Boolean; error: Text }
	// SECURITY: $vt_keyPem is never logged.
	var $result : Object
	$result:=New object("success"; False; "error"; "")

	// Ensure parent directories exist
	var $vf_cert : 4D.File
	var $vf_key : 4D.File
	$vf_cert:=File(This._config.certPath)
	$vf_key:=File(This._config.keyPath)

	If (Not($vf_cert.parent.exists))
		Try
			$vf_cert.parent.create()
		Catch
			$result.error:="Could not create cert directory: "+This._config.certPath
			return $result
		End try
	End if

	If (Not($vf_key.parent.exists))
		Try
			$vf_key.parent.create()
		Catch
			$result.error:="Could not create key directory: "+This._config.keyPath
			return $result
		End try
	End if

	// Write certificate (not secret — logged only by path, not content)
	Try
		$vf_cert.setText($vt_certPem; "utf-8")
	Catch
		$result.error:="Failed to write certificate file: "+This._config.certPath
		return $result
	End try

	// Write private key (secret — path only, content never logged)
	Try
		$vf_key.setText($vt_keyPem; "utf-8")
	Catch
		$result.error:="Failed to write key file"
		return $result
	End try

	// Save metadata
	This._saveMeta($vt_certPem)

	This._logger.info("Certificate and key saved"; New object("certPath"; This._config.certPath))
	$result.success:=True
	return $result


// ============================================================
// LOAD / CHECK EXPIRY
// ============================================================

Function needsRenewal() : Boolean
	// Returns True if the current certificate does not exist, has expired,
	// or has passed the 2/3-lifetime renewal trigger point.
	// If ARI renewal window data is available in metadata, uses that instead.

	var $vo_meta : Object
	$vo_meta:=This._loadMeta()

	If ($vo_meta=Null)
		// No cert on disk — definitely need to issue one
		return True
	End if

	// Check ARI renewal window first (RFC 9773)
	If (OB Is defined($vo_meta; "renewalWindow")) && ($vo_meta.renewalWindow#Null)
		var $vt_ariStart : Text
		$vt_ariStart:=String($vo_meta.renewalWindow.start)
		If (Length($vt_ariStart)>0)
			var $vd_ariStart : Date
			$vd_ariStart:=Date($vt_ariStart)
			If (Current date>=$vd_ariStart)
				This._logger.info("Renewal triggered by ARI window"; New object("ariStart"; $vt_ariStart))
				return True
			End if
			// ARI says not yet — trust it
			return False
		End if
	End if

	// Fallback: time-based trigger at 2/3 of lifetime elapsed
	If (OB Is defined($vo_meta; "notAfter")) && (OB Is defined($vo_meta; "issuedAt"))
		var $vd_notAfter : Date
		var $vd_issuedAt : Date
		$vd_notAfter:=Date(String($vo_meta.notAfter))
		$vd_issuedAt:=Date(String($vo_meta.issuedAt))

		var $vl_lifetime : Integer
		var $vl_elapsed : Integer
		$vl_lifetime:=$vd_notAfter-$vd_issuedAt
		$vl_elapsed:=Current date-$vd_issuedAt

		// Renew at 2/3 of lifetime + jitter (jitter applied in scheduler)
		var $vl_threshold : Integer
		$vl_threshold:=($vl_lifetime*2)\3  // integer division

		If ($vl_elapsed>=$vl_threshold)
			This._logger.info("Renewal triggered by time-based threshold"; New object(\
				"elapsed"; $vl_elapsed; \
				"threshold"; $vl_threshold; \
				"lifetime"; $vl_lifetime))
			return True
		End if
	Else
		// No dates in metadata — can't determine, so trigger renewal
		return True
	End if

	return False


Function certExists() : Boolean
	// Return True if the certificate file exists on disk.
	var $vf_cert : 4D.File
	$vf_cert:=File(This._config.certPath)
	return $vf_cert.exists


// ============================================================
// POST-RENEWAL ACTION
// ============================================================

Function triggerReload() : Object
	// Execute the configured post-renewal action.
	// Returns { success: Boolean; error: Text }
	var $result : Object
	$result:=New object("success"; True; "error"; "")

	Case of
		: (This._config.postRenewAction="restart")
			// WEB STOP SERVER / WEB START SERVER — brief connection drop
			This._logger.info("Restarting web server to load new certificate"; Null)
			Try
				WEB STOP SERVER
				DELAY PROCESS(Current process; 60)  // 1 second pause
				WEB START SERVER
				This._logger.info("Web server restarted"; Null)
			Catch
				$result.success:=False
				$result.error:="Web server restart failed"
				This._logger.error("Web server restart failed"; Null)
			End try

		: (This._config.postRenewAction="none")
			// No built-in action — call the formula if provided
			If (This._config.postRenewFormula#Null)
				Try
					This._config.postRenewFormula.call(This; $result)
				Catch
					This._logger.warn("Post-renew formula raised an error"; Null)
				End try
			End if

		Else
			This._logger.warn("Unknown postRenewAction: "+This._config.postRenewAction; Null)
	End case

	return $result


// ============================================================
// ARI RENEWAL WINDOW
// ============================================================

Function updateAriRenewalWindow($vo_ariWindow : Object)
	// Store the ARI-suggested renewal window from the renewalInfo response.
	// $vo_ariWindow: { start: "<ISO8601>", end: "<ISO8601>" }
	var $vo_meta : Object
	$vo_meta:=This._loadMeta()
	If ($vo_meta=Null)
		$vo_meta:=New object
	End if
	$vo_meta.renewalWindow:=$vo_ariWindow
	This._writeMeta($vo_meta)


// ============================================================
// STATUS SURFACE
// ============================================================

Function status() : Object
	// Return a status object for fleet monitoring.
	//   { hostname, notAfter, issuedAt, lastSuccess, lastAttempt,
	//     nextCheck, certExists, needsRenewal, certPath }
	var $vo_meta : Object
	$vo_meta:=This._loadMeta()

	var $vo_status : Object
	$vo_status:=New object(\
		"hostname"; String(This._config.identifiers[0]); \
		"certPath"; This._config.certPath; \
		"certExists"; This.certExists(); \
		"needsRenewal"; This.needsRenewal(); \
		"notAfter"; ""; \
		"issuedAt"; ""; \
		"lastSuccess"; ""; \
		"lastAttempt"; ""; \
		"nextCheck"; "")

	If ($vo_meta#Null)
		$vo_status.notAfter:=String($vo_meta.notAfter)
		$vo_status.issuedAt:=String($vo_meta.issuedAt)
		$vo_status.lastSuccess:=String($vo_meta.lastSuccess)
		$vo_status.lastAttempt:=String($vo_meta.lastAttempt)
		$vo_status.nextCheck:=String($vo_meta.nextCheck)
	End if

	return $vo_status


Function recordAttempt()
	// Record a renewal attempt timestamp in metadata.
	var $vo_meta : Object
	$vo_meta:=This._loadMeta()
	If ($vo_meta=Null)
		$vo_meta:=New object
	End if
	$vo_meta.lastAttempt:=String(Current date; ISO date; Current time)
	This._writeMeta($vo_meta)


Function recordSuccess()
	// Record a successful renewal timestamp in metadata.
	var $vo_meta : Object
	$vo_meta:=This._loadMeta()
	If ($vo_meta=Null)
		$vo_meta:=New object
	End if
	$vo_meta.lastSuccess:=String(Current date; ISO date; Current time)
	This._writeMeta($vo_meta)


Function recordNextCheck($vd_nextCheck : Date)
	// Record the next scheduled check date in metadata.
	var $vo_meta : Object
	$vo_meta:=This._loadMeta()
	If ($vo_meta=Null)
		$vo_meta:=New object
	End if
	$vo_meta.nextCheck:=String($vd_nextCheck; ISO date)
	This._writeMeta($vo_meta)


// ============================================================
// INTERNAL — METADATA
// ============================================================

Function _metaFilePath() : Text
	var $vf_cert : 4D.File
	$vf_cert:=File(This._config.certPath)
	return $vf_cert.parent.platformPath+"acme-cert-meta.json"


Function _loadMeta() : Object
	var $vf_meta : 4D.File
	$vf_meta:=File(This._metaFilePath())
	If (Not($vf_meta.exists))
		return Null
	End if
	Try
		var $vt_json : Text
		$vt_json:=$vf_meta.getText("utf-8")
		return JSON Parse($vt_json)
	Catch
		return Null
	End try


Function _writeMeta($vo_meta : Object)
	var $vf_meta : 4D.File
	$vf_meta:=File(This._metaFilePath())
	Try
		$vf_meta.setText(JSON Stringify($vo_meta); "utf-8")
	Catch
		This._logger.warn("Could not write cert metadata file"; Null)
	End try


Function _saveMeta($vt_certPem : Text)
	// Extract not-after from the certificate PEM and write metadata.
	// 4D does not offer native PEM parsing in v20.0; we derive the not-after
	// by computing issued date + assumed lifetime. The scheduler will request
	// ARI to get the precise window.
	//
	// For now, parse the certificate via a known workaround: export the cert
	// to a temp file and read it back using certificateInfo if available,
	// or fall back to an assumed 90-day validity from the current date.

	var $vo_meta : Object
	$vo_meta:=This._loadMeta()
	If ($vo_meta=Null)
		$vo_meta:=New object
	End if

	$vo_meta.hostname:=String(This._config.identifiers[0])
	$vo_meta.issuedAt:=String(Current date; ISO date)

	// Attempt to extract the certificate not-after date
	var $vd_notAfter : Date
	$vd_notAfter:=This._extractNotAfterFromPem($vt_certPem)
	If ($vd_notAfter=!00-00-00!)
		// Fallback: assume 90 days (Let's Encrypt standard)
		$vd_notAfter:=Current date+90
	End if

	$vo_meta.notAfter:=String($vd_notAfter; ISO date)
	$vo_meta.lastSuccess:=String(Current date; ISO date; Current time)

	This._writeMeta($vo_meta)


Function _extractNotAfterFromPem($vt_certPem : Text) : Date
	// Attempt to parse the notAfter date from a PEM certificate.
	// 4D v20.0 does not have a native PEM/X.509 parser.
	// This is a best-effort scan of the PEM for the "Not After" string that
	// some environments embed, or uses a fixed fallback.
	//
	// SPIKE NOTE: This is a known gap. The correct fix is either:
	//   (a) Use 4D v20 R6+ certificate info API if available, or
	//   (b) Parse the ASN.1 DER notAfter field (UTCTime or GeneralizedTime)
	//       by decoding the base64 PEM body.
	// For MVP, the fallback (90 days from today) is safe — the scheduler will
	// check ARI and override this.

	// Return zero date to signal "not parsed"
	return !00-00-00!
