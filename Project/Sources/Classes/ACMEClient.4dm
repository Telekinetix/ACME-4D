// ----------------------------------------------------
// Class: ACMEClient
// Main entry point and orchestrator for the ACME / Let's Encrypt component.
//
// Ties together all sub-classes into a single API surface for the host
// application. The host application creates an ACMEConfig, passes it to
// ACMEClient.new(), and calls:
//   • setup()             — one-time: load or create account, verify directory
//   • renew()             — obtain or renew the certificate immediately
//   • startScheduler()    — start the background ARI-driven renewal timer
//   • status()            — query current cert status for monitoring
//
// Standard result object (all public methods):
//   { success: Boolean; error: Text; data: Variant }
//
// Minimum platform: 4D v20.0 LTS
//
// Example usage (host application startup):
//   var $cfg : cs.ACMEConfig
//   $cfg:=cs.ACMEConfig.new()
//   $cfg.setEmail("admin@example.com").addIdentifier("myhost.example.com")
//   $cfg.setCertPath("/ssl/cert.pem").setKeyPath("/ssl/key.pem")
//   $cfg.setStaging(False)
//   var $acme : cs.ACMEClient
//   $acme:=cs.ACMEClient.new($cfg)
//   $acme.setup()
//   $acme.startScheduler()
//
// For a first run or forced renewal:
//   $acme.renew()
//
// To query status (fleet monitoring):
//   var $status : Object := $acme.status()
// ----------------------------------------------------

property _config : cs:C1710.ACMEConfig
property _logger : cs:C1710.ACMELogger
property _transport : cs:C1710.ACMETransport
property _signer : cs:C1710.ACMEJwsSigner
property _account : cs:C1710.ACMEAccount
property _challenge : cs:C1710.ACMEChallenge
property _certStore : cs:C1710.ACMECertStore
property _scheduler : cs:C1710.ACMEScheduler
property _isSetup : Boolean
property _version : Text


Class constructor($config : cs:C1710.ACMEConfig)
	This:C1470._config:=$config
	This:C1470._version:="0.1.0"
	This:C1470._isSetup:=False:C215
	
	// Construct the logger first (all other classes receive it)
	This:C1470._logger:=cs:C1710.ACMELogger.new(cs:C1710.ACMELogger.new().INFO)
	
	// Construct sub-components
	This:C1470._transport:=cs:C1710.ACMETransport.new($config; This:C1470._logger)
	This:C1470._account:=cs:C1710.ACMEAccount.new($config; This:C1470._logger)
	This:C1470._challenge:=cs:C1710.ACMEChallenge.new($config; This:C1470._logger)
	This:C1470._certStore:=cs:C1710.ACMECertStore.new($config; This:C1470._logger)
	This:C1470._scheduler:=Null:C1517  // created on startScheduler()
	This:C1470._signer:=Null:C1517  // created after account key is loaded
	
	
	// ============================================================
	// CONFIGURATION HELPERS
	// ============================================================
	
Function version() : Text
	return This:C1470._version
	
	
Function setLogLevel($vl_level : Integer) : cs:C1710.ACMEClient
	// 0=ERROR 1=WARN 2=INFO 3=DEBUG
	This:C1470._logger.setLevel($vl_level)
	return This:C1470
	
	
Function logger() : cs:C1710.ACMELogger
	return This:C1470._logger
	
	
	// ============================================================
	// SETUP
	// ============================================================
	
Function setup() : Object
	// Initialise the component:
	//   1. Validate config
	//   2. Fetch the ACME directory (verify the CA is reachable)
	//   3. Load or generate the account key
	//   4. Register the account (or confirm existing registration)
	//   5. Wire the signer to the transport
	// Must be called before renew() or startScheduler().
	var $result : Object
	$result:=New object:C1471("success"; False:C215; "error"; ""; "data"; Null:C1517)
	
	// 1. Validate config
	If (Not:C34(This:C1470._config.isValid()))
		$result.error:=This:C1470._config.validationError()
		This:C1470._logger.error("ACMEClient.setup() failed: invalid config — "+$result.error; Null:C1517)
		return $result
	End if 
	
	This:C1470._logger.info("ACME setup starting"; New object:C1471(\
		"staging"; This:C1470._config.staging; \
		"directoryUrl"; This:C1470._config.directoryUrl))
	
	// 2. Fetch directory (validates CA reachability)
	var $vo_dir : Object
	$vo_dir:=This:C1470._transport.directory()
	If ($vo_dir=Null:C1517)
		$result.error:="Could not fetch ACME directory from: "+This:C1470._config.directoryUrl
		return $result
	End if 
	
	// 3. Load or generate account key
	var $vb_hasAccount : Boolean
	$vb_hasAccount:=This:C1470._account.load()
	
	If (Not:C34($vb_hasAccount))
		This:C1470._logger.info("No existing account — generating new key pair"; Null:C1517)
		This:C1470._account.generateKey()
	End if 
	
	// 4. Create JWS signer from the account key
	This:C1470._signer:=cs:C1710.ACMEJwsSigner.new(This:C1470._account.privateKeyPem())
	This:C1470._transport.setSigner(This:C1470._signer)
	
	// Handle the JWK public key extraction for the signer
	// (see ACMEJwsSigner._buildPublicJwk() spike notes)
	var $vo_jwk : Object
	$vo_jwk:=This:C1470._signer.publicJwk()
	
	If ($vo_jwk=Null:C1517)
		// JWK extraction failed — need to regenerate the key via ACME CryptoKey
		// to get a JWKS-based key so we can extract n and e for the JWK header.
		This:C1470._logger.warn("Could not extract JWK from existing key PEM; regenerating via JWKS path"; Null:C1517)
		var $vo_result : Object
		$vo_result:=This:C1470._regenerateKeyViaJwks()
		If (Not:C34($vo_result.success))
			$result.error:="Could not obtain JWK from account key: "+$vo_result.error
			return $result
		End if 
	End if 
	
	// 5. Register or confirm account
	If (Not:C34(This:C1470._account.isRegistered))
		var $vo_regResult : Object
		$vo_regResult:=This:C1470._account.register(This:C1470._transport; This:C1470._signer)
		If (Not:C34($vo_regResult.success))
			$result.error:="Account registration failed: "+$vo_regResult.error
			return $result
		End if 
		This:C1470._account.save()
	Else 
		// Already registered — switch signer to KID mode
		This:C1470._signer.setKid(This:C1470._account.accountUrl)
		This:C1470._logger.info("Using existing account"; New object:C1471("accountUrl"; This:C1470._account.accountUrl))
	End if 
	
	This:C1470._isSetup:=True:C214
	$result.success:=True:C214
	This:C1470._logger.info("ACME setup complete"; Null:C1517)
	return $result
	
	
	// ============================================================
	// RENEW (OBTAIN OR RENEW CERTIFICATE)
	// ============================================================
	
Function renew() : Object
	// Obtain a new certificate or renew the existing one.
	// Runs the full order → authorize → finalize → download → install cycle.
	// Safe to call when a valid cert exists (will skip if not needed, unless forced).
	// Returns { success: Boolean; error: Text; certPath: Text; skipped: Boolean }
	var $result : Object
	$result:=New object:C1471("success"; False:C215; "error"; ""; "certPath"; ""; "skipped"; False:C215)
	
	If (Not:C34(This:C1470._isSetup))
		var $vo_setup : Object
		$vo_setup:=This:C1470.setup()
		If (Not:C34($vo_setup.success))
			$result.error:="Setup failed: "+$vo_setup.error
			return $result
		End if 
	End if 
	
	// Record the attempt
	This:C1470._certStore.recordAttempt()
	
	This:C1470._logger.info("Starting certificate issuance/renewal"; New object:C1471(\
		"hostname"; String:C10(This:C1470._config.identifiers[0]); \
		"staging"; This:C1470._config.staging))
	
	// Generate a new certificate key pair (separate from the account key)
	var $vo_certKey : 4D:C1709.CryptoKey
	var $vo_certKeyParams : Object
	$vo_certKeyParams:=New object:C1471("type"; "RSA"; "size"; 2048)
	$vo_certKey:=4D:C1709.CryptoKey.new($vo_certKeyParams)
	var $vt_certKeyPem : Text
	$vt_certKeyPem:=$vo_certKey.getPrivateKey()
	
	// Run the order state machine
	var $vo_order : cs:C1710.ACMEOrder
	$vo_order:=cs:C1710.ACMEOrder.new(\
		This:C1470._config; \
		This:C1470._logger; \
		This:C1470._transport; \
		This:C1470._challenge; \
		This:C1470._signer)
	
	var $vo_orderResult : Object
	$vo_orderResult:=$vo_order.issueCertificate($vt_certKeyPem)
	
	If (Not:C34($vo_orderResult.success))
		$result.error:=$vo_orderResult.error
		This:C1470._logger.error("Certificate issuance failed"; New object:C1471("error"; $vo_orderResult.error))
		return $result
	End if 
	
	// Save cert and key
	var $vo_saveResult : Object
	$vo_saveResult:=This:C1470._certStore.saveCertificate($vo_orderResult.certPem; $vt_certKeyPem)
	If (Not:C34($vo_saveResult.success))
		$result.error:="Certificate save failed: "+$vo_saveResult.error
		return $result
	End if 
	
	// Record success
	This:C1470._certStore.recordSuccess()
	
	// Trigger web server reload
	var $vo_reloadResult : Object
	$vo_reloadResult:=This:C1470._certStore.triggerReload()
	If (Not:C34($vo_reloadResult.success))
		// Non-fatal: cert is on disk, reload just failed
		This:C1470._logger.warn("Post-renew reload action failed: "+$vo_reloadResult.error; Null:C1517)
	End if 
	
	$result.success:=True:C214
	$result.certPath:=This:C1470._config.certPath
	return $result
	
	
Function renewIfNeeded() : Object
	// Renew only if the cert store indicates renewal is due.
	If (This:C1470._certStore.needsRenewal())
		return This:C1470.renew()
	End if 
	var $result : Object
	$result:=New object:C1471("success"; True:C214; "error"; ""; "skipped"; True:C214)
	return $result
	
	
	// ============================================================
	// SCHEDULER
	// ============================================================
	
Function startScheduler() : cs:C1710.ACMEClient
	// Start the background ARI-driven renewal scheduler.
	// Call from onHostDatabaseEvent or equivalent.
	This:C1470._scheduler:=cs:C1710.ACMEScheduler.new(This:C1470._config; This:C1470._logger; This:C1470)
	This:C1470._scheduler.start()
	return This:C1470
	
	
Function stopScheduler()
	If (This:C1470._scheduler#Null:C1517)
		This:C1470._scheduler.stop()
	End if 
	
	
Function runSchedulerCheck()
	// Execute a scheduler check from a worker process.
	// Host application should call:
	//   CALL WORKER("ACME_Scheduler"; "ACME_SchedulerWorker")
	// where ACME_SchedulerWorker is a project method that calls:
	//   cs.ACMEClient.getSharedInstance().runSchedulerCheck()
	If (This:C1470._scheduler#Null:C1517)
		This:C1470._scheduler.check()
	End if 
	
	
	// ============================================================
	// STATUS
	// ============================================================
	
Function status() : Object
	// Return a composite status object for monitoring.
	// Combines cert store status with scheduler state.
	var $vo_status : Object
	$vo_status:=This:C1470._certStore.status()
	$vo_status.version:=This:C1470._version
	$vo_status.staging:=This:C1470._config.staging
	$vo_status.isSetup:=This:C1470._isSetup
	
	// Include scheduler state from Storage if available
	If (OB Is defined:C1231(Storage:C1525; "acme")) && (OB Is defined:C1231(Storage:C1525.acme; "scheduler"))
		$vo_status.scheduler:=Storage:C1525.acme.scheduler
	Else 
		$vo_status.scheduler:=New object:C1471("running"; "false")
	End if 
	
	return $vo_status
	
	
	// ============================================================
	// CHALLENGE HANDLER (called by host web server URL handler)
	// ============================================================
	
Function handleChallengeRequest($vt_requestUrl : Text) : Object
	// Entry point for the host web server's URL handler for:
	//   /.well-known/acme-challenge/<token>
	//
	// Returns { found: Boolean; keyAuth: Text } where keyAuth is the
	// response body to send as text/plain with HTTP 200.
	// Returns { found: False } if no active challenge for this URL.
	//
	// Host URL handler example:
	//   If (Match regex("^\/.well-known\/acme-challenge\/(.+)$"; $1URL; 1; $pos; $len))
	//     var $token : Text := Substring($1URL; $pos{1}; $len{1})
	//     var $resp : Object := $acme.handleChallengeRequest($1URL)
	//     If ($resp.found)
	//       WEB SEND TEXT($resp.keyAuth; "text/plain")
	//     Else
	//       WEB SEND HTTP REDIRECT("/"; "*")
	//     End if
	//   End if
	
	// Extract token from URL path /.well-known/acme-challenge/<token>
	var $vt_token : Text
	var $vl_pos : Integer
	$vl_pos:=Position:C15("/.well-known/acme-challenge/"; $vt_requestUrl)
	If ($vl_pos=0)
		return New object:C1471("found"; False:C215; "keyAuth"; "")
	End if 
	
	$vt_token:=Substring:C12($vt_requestUrl; $vl_pos+Length:C16("/.well-known/acme-challenge/"))
	// Strip any query string
	var $vl_qpos : Integer
	$vl_qpos:=Position:C15("?"; $vt_token)
	If ($vl_qpos>0)
		$vt_token:=Substring:C12($vt_token; 1; $vl_qpos-1)
	End if 
	
	var $vt_keyAuth : Text
	$vt_keyAuth:=This:C1470._challenge.serveWebServerChallenge($vt_requestUrl; $vt_token)
	
	If (Length:C16($vt_keyAuth)>0)
		return New object:C1471("found"; True:C214; "keyAuth"; $vt_keyAuth)
	End if 
	
	return New object:C1471("found"; False:C215; "keyAuth"; "")
	
	
	// ============================================================
	// INTERNAL
	// ============================================================
	
Function _regenerateKeyViaJwks() : Object
	// When we can't extract JWK from a loaded PEM key, generate a fresh key
	// specifically via the 4D CryptoKey type="RSA" path which allows JWKS export.
	// This replaces the account key — only safe before first registration.
	var $result : Object
	$result:=New object:C1471("success"; False:C215; "error"; "")
	
	If (This:C1470._account.isRegistered)
		$result.error:="Cannot regenerate account key after registration"
		return $result
	End if 
	
	This:C1470._account.generateKey()
	
	// Re-create signer with new key
	This:C1470._signer:=cs:C1710.ACMEJwsSigner.new(This:C1470._account.privateKeyPem())
	This:C1470._transport.setSigner(This:C1470._signer)
	
	var $vo_jwk : Object
	$vo_jwk:=This:C1470._signer.publicJwk()
	If ($vo_jwk=Null:C1517)
		$result.error:="JWK extraction still failing after key regeneration — platform spike needed"
		return $result
	End if 
	
	$result.success:=True:C214
	return $result
	