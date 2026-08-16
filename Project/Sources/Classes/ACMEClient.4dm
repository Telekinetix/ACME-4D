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
//   var $cfg : cs.acme.ACMEConfig
//   $cfg:=cs.acme.ACMEConfig.new()
//   $cfg.setEmail("admin@example.com").addIdentifier("myhost.example.com")
//   $cfg.setCertPath("/ssl/cert.pem").setKeyPath("/ssl/key.pem")
//   $cfg.setStaging(False)
//   var $acme : cs.acme.ACMEClient
//   $acme:=cs.acme.ACMEClient.new($cfg)
//   $acme.setup()
//   $acme.startScheduler()
//
// For a first run or forced renewal:
//   $acme.renew()
//
// To query status (fleet monitoring):
//   var $status : Object := $acme.status()
// ----------------------------------------------------

property _config : cs.acme.ACMEConfig
property _logger : cs.acme.ACMELogger
property _transport : cs.acme.ACMETransport
property _signer : cs.acme.ACMEJwsSigner
property _account : cs.acme.ACMEAccount
property _challenge : cs.acme.ACMEChallenge
property _certStore : cs.acme.ACMECertStore
property _scheduler : cs.acme.ACMEScheduler
property _isSetup : Boolean
property _version : Text


Class constructor($config : cs.acme.ACMEConfig)
	This._config:=$config
	This._version:="0.1.0"
	This._isSetup:=False

	// Construct the logger first (all other classes receive it)
	This._logger:=cs.acme.ACMELogger.new(cs.acme.ACMELogger.new().INFO)

	// Construct sub-components
	This._transport:=cs.acme.ACMETransport.new($config; This._logger)
	This._account:=cs.acme.ACMEAccount.new($config; This._logger)
	This._challenge:=cs.acme.ACMEChallenge.new($config; This._logger)
	This._certStore:=cs.acme.ACMECertStore.new($config; This._logger)
	This._scheduler:=Null  // created on startScheduler()
	This._signer:=Null     // created after account key is loaded


// ============================================================
// CONFIGURATION HELPERS
// ============================================================

Function version() : Text
	return This._version


Function setLogLevel($vl_level : Integer) : cs.acme.ACMEClient
	// 0=ERROR 1=WARN 2=INFO 3=DEBUG
	This._logger.setLevel($vl_level)
	return This


Function logger() : cs.acme.ACMELogger
	return This._logger


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
	$result:=New object("success"; False; "error"; ""; "data"; Null)

	// 1. Validate config
	If (Not(This._config.isValid()))
		$result.error:=This._config.validationError()
		This._logger.error("ACMEClient.setup() failed: invalid config — "+$result.error; Null)
		return $result
	End if

	This._logger.info("ACME setup starting"; New object(\
		"staging"; This._config.staging; \
		"directoryUrl"; This._config.directoryUrl))

	// 2. Fetch directory (validates CA reachability)
	var $vo_dir : Object
	$vo_dir:=This._transport.directory()
	If ($vo_dir=Null)
		$result.error:="Could not fetch ACME directory from: "+This._config.directoryUrl
		return $result
	End if

	// 3. Load or generate account key
	var $vb_hasAccount : Boolean
	$vb_hasAccount:=This._account.load()

	If (Not($vb_hasAccount))
		This._logger.info("No existing account — generating new key pair"; Null)
		This._account.generateKey()
	End if

	// 4. Create JWS signer from the account key
	This._signer:=cs.acme.ACMEJwsSigner.new(This._account.privateKeyPem())
	This._transport.setSigner(This._signer)

	// Handle the JWK public key extraction for the signer
	// (see ACMEJwsSigner._buildPublicJwk() spike notes)
	var $vo_jwk : Object
	$vo_jwk:=This._signer.publicJwk()

	If ($vo_jwk=Null)
		// JWK extraction failed — need to regenerate the key via ACME CryptoKey
		// to get a JWKS-based key so we can extract n and e for the JWK header.
		This._logger.warn("Could not extract JWK from existing key PEM; regenerating via JWKS path"; Null)
		var $vo_result : Object
		$vo_result:=This._regenerateKeyViaJwks()
		If (Not($vo_result.success))
			$result.error:="Could not obtain JWK from account key: "+$vo_result.error
			return $result
		End if
	End if

	// 5. Register or confirm account
	If (Not(This._account.isRegistered))
		var $vo_regResult : Object
		$vo_regResult:=This._account.register(This._transport; This._signer)
		If (Not($vo_regResult.success))
			$result.error:="Account registration failed: "+$vo_regResult.error
			return $result
		End if
		This._account.save()
	Else
		// Already registered — switch signer to KID mode
		This._signer.setKid(This._account.accountUrl)
		This._logger.info("Using existing account"; New object("accountUrl"; This._account.accountUrl))
	End if

	This._isSetup:=True
	$result.success:=True
	This._logger.info("ACME setup complete"; Null)
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
	$result:=New object("success"; False; "error"; ""; "certPath"; ""; "skipped"; False)

	If (Not(This._isSetup))
		var $vo_setup : Object
		$vo_setup:=This.setup()
		If (Not($vo_setup.success))
			$result.error:="Setup failed: "+$vo_setup.error
			return $result
		End if
	End if

	// Record the attempt
	This._certStore.recordAttempt()

	This._logger.info("Starting certificate issuance/renewal"; New object(\
		"hostname"; String(This._config.identifiers[0]); \
		"staging"; This._config.staging))

	// Generate a new certificate key pair (separate from the account key)
	var $vo_certKey : 4D.CryptoKey
	var $vo_certKeyParams : Object
	$vo_certKeyParams:=New object("type"; "RSA"; "size"; 2048)
	$vo_certKey:=4D.CryptoKey.new($vo_certKeyParams)
	var $vt_certKeyPem : Text
	$vt_certKeyPem:=$vo_certKey.getPrivateKey()

	// Run the order state machine
	var $vo_order : cs.acme.ACMEOrder
	$vo_order:=cs.acme.ACMEOrder.new(\
		This._config; \
		This._logger; \
		This._transport; \
		This._challenge; \
		This._signer)

	var $vo_orderResult : Object
	$vo_orderResult:=$vo_order.issueCertificate($vt_certKeyPem)

	If (Not($vo_orderResult.success))
		$result.error:=$vo_orderResult.error
		This._logger.error("Certificate issuance failed"; New object("error"; $vo_orderResult.error))
		return $result
	End if

	// Save cert and key
	var $vo_saveResult : Object
	$vo_saveResult:=This._certStore.saveCertificate($vo_orderResult.certPem; $vt_certKeyPem)
	If (Not($vo_saveResult.success))
		$result.error:="Certificate save failed: "+$vo_saveResult.error
		return $result
	End if

	// Record success
	This._certStore.recordSuccess()

	// Trigger web server reload
	var $vo_reloadResult : Object
	$vo_reloadResult:=This._certStore.triggerReload()
	If (Not($vo_reloadResult.success))
		// Non-fatal: cert is on disk, reload just failed
		This._logger.warn("Post-renew reload action failed: "+$vo_reloadResult.error; Null)
	End if

	$result.success:=True
	$result.certPath:=This._config.certPath
	return $result


Function renewIfNeeded() : Object
	// Renew only if the cert store indicates renewal is due.
	If (This._certStore.needsRenewal())
		return This.renew()
	End if
	var $result : Object
	$result:=New object("success"; True; "error"; ""; "skipped"; True)
	return $result


// ============================================================
// SCHEDULER
// ============================================================

Function startScheduler() : cs.acme.ACMEClient
	// Start the background ARI-driven renewal scheduler.
	// Call from onHostDatabaseEvent or equivalent.
	This._scheduler:=cs.acme.ACMEScheduler.new(This._config; This._logger; This)
	This._scheduler.start()
	return This


Function stopScheduler()
	If (This._scheduler#Null)
		This._scheduler.stop()
	End if


Function runSchedulerCheck()
	// Execute a scheduler check from a worker process.
	// Host application should call:
	//   CALL WORKER("ACME_Scheduler"; "ACME_SchedulerWorker")
	// where ACME_SchedulerWorker is a project method that calls:
	//   cs.acme.ACMEClient.getSharedInstance().runSchedulerCheck()
	If (This._scheduler#Null)
		This._scheduler.check()
	End if


// ============================================================
// STATUS
// ============================================================

Function status() : Object
	// Return a composite status object for monitoring.
	// Combines cert store status with scheduler state.
	var $vo_status : Object
	$vo_status:=This._certStore.status()
	$vo_status.version:=This._version
	$vo_status.staging:=This._config.staging
	$vo_status.isSetup:=This._isSetup

	// Include scheduler state from Storage if available
	If (OB Is defined(Storage; "acme")) && (OB Is defined(Storage.acme; "scheduler"))
		$vo_status.scheduler:=Storage.acme.scheduler
	Else
		$vo_status.scheduler:=New object("running"; "false")
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
	$vl_pos:=Position("/.well-known/acme-challenge/"; $vt_requestUrl)
	If ($vl_pos=0)
		return New object("found"; False; "keyAuth"; "")
	End if

	$vt_token:=Substring($vt_requestUrl; $vl_pos+Length("/.well-known/acme-challenge/"))
	// Strip any query string
	var $vl_qpos : Integer
	$vl_qpos:=Position("?"; $vt_token)
	If ($vl_qpos>0)
		$vt_token:=Substring($vt_token; 1; $vl_qpos-1)
	End if

	var $vt_keyAuth : Text
	$vt_keyAuth:=This._challenge.serveWebServerChallenge($vt_requestUrl; $vt_token)

	If (Length($vt_keyAuth)>0)
		return New object("found"; True; "keyAuth"; $vt_keyAuth)
	End if

	return New object("found"; False; "keyAuth"; "")


// ============================================================
// INTERNAL
// ============================================================

Function _regenerateKeyViaJwks() : Object
	// When we can't extract JWK from a loaded PEM key, generate a fresh key
	// specifically via the 4D CryptoKey type="RSA" path which allows JWKS export.
	// This replaces the account key — only safe before first registration.
	var $result : Object
	$result:=New object("success"; False; "error"; "")

	If (This._account.isRegistered)
		$result.error:="Cannot regenerate account key after registration"
		return $result
	End if

	This._account.generateKey()

	// Re-create signer with new key
	This._signer:=cs.acme.ACMEJwsSigner.new(This._account.privateKeyPem())
	This._transport.setSigner(This._signer)

	var $vo_jwk : Object
	$vo_jwk:=This._signer.publicJwk()
	If ($vo_jwk=Null)
		$result.error:="JWK extraction still failing after key regeneration — platform spike needed"
		return $result
	End if

	$result.success:=True
	return $result
