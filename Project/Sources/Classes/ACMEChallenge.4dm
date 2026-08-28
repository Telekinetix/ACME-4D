// ----------------------------------------------------
// Class: ACMEChallenge
// HTTP-01 challenge publisher for the ACME component.
//
// HTTP-01 challenge flow (RFC 8555 §8.3):
//   1. The CA provides a token string per authorization.
//   2. We compute: keyAuthorization = token + "." + jwkThumbprint(accountKey)
//   3. We publish keyAuthorization at:
//        http://<host>/.well-known/acme-challenge/<token>
//      as Content-Type: text/plain on port 80.
//   4. We tell the CA to validate (POST challenge URL with empty payload {}).
//   5. We poll the authorization until "valid" or "invalid".
//   6. We clean up the published token.
//
// Three publish strategies (set via ACMEConfig.challengeStrategy):
//
//   "webserver" — registers a URL path handler with the 4D web server.
//     Only works when the 4D server is reachable on port 80 for the domain.
//     Uses OnWebConnection or HTTP handlers depending on 4D version.
//     The token response is stored in Storage while the challenge is active.
//
//   "webroot"   — writes the token to a file under ACMEConfig.webrootPath.
//     Requires a separate web server (nginx, Apache…) already serving that
//     directory on port 80. The path used is:
//       <webrootPath>/.well-known/acme-challenge/<token>
//
//   "listener"  — starts a minimal temporary HTTP server on port 80 to answer
//     exactly the one challenge, then shuts it down.
//     NOTE: Binding port 80 may require elevated privileges on the OS.
//     This strategy is a placeholder; the implementation requires
//     TCP socket APIs not available in v20.0 without a plugin.
//     *** MARKED AS FUTURE — not implemented in MVP. ***
//
// The token and keyAuthorization values are never written to logs.
// ----------------------------------------------------

property _config : cs:C1710.ACMEConfig
property _logger : cs:C1710.ACMELogger
property _activeToken : Text  // Currently published token (not logged)
property _activeKeyAuth : Text  // Currently active keyAuthorization (not logged)


Class constructor($config : cs:C1710.ACMEConfig; $logger : cs:C1710.ACMELogger)
	This:C1470._config:=$config
	This:C1470._logger:=$logger
	This:C1470._activeToken:=""
	This:C1470._activeKeyAuth:=""
	
	
	// ============================================================
	// PUBLISH
	// ============================================================
	
Function publish($vt_token : Text; $vt_keyAuth : Text) : Object
	// Publish the keyAuthorization for the given token.
	// Returns { success: Boolean; error: Text }
	// SECURITY: $vt_token and $vt_keyAuth are NEVER logged.
	This:C1470._activeToken:=$vt_token
	This:C1470._activeKeyAuth:=$vt_keyAuth
	
	var $result : Object
	$result:=New object:C1471("success"; False:C215; "error"; "")
	
	Case of 
		: (This:C1470._config.challengeStrategy="webserver")
			$result:=This:C1470._publishViaWebServer($vt_token; $vt_keyAuth)
			
		: (This:C1470._config.challengeStrategy="webroot")
			$result:=This:C1470._publishViaWebroot($vt_token; $vt_keyAuth)
			
		: (This:C1470._config.challengeStrategy="listener")
			$result.error:="listener strategy is not implemented in MVP; use webserver or webroot"
			
		Else 
			$result.error:="Unknown challenge strategy: "+This:C1470._config.challengeStrategy
	End case 
	
	If ($result.success)
		This:C1470._logger.info("HTTP-01 challenge published"; New object:C1471("strategy"; This:C1470._config.challengeStrategy))
	Else 
		This:C1470._logger.error("HTTP-01 challenge publish failed"; New object:C1471("strategy"; This:C1470._config.challengeStrategy; "error"; $result.error))
	End if 
	
	return $result
	
	
	// ============================================================
	// UNPUBLISH (CLEANUP)
	// ============================================================
	
Function unpublish($vt_token : Text)
	// Remove the published token after the challenge has been validated (or failed).
	Case of 
		: (This:C1470._config.challengeStrategy="webserver")
			This:C1470._unpublishViaWebServer($vt_token)
			
		: (This:C1470._config.challengeStrategy="webroot")
			This:C1470._unpublishViaWebroot($vt_token)
	End case 
	
	This:C1470._activeToken:=""
	This:C1470._activeKeyAuth:=""
	This:C1470._logger.info("HTTP-01 challenge unpublished"; Null:C1517)
	
	
	// ============================================================
	// INTERNAL — WEBSERVER STRATEGY
	// ============================================================
	
Function _publishViaWebServer($vt_token : Text; $vt_keyAuth : Text) : Object
	// Store the keyAuthorization in a shared Storage entry so the host
	// web server's URL handler can serve it.
	//
	// The host application must register a handler for:
	//   /.well-known/acme-challenge/*
	// that calls ACMEChallenge.serveWebServerChallenge() — or alternatively
	// configure the 4D web server to call the ACME_Challenge_Handler method.
	//
	// This component provides ACME_Challenge_Handler as a project method that
	// the host can assign to the URL handler.
	var $result : Object
	$result:=New object:C1471("success"; True:C214; "error"; "")
	
	If (Not:C34(OB Is defined:C1231(Storage:C1525; "acme")))
		Use (Storage:C1525)
			Storage:C1525.acme:=New shared object:C1526
		End use 
	End if 
	
	If (Not:C34(OB Is defined:C1231(Storage:C1525.acme; "challenges")))
		Use (Storage:C1525.acme)
			Storage:C1525.acme.challenges:=New shared object:C1526
		End use 
	End if 
	
	Use (Storage:C1525.acme.challenges)
		Storage:C1525.acme.challenges[$vt_token]:=$vt_keyAuth
	End use 
	
	return $result
	
	
Function _unpublishViaWebServer($vt_token : Text)
	If (OB Is defined:C1231(Storage:C1525; "acme")) && (OB Is defined:C1231(Storage:C1525.acme; "challenges"))
		Use (Storage:C1525.acme.challenges)
			OB REMOVE:C1226(Storage:C1525.acme.challenges; $vt_token)
		End use 
	End if 
	
	
	// ============================================================
	// INTERNAL — WEBROOT STRATEGY
	// ============================================================
	
Function _publishViaWebroot($vt_token : Text; $vt_keyAuth : Text) : Object
	var $result : Object
	$result:=New object:C1471("success"; False:C215; "error"; "")
	
	If (Length:C16(This:C1470._config.webrootPath)=0)
		$result.error:="webrootPath not set in config"
		return $result
	End if 
	
	// Ensure the .well-known/acme-challenge directory exists
	var $vt_challengeDir : Text
	$vt_challengeDir:=This:C1470._config.webrootPath+".well-known"+Folder separator:K24:12+"acme-challenge"+Folder separator:K24:12
	
	var $vf_dir : 4D:C1709.Folder
	$vf_dir:=Folder:C1567($vt_challengeDir; fk platform path:K87:2)
	If (Not:C34($vf_dir.exists))
		Try
			$vf_dir.create()
		Catch
			$result.error:="Failed to create challenge directory: "+$vt_challengeDir
			return $result
		End try
	End if 
	
	// Write the keyAuthorization as plain text (token filename, no extension)
	var $vf_token : 4D:C1709.File
	$vf_token:=File:C1566($vt_challengeDir+$vt_token; fk platform path:K87:2)
	Try
		$vf_token.setText($vt_keyAuth; "utf-8")
	Catch
		$result.error:="Failed to write challenge token file"
		return $result
	End try
	
	$result.success:=True:C214
	return $result
	
	
Function _unpublishViaWebroot($vt_token : Text)
	If (Length:C16(This:C1470._config.webrootPath)=0)
		return 
	End if 
	
	var $vt_challengeDir : Text
	$vt_challengeDir:=This:C1470._config.webrootPath+".well-known"+Folder separator:K24:12+"acme-challenge"+Folder separator:K24:12
	
	var $vf_token : 4D:C1709.File
	$vf_token:=File:C1566($vt_challengeDir+$vt_token; fk platform path:K87:2)
	If ($vf_token.exists)
		Try
			$vf_token.delete()
		Catch
			// Best-effort cleanup; log but don't fail
			This:C1470._logger.warn("Could not delete challenge token file"; Null:C1517)
		End try
	End if 
	
	
	// ============================================================
	// WEB SERVER HANDLER (called by the host URL handler)
	// ============================================================
	
Function serveWebServerChallenge($vt_url : Text; $vt_token : Text) : Text
	// Look up and return the keyAuthorization for the given token.
	// Returns "" if not found (404 should be sent by the caller).
	// The host's URL handler should call this and return the result as text/plain.
	If (OB Is defined:C1231(Storage:C1525; "acme")) && (OB Is defined:C1231(Storage:C1525.acme; "challenges"))
		var $vt_keyAuth : Text
		$vt_keyAuth:=String:C10(Storage:C1525.acme.challenges[$vt_token])
		return $vt_keyAuth
	End if 
	return ""
	