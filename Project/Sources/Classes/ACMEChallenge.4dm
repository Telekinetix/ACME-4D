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

property _config : cs.acme.ACMEConfig
property _logger : cs.acme.ACMELogger
property _activeToken : Text    // Currently published token (not logged)
property _activeKeyAuth : Text  // Currently active keyAuthorization (not logged)


Class constructor($config : cs.acme.ACMEConfig; $logger : cs.acme.ACMELogger)
	This._config:=$config
	This._logger:=$logger
	This._activeToken:=""
	This._activeKeyAuth:=""


// ============================================================
// PUBLISH
// ============================================================

Function publish($vt_token : Text; $vt_keyAuth : Text) : Object
	// Publish the keyAuthorization for the given token.
	// Returns { success: Boolean; error: Text }
	// SECURITY: $vt_token and $vt_keyAuth are NEVER logged.
	This._activeToken:=$vt_token
	This._activeKeyAuth:=$vt_keyAuth

	var $result : Object
	$result:=New object("success"; False; "error"; "")

	Case of
		: (This._config.challengeStrategy="webserver")
			$result:=This._publishViaWebServer($vt_token; $vt_keyAuth)

		: (This._config.challengeStrategy="webroot")
			$result:=This._publishViaWebroot($vt_token; $vt_keyAuth)

		: (This._config.challengeStrategy="listener")
			$result.error:="listener strategy is not implemented in MVP; use webserver or webroot"

		Else
			$result.error:="Unknown challenge strategy: "+This._config.challengeStrategy
	End case

	If ($result.success)
		This._logger.info("HTTP-01 challenge published"; New object("strategy"; This._config.challengeStrategy))
	Else
		This._logger.error("HTTP-01 challenge publish failed"; New object("strategy"; This._config.challengeStrategy; "error"; $result.error))
	End if

	return $result


// ============================================================
// UNPUBLISH (CLEANUP)
// ============================================================

Function unpublish($vt_token : Text)
	// Remove the published token after the challenge has been validated (or failed).
	Case of
		: (This._config.challengeStrategy="webserver")
			This._unpublishViaWebServer($vt_token)

		: (This._config.challengeStrategy="webroot")
			This._unpublishViaWebroot($vt_token)
	End case

	This._activeToken:=""
	This._activeKeyAuth:=""
	This._logger.info("HTTP-01 challenge unpublished"; Null)


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
	$result:=New object("success"; True; "error"; "")

	If (Not(OB Is defined(Storage; "acme")))
		Use (Storage)
			Storage.acme:=New shared object
		End use
	End if

	If (Not(OB Is defined(Storage.acme; "challenges")))
		Use (Storage.acme)
			Storage.acme.challenges:=New shared object
		End use
	End if

	Use (Storage.acme.challenges)
		Storage.acme.challenges[$vt_token]:=$vt_keyAuth
	End use

	return $result


Function _unpublishViaWebServer($vt_token : Text)
	If (OB Is defined(Storage; "acme")) && (OB Is defined(Storage.acme; "challenges"))
		Use (Storage.acme.challenges)
			OB REMOVE(Storage.acme.challenges; $vt_token)
		End use
	End if


// ============================================================
// INTERNAL — WEBROOT STRATEGY
// ============================================================

Function _publishViaWebroot($vt_token : Text; $vt_keyAuth : Text) : Object
	var $result : Object
	$result:=New object("success"; False; "error"; "")

	If (Length(This._config.webrootPath)=0)
		$result.error:="webrootPath not set in config"
		return $result
	End if

	// Ensure the .well-known/acme-challenge directory exists
	var $vt_challengeDir : Text
	$vt_challengeDir:=This._config.webrootPath+".well-known"+Folder separator+"acme-challenge"+Folder separator

	var $vf_dir : 4D.Folder
	$vf_dir:=Folder($vt_challengeDir)
	If (Not($vf_dir.exists))
		Try
			$vf_dir.create()
		Catch
			$result.error:="Failed to create challenge directory: "+$vt_challengeDir
			return $result
		End try
	End if

	// Write the keyAuthorization as plain text (token filename, no extension)
	var $vf_token : 4D.File
	$vf_token:=File($vt_challengeDir+$vt_token)
	Try
		$vf_token.setText($vt_keyAuth; "utf-8")
	Catch
		$result.error:="Failed to write challenge token file"
		return $result
	End try

	$result.success:=True
	return $result


Function _unpublishViaWebroot($vt_token : Text)
	If (Length(This._config.webrootPath)=0)
		return
	End if

	var $vt_challengeDir : Text
	$vt_challengeDir:=This._config.webrootPath+".well-known"+Folder separator+"acme-challenge"+Folder separator

	var $vf_token : 4D.File
	$vf_token:=File($vt_challengeDir+$vt_token)
	If ($vf_token.exists)
		Try
			$vf_token.delete()
		Catch
			// Best-effort cleanup; log but don't fail
			This._logger.warn("Could not delete challenge token file"; Null)
		End try
	End if


// ============================================================
// WEB SERVER HANDLER (called by the host URL handler)
// ============================================================

Function serveWebServerChallenge($vt_url : Text; $vt_token : Text) : Text
	// Look up and return the keyAuthorization for the given token.
	// Returns "" if not found (404 should be sent by the caller).
	// The host's URL handler should call this and return the result as text/plain.
	If (OB Is defined(Storage; "acme")) && (OB Is defined(Storage.acme; "challenges"))
		var $vt_keyAuth : Text
		$vt_keyAuth:=String(Storage.acme.challenges[$vt_token])
		return $vt_keyAuth
	End if
	return ""
