// ----------------------------------------------------
// Class: ACMETransport
// HTTP transport layer for ACMEv2 (RFC 8555).
//
// Responsibilities:
//   • Fetch and cache the ACME directory (endpoint URL discovery).
//   • Maintain a fresh Replay-Nonce, refetching automatically.
//   • Issue signed POST requests (JWS) and POST-as-GET requests.
//   • Parse ACME problem documents (application/problem+json).
//   • Retry on transient server errors (5xx) with exponential back-off.
//   • Capture the Location header (for new account / new order responses).
//   • Never log secrets — tokens and key material are not passed through here.
//
// Standard result object returned by all public methods:
//   { success: Boolean; status: Integer; body: Variant (Object|Text|Null);
//     headers: Object; location: Text; error: Text; errorType: Text }
//
// Platform baseline: 4D v20.0 — uses 4D.HTTPRequest (confirmed in v18 R6+,
// present in all v20.x). Falls back to HTTP Request command if needed but
// the class form is strongly preferred for header access.
// ----------------------------------------------------

property _config : cs.acme.ACMEConfig
property _logger : cs.acme.ACMELogger
property _directory : Object   // Cached ACME directory object
property _nonce : Text         // Current unused Replay-Nonce (never log)
property _signer : cs.acme.ACMEJwsSigner  // Set by ACMEClient after account key loaded


Class constructor($config : cs.acme.ACMEConfig; $logger : cs.acme.ACMELogger)
	This._config:=$config
	This._logger:=$logger
	This._directory:=Null
	This._nonce:=""
	This._signer:=Null


// ============================================================
// DIRECTORY
// ============================================================

Function directory() : Object
	// Return the cached directory, fetching it if necessary.
	// Result keys include: newNonce, newAccount, newOrder, renewalInfo (ARI).
	If (This._directory=Null)
		var $result : Object
		$result:=This._rawGet(This._config.directoryUrl)
		If ($result.success)
			This._directory:=$result.body
			This._logger.debug("ACME directory fetched"; New object("url"; This._config.directoryUrl))
		Else
			This._logger.error("Failed to fetch ACME directory"; New object("error"; $result.error))
		End if
	End if
	return This._directory


Function directoryUrl($key : Text) : Text
	// Convenience: get a named URL from the directory (e.g. "newOrder").
	var $dir : Object
	$dir:=This.directory()
	If ($dir=Null)
		return ""
	End if
	return String($dir[$key])


// ============================================================
// NONCE
// ============================================================

Function freshNonce() : Text
	// Return the cached nonce, or HEAD-request a new one from newNonce.
	// The nonce is consumed once by a JWS request — callers take it and
	// this store is cleared. A new nonce is captured from every response
	// Replay-Nonce header by _captureNonce().
	If (Length(This._nonce)>0)
		var $vt_nonce : Text
		$vt_nonce:=This._nonce
		This._nonce:=""
		return $vt_nonce
	End if

	// Fetch a fresh nonce via HEAD on the newNonce endpoint
	var $vt_url : Text
	$vt_url:=This.directoryUrl("newNonce")
	If (Length($vt_url)=0)
		This._logger.error("newNonce URL not available from directory"; Null)
		return ""
	End if

	var $vo_options : Object
	var $vo_request : 4D.HTTPRequest
	var vl_acmeHttpError : Integer
	var vt_acmeHttpError : Text

	$vo_options:=New object(\
		"method"; "HEAD"; \
		"timeout"; This._config.timeout)

	vl_acmeHttpError:=0
	vt_acmeHttpError:=""
	ON ERR CALL("ACME_HTTP_Error")
	$vo_request:=4D.HTTPRequest.new($vt_url; $vo_options)
	$vo_request.wait()
	ON ERR CALL("")

	If (vl_acmeHttpError#0)
		This._logger.error("HEAD newNonce failed: "+vt_acmeHttpError; Null)
		return ""
	End if

	var $vt_nonce : Text
	$vt_nonce:=String($vo_request.response.headers["Replay-Nonce"])
	return $vt_nonce


// ============================================================
// SIGNED POST (standard ACME request)
// ============================================================

Function post($vt_url : Text; $vo_payload : Object) : Object
	// Issue a signed POST carrying a JSON payload.
	// $vo_payload = Null means a POST-as-GET (empty string payload in JWS).
	return This._signedRequest($vt_url; $vo_payload; False)


Function postAsGet($vt_url : Text) : Object
	// RFC 8555 §6.3: POST-as-GET uses an empty string (not null JSON) payload.
	return This._signedRequest($vt_url; Null; True)


// ============================================================
// INTERNAL — SIGNED REQUEST
// ============================================================

Function _signedRequest($vt_url : Text; $vo_payload : Object; $vb_postAsGet : Boolean) : Object
	var $result : Object
	$result:=This._emptyResult($vt_url)

	If (This._signer=Null)
		$result.error:="ACMETransport: signer not set — call setSigner() before making requests"
		return $result
	End if

	var $vt_nonce : Text
	$vt_nonce:=This.freshNonce()
	If (Length($vt_nonce)=0)
		$result.error:="ACMETransport: could not obtain a Replay-Nonce"
		return $result
	End if

	// Build JWS
	var $vo_jws : Object
	If ($vb_postAsGet)
		$vo_jws:=This._signer.signPostAsGet($vt_url; $vt_nonce)
	Else
		$vo_jws:=This._signer.sign($vt_url; $vo_payload; $vt_nonce)
	End if

	If ($vo_jws=Null)
		$result.error:="ACMETransport: JWS signing failed"
		return $result
	End if

	// HTTP POST
	var $vo_options : Object
	$vo_options:=New object(\
		"method"; "POST"; \
		"headers"; New object(\
			"Content-Type"; "application/jose+json"; \
			"Accept"; "application/json"); \
		"body"; $vo_jws; \
		"timeout"; This._config.timeout)

	return This._executeWithRetry($vt_url; $vo_options; 1)


// ============================================================
// INTERNAL — RAW GET (for directory fetch)
// ============================================================

Function _rawGet($vt_url : Text) : Object
	var $vo_options : Object
	$vo_options:=New object(\
		"method"; "GET"; \
		"headers"; New object("Accept"; "application/json"); \
		"timeout"; This._config.timeout)
	return This._executeWithRetry($vt_url; $vo_options; 1)


// ============================================================
// INTERNAL — HTTP EXECUTE WITH RETRY
// ============================================================

Function _executeWithRetry($vt_url : Text; $vo_options : Object; $vl_attempt : Integer) : Object
	var $result : Object
	$result:=This._emptyResult($vt_url)

	var $vo_request : 4D.HTTPRequest
	var vl_acmeHttpError : Integer
	var vt_acmeHttpError : Text

	vl_acmeHttpError:=0
	vt_acmeHttpError:=""
	ON ERR CALL("ACME_HTTP_Error")
	$vo_request:=4D.HTTPRequest.new($vt_url; $vo_options)
	$vo_request.wait()
	ON ERR CALL("")

	// Network-level failure
	If (vl_acmeHttpError#0) | ($vo_request.response=Null)
		$result.error:=(vt_acmeHttpError#"") ? vt_acmeHttpError : "No response (network/timeout)"
		$result.errorCode:=vl_acmeHttpError
		// Retry on network error (up to 3 attempts)
		If ($vl_attempt<3)
			DELAY PROCESS(Current process; 2*$vl_attempt*60)  // 2s, 4s back-off (ticks)
			return This._executeWithRetry($vt_url; $vo_options; $vl_attempt+1)
		End if
		return $result
	End if

	// Capture nonce from every response for the next request
	This._captureNonce($vo_request.response.headers)

	$result.status:=$vo_request.response.status
	$result.headers:=$vo_request.response.headers

	// Location header (new account, new order)
	If (OB Is defined($vo_request.response.headers; "Location"))
		$result.location:=String($vo_request.response.headers["Location"])
	End if

	// Parse body — expect JSON for most ACME responses
	var $vt_body : Text
	var $vo_body : Object
	$vt_body:=""
	If (Value type($vo_request.response.body)=Is text)
		$vt_body:=$vo_request.response.body
	End if

	If (Length($vt_body)>0)
		$vo_body:=Try(JSON Parse($vt_body))
		If ($vo_body#Null) && (Value type($vo_body)=Is object)
			$result.body:=$vo_body
		Else
			$result.body:=$vt_body
		End if
	End if

	// 2xx = success
	If ($vo_request.response.status>=200) && ($vo_request.response.status<300)
		$result.success:=True
		return $result
	End if

	// 5xx = transient server error — retry
	If ($vo_request.response.status>=500) && ($vl_attempt<3)
		DELAY PROCESS(Current process; 2*$vl_attempt*60)
		return This._executeWithRetry($vt_url; $vo_options; $vl_attempt+1)
	End if

	// Error response — parse ACME problem document
	$result.success:=False
	$result.error:=This._parseError($result.body; $result.status)
	If (Value type($result.body)=Is object)
		$result.errorType:=String($result.body["type"])
	End if
	This._logger.warn("ACME request failed"; New object(\
		"url"; $vt_url; \
		"status"; $result.status; \
		"error"; $result.error))
	return $result


// ============================================================
// INTERNAL — HELPERS
// ============================================================

Function setSigner($signer : cs.acme.ACMEJwsSigner)
	This._signer:=$signer


Function _captureNonce($headers : Object)
	If ($headers#Null) && (OB Is defined($headers; "Replay-Nonce"))
		This._nonce:=String($headers["Replay-Nonce"])
	End if


Function _parseError($vv_body : Variant; $vl_status : Integer) : Text
	// Parse an ACME problem document into a human-readable error.
	// Problem documents have: type, detail, subproblems[]
	var $vt_error : Text
	var $vo_body : Object
	var $vl_type : Integer

	$vl_type:=Value type($vv_body)

	Case of
		: ($vv_body=Null)
			$vt_error:="HTTP "+String($vl_status)

		: ($vl_type=Is object)
			$vo_body:=$vv_body
			Case of
				: (OB Is defined($vo_body; "detail"))
					$vt_error:=String($vo_body.detail)
					If (Length($vt_error)=0)
						$vt_error:=String($vo_body["type"])
					End if
				: (OB Is defined($vo_body; "type"))
					$vt_error:=String($vo_body["type"])
				Else
					$vt_error:="HTTP "+String($vl_status)
			End case

		: ($vl_type=Is text)
			$vt_error:="HTTP "+String($vl_status)+": "+String($vv_body)

		Else
			$vt_error:="HTTP "+String($vl_status)
	End case

	If (Length($vt_error)=0)
		$vt_error:="HTTP "+String($vl_status)
	End if
	return $vt_error


Function _emptyResult($vt_url : Text) : Object
	return New object(\
		"success"; False; \
		"status"; 0; \
		"body"; Null; \
		"headers"; New object; \
		"location"; ""; \
		"error"; ""; \
		"errorType"; ""; \
		"errorCode"; 0; \
		"url"; $vt_url)
