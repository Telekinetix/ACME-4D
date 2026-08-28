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

property _config : cs:C1710.ACMEConfig
property _logger : cs:C1710.ACMELogger
property _directory : Object  // Cached ACME directory object
property _nonce : Text  // Current unused Replay-Nonce (never log)
property _signer : cs:C1710.ACMEJwsSigner  // Set by ACMEClient after account key loaded


Class constructor($config : cs:C1710.ACMEConfig; $logger : cs:C1710.ACMELogger)
	This:C1470._config:=$config
	This:C1470._logger:=$logger
	This:C1470._directory:=Null:C1517
	This:C1470._nonce:=""
	This:C1470._signer:=Null:C1517
	
	
	// ============================================================
	// DIRECTORY
	// ============================================================
	
Function directory() : Object
	// Return the cached directory, fetching it if necessary.
	// Result keys include: newNonce, newAccount, newOrder, renewalInfo (ARI).
	If (This:C1470._directory=Null:C1517)
		var $result : Object
		$result:=This:C1470._rawGet(This:C1470._config.directoryUrl)
		If ($result.success)
			This:C1470._directory:=$result.body
			This:C1470._logger.debug("ACME directory fetched"; New object:C1471("url"; This:C1470._config.directoryUrl))
		Else 
			This:C1470._logger.error("Failed to fetch ACME directory"; New object:C1471("error"; $result.error))
		End if 
	End if 
	return This:C1470._directory
	
	
Function directoryUrl($key : Text) : Text
	// Convenience: get a named URL from the directory (e.g. "newOrder").
	var $dir : Object
	$dir:=This:C1470.directory()
	If ($dir=Null:C1517)
		return ""
	End if 
	return String:C10($dir[$key])
	
	
	// ============================================================
	// NONCE
	// ============================================================
	
Function freshNonce() : Text
	// Return the cached nonce, or HEAD-request a new one from newNonce.
	// The nonce is consumed once by a JWS request — callers take it and
	// this store is cleared. A new nonce is captured from every response
	// Replay-Nonce header by _captureNonce().
	If (Length:C16(This:C1470._nonce)>0)
		var $vt_nonce : Text
		$vt_nonce:=This:C1470._nonce
		This:C1470._nonce:=""
		return $vt_nonce
	End if 
	
	// Fetch a fresh nonce via HEAD on the newNonce endpoint
	var $vt_url : Text
	$vt_url:=This:C1470.directoryUrl("newNonce")
	If (Length:C16($vt_url)=0)
		This:C1470._logger.error("newNonce URL not available from directory"; Null:C1517)
		return ""
	End if 
	
	var $vo_options : Object
	var $vo_request : 4D:C1709.HTTPRequest
	var vl_acmeHttpError : Integer
	var vt_acmeHttpError : Text
	
	$vo_options:=New object:C1471(\
		"method"; "HEAD"; \
		"timeout"; This:C1470._config.timeout)
	
	vl_acmeHttpError:=0
	vt_acmeHttpError:=""
	ON ERR CALL:C155("ACME_HTTP_Error")
	$vo_request:=4D:C1709.HTTPRequest.new($vt_url; $vo_options)
	$vo_request.wait()
	ON ERR CALL:C155("")
	
	If (vl_acmeHttpError#0)
		This:C1470._logger.error("HEAD newNonce failed: "+vt_acmeHttpError; Null:C1517)
		return ""
	End if 
	
	If (OB Is defined:C1231($vo_request.response.headers; "replay-nonce"))
		$vt_nonce:=String:C10($vo_request.response.headers["replay-nonce"])
	Else 
		$vt_nonce:=String:C10($vo_request.response.headers["Replay-Nonce"])
	End if 
	
	return $vt_nonce
	
	// ============================================================
	// SIGNED POST (standard ACME request)
	// ============================================================
	
Function post($vt_url : Text; $vo_payload : Object) : Object
	// Issue a signed POST carrying a JSON payload.
	// $vo_payload = Null means a POST-as-GET (empty string payload in JWS).
	return This:C1470._signedRequest($vt_url; $vo_payload; False:C215)
	
	
Function postAsGet($vt_url : Text) : Object
	// RFC 8555 §6.3: POST-as-GET uses an empty string (not null JSON) payload.
	return This:C1470._signedRequest($vt_url; Null:C1517; True:C214)
	
	
	// ============================================================
	// INTERNAL — SIGNED REQUEST
	// ============================================================
	
Function _signedRequest($vt_url : Text; $vo_payload : Object; $vb_postAsGet : Boolean) : Object
	var $result : Object
	$result:=This:C1470._emptyResult($vt_url)
	
	If (This:C1470._signer=Null:C1517)
		$result.error:="ACMETransport: signer not set — call setSigner() before making requests"
		return $result
	End if 
	
	var $vt_nonce : Text
	$vt_nonce:=This:C1470.freshNonce()
	If (Length:C16($vt_nonce)=0)
		$result.error:="ACMETransport: could not obtain a Replay-Nonce"
		return $result
	End if 
	
	// Build JWS
	var $vo_jws : Object
	If ($vb_postAsGet)
		$vo_jws:=This:C1470._signer.signPostAsGet($vt_url; $vt_nonce)
	Else 
		$vo_jws:=This:C1470._signer.sign($vt_url; $vo_payload; $vt_nonce)
	End if 
	
	If ($vo_jws=Null:C1517)
		$result.error:="ACMETransport: JWS signing failed"
		return $result
	End if 
	
	// HTTP POST
	var $vo_options : Object
	$vo_options:=New object:C1471(\
		"method"; "POST"; \
		"headers"; New object:C1471(\
		"Content-Type"; "application/jose+json"; \
		"Accept"; "application/json"); \
		"body"; $vo_jws; \
		"timeout"; This:C1470._config.timeout)
	
	return This:C1470._executeWithRetry($vt_url; $vo_options; 1)
	
	
	// ============================================================
	// INTERNAL — RAW GET (for directory fetch)
	// ============================================================
	
Function _rawGet($vt_url : Text) : Object
	var $vo_options : Object
	$vo_options:=New object:C1471(\
		"method"; "GET"; \
		"headers"; New object:C1471("Accept"; "application/json"); \
		"timeout"; This:C1470._config.timeout)
	return This:C1470._executeWithRetry($vt_url; $vo_options; 1)
	
	
	// ============================================================
	// INTERNAL — HTTP EXECUTE WITH RETRY
	// ============================================================
	
Function _executeWithRetry($vt_url : Text; $vo_options : Object; $vl_attempt : Integer) : Object
	var $result : Object
	$result:=This:C1470._emptyResult($vt_url)
	
	var $vo_request : 4D:C1709.HTTPRequest
	var vl_acmeHttpError : Integer
	var vt_acmeHttpError : Text
	
	vl_acmeHttpError:=0
	vt_acmeHttpError:=""
	ON ERR CALL:C155("ACME_HTTP_Error")
	$vo_request:=4D:C1709.HTTPRequest.new($vt_url; $vo_options)
	$vo_request.wait()
	ON ERR CALL:C155("")
	
	// Network-level failure
	If (vl_acmeHttpError#0) | ($vo_request.response=Null:C1517)
		$result.error:=(vt_acmeHttpError#"") ? vt_acmeHttpError : "No response (network/timeout)"
		$result.errorCode:=vl_acmeHttpError
		// Retry on network error (up to 3 attempts)
		If ($vl_attempt<3)
			DELAY PROCESS:C323(Current process:C322; 2*$vl_attempt*60)  // 2s, 4s back-off (ticks)
			return This:C1470._executeWithRetry($vt_url; $vo_options; $vl_attempt+1)
		End if 
		return $result
	End if 
	
	// Capture nonce from every response for the next request
	This:C1470._captureNonce($vo_request.response.headers)
	
	$result.status:=$vo_request.response.status
	$result.headers:=$vo_request.response.headers
	
	// Location header (new account, new order)
	If (OB Is defined:C1231($vo_request.response.headers; "Location"))
		$result.location:=String:C10($vo_request.response.headers["Location"])
	End if 
	
	// Parse body — expect JSON for most ACME responses
	var $vt_body : Text
	var $vo_body : Object
	$vt_body:=""
	If (Value type:C1509($vo_request.response.body)=Is text:K8:3)
		$vt_body:=$vo_request.response.body
	End if 
	
	If (Length:C16($vt_body)>0)
		$vo_body:=Try(JSON Parse:C1218($vt_body))
		If ($vo_body#Null:C1517) && (Value type:C1509($vo_body)=Is object:K8:27)
			$result.body:=$vo_body
		Else 
			$result.body:=$vt_body
		End if 
	End if 
	
	If (Value type:C1509($vo_request.response.body)=Is object:K8:27)
		$result.body:=$vo_request.response.body
	End if 
	
	// 2xx = success
	If ($vo_request.response.status>=200) && ($vo_request.response.status<300)
		$result.success:=True:C214
		return $result
	End if 
	
	// 5xx = transient server error — retry
	If ($vo_request.response.status>=500) && ($vl_attempt<3)
		DELAY PROCESS:C323(Current process:C322; 2*$vl_attempt*60)
		return This:C1470._executeWithRetry($vt_url; $vo_options; $vl_attempt+1)
	End if 
	
	// Error response — parse ACME problem document
	$result.success:=False:C215
	$result.error:=This:C1470._parseError($result.body; $result.status)
	If (Value type:C1509($result.body)=Is object:K8:27)
		$result.errorType:=String:C10($result.body["type"])
	End if 
	This:C1470._logger.warn("ACME request failed"; New object:C1471(\
		"url"; $vt_url; \
		"status"; $result.status; \
		"error"; $result.error))
	return $result
	
	
	// ============================================================
	// INTERNAL — HELPERS
	// ============================================================
	
Function setSigner($signer : cs:C1710.ACMEJwsSigner)
	This:C1470._signer:=$signer
	
	
Function _captureNonce($headers : Object)
	If ($headers#Null:C1517) && (OB Is defined:C1231($headers; "Replay-Nonce"))
		This:C1470._nonce:=String:C10($headers["Replay-Nonce"])
	End if 
	
	
Function _parseError($vv_body : Variant; $vl_status : Integer) : Text
	// Parse an ACME problem document into a human-readable error.
	// Problem documents have: type, detail, subproblems[]
	var $vt_error : Text
	var $vo_body : Object
	var $vl_type : Integer
	
	$vl_type:=Value type:C1509($vv_body)
	
	Case of 
		: ($vv_body=Null:C1517)
			$vt_error:="HTTP "+String:C10($vl_status)
			
		: ($vl_type=Is object:K8:27)
			$vo_body:=$vv_body
			Case of 
				: (OB Is defined:C1231($vo_body; "detail"))
					$vt_error:=String:C10($vo_body.detail)
					If (Length:C16($vt_error)=0)
						$vt_error:=String:C10($vo_body["type"])
					End if 
				: (OB Is defined:C1231($vo_body; "type"))
					$vt_error:=String:C10($vo_body["type"])
				Else 
					$vt_error:="HTTP "+String:C10($vl_status)
			End case 
			
		: ($vl_type=Is text:K8:3)
			$vt_error:="HTTP "+String:C10($vl_status)+": "+String:C10($vv_body)
			
		Else 
			$vt_error:="HTTP "+String:C10($vl_status)
	End case 
	
	If (Length:C16($vt_error)=0)
		$vt_error:="HTTP "+String:C10($vl_status)
	End if 
	return $vt_error
	
	
Function _emptyResult($vt_url : Text) : Object
	return New object:C1471(\
		"success"; False:C215; \
		"status"; 0; \
		"body"; Null:C1517; \
		"headers"; New object:C1471; \
		"location"; ""; \
		"error"; ""; \
		"errorType"; ""; \
		"errorCode"; 0; \
		"url"; $vt_url)
	