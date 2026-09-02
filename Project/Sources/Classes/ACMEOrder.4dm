// ----------------------------------------------------
// Class: ACMEOrder
// Order state machine for the ACMEv2 protocol (RFC 8555 §7.3–7.5).
//
// Drives the full certificate issuance flow for one order:
//   1. POST newOrder          → order URL + authorizations + finalize URL
//   2. For each authorization → fetch, find http-01 challenge, publish, notify CA
//   3. Poll authorization     → wait for "valid"
//   4. POST finalize          → submit CSR
//   5. Poll order             → wait for "valid"
//   6. GET certificate        → download PEM chain
//
// State persistence:
//   Order state is saved to <storePath>/order-<hostname>.json after each step
//   so that a crash mid-flight can be resumed from the last known-good state.
//   On startup, ACMEClient checks for a stale pending order and resumes it.
//
// Result object returned by issueCertificate():
//   { success: Boolean; certPem: Text; error: Text; orderUrl: Text }
// ----------------------------------------------------

property _config : cs:C1710.ACMEConfig
property _logger : cs:C1710.ACMELogger
property _transport : cs:C1710.ACMETransport
property _challenge : cs:C1710.ACMEChallenge
property _signer : cs:C1710.ACMEJwsSigner
property _orderUrl : Text
property _finalizeUrl : Text
property _certUrl : Text
property _authUrls : Collection
property _status : Text


Class constructor(\
$config : cs:C1710.ACMEConfig; \
$logger : cs:C1710.ACMELogger; \
$transport : cs:C1710.ACMETransport; \
$challenge : cs:C1710.ACMEChallenge; \
$signer : cs:C1710.ACMEJwsSigner)
	
	This:C1470._config:=$config
	This:C1470._logger:=$logger
	This:C1470._transport:=$transport
	This:C1470._challenge:=$challenge
	This:C1470._signer:=$signer
	This:C1470._orderUrl:=""
	This:C1470._finalizeUrl:=""
	This:C1470._certUrl:=""
	This:C1470._authUrls:=New collection:C1472
	This:C1470._status:=""
	
	
	// ============================================================
	// MAIN ENTRY POINT
	// ============================================================
	
Function issueCertificate($vt_privateKeyPem : Text) : Object
	// Full order → authorize → finalize → download flow.
	// $vt_privateKeyPem: the cert private key PEM (NOT the account key).
	// Returns { success, certPem, error, orderUrl }
	var $result : Object
	$result:=New object:C1471("success"; False:C215; "certPem"; ""; "error"; ""; "orderUrl"; "")
	
	// Step 1: Create order
	var $vo_order : Object
	$vo_order:=This:C1470._createOrder()
	If (Not:C34($vo_order.success))
		$result.error:=$vo_order.error
		return $result
	End if 
	$result.orderUrl:=This:C1470._orderUrl
	
	// Step 2: Process each authorization
	var $i : Integer
	For ($i; 0; This:C1470._authUrls.length-1)
		var $vo_authResult : Object
		$vo_authResult:=This:C1470._processAuthorization(This:C1470._authUrls[$i])
		If (Not:C34($vo_authResult.success))
			$result.error:=$vo_authResult.error
			return $result
		End if 
	End for 
	
	// Step 3: Finalize — submit CSR
	var $vo_finResult : Object
	$vo_finResult:=This:C1470._finalize($vt_privateKeyPem)
	If (Not:C34($vo_finResult.success))
		$result.error:=$vo_finResult.error
		return $result
	End if 
	
	// Step 4: Download certificate
	var $vt_certPem : Text
	$vt_certPem:=This:C1470._downloadCertificate()
	If (Length:C16($vt_certPem)=0)
		$result.error:="Certificate download failed or returned empty response"
		return $result
	End if 
	
	$result.success:=True:C214
	$result.certPem:=$vt_certPem
	This:C1470._logger.info("Certificate issued successfully"; New object:C1471("orderUrl"; This:C1470._orderUrl))
	return $result
	
	
	// ============================================================
	// STEP 1 — CREATE ORDER
	// ============================================================
	
Function _createOrder() : Object
	var $result : Object
	$result:=New object:C1471("success"; False:C215; "error"; "")
	
	var $vt_newOrderUrl : Text
	$vt_newOrderUrl:=This:C1470._transport.directoryUrl("newOrder")
	If (Length:C16($vt_newOrderUrl)=0)
		$result.error:="newOrder URL not available from directory"
		return $result
	End if 
	
	// Build identifiers array from config
	var $vc_identifiers : Collection
	$vc_identifiers:=New collection:C1472
	var $i : Integer
	For ($i; 0; This:C1470._config.identifiers.length-1)
		$vc_identifiers.push(New object:C1471("type"; "dns"; "value"; This:C1470._config.identifiers[$i]))
	End for 
	
	var $vo_payload : Object
	$vo_payload:=New object:C1471("identifiers"; $vc_identifiers)
	
	var $vo_response : Object
	$vo_response:=This:C1470._transport.post($vt_newOrderUrl; $vo_payload)
	
	If (Not:C34($vo_response.success)) && ($vo_response.status#201)
		$result.error:="newOrder failed: "+$vo_response.error
		This:C1470._logger.error("newOrder failed"; New object:C1471("error"; $vo_response.error; "status"; $vo_response.status))
		return $result
	End if 
	
	This:C1470._orderUrl:=$vo_response.location
	var $vo_order : Object
	$vo_order:=($vo_response.body#Null:C1517) ? $vo_response.body : New object:C1471
	
	This:C1470._finalizeUrl:=String:C10($vo_order.finalize)
	This:C1470._authUrls:=New collection:C1472
	If (OB Is defined:C1231($vo_order; "authorizations"))
		This:C1470._authUrls:=$vo_order.authorizations
	End if 
	This:C1470._status:=String:C10($vo_order.status)
	
	This:C1470._saveOrderState()
	This:C1470._logger.info("Order created"; New object:C1471("orderUrl"; This:C1470._orderUrl; "status"; This:C1470._status))
	
	$result.success:=True:C214
	return $result
	
	
	// ============================================================
	// STEP 2 — PROCESS AUTHORIZATION
	// ============================================================
	
Function _processAuthorization($vt_authUrl : Text) : Object
	var $result : Object
	$result:=New object:C1471("success"; False:C215; "error"; "")
	
	// Fetch the authorization object (POST-as-GET per RFC 8555 §6.3)
	var $vo_response : Object
	$vo_response:=This:C1470._transport.postAsGet($vt_authUrl)
	
	If (Not:C34($vo_response.success))
		$result.error:="Failed to fetch authorization: "+$vo_response.error
		return $result
	End if 
	
	var $vo_auth : Object
	$vo_auth:=$vo_response.body
	
	// Check if already valid (possible on re-run within validity window)
	If (String:C10($vo_auth.status)="valid")
		This:C1470._logger.info("Authorization already valid"; New object:C1471("url"; $vt_authUrl))
		$result.success:=True:C214
		return $result
	End if 
	
	// Find the http-01 challenge
	var $vo_challenge : Object
	$vo_challenge:=This:C1470._findHttp01Challenge($vo_auth)
	
	If ($vo_challenge=Null:C1517)
		$result.error:="No http-01 challenge found in authorization"
		return $result
	End if 
	
	var $vt_token : Text
	var $vt_challengeUrl : Text
	$vt_token:=String:C10($vo_challenge.token)
	$vt_challengeUrl:=String:C10($vo_challenge.url)
	
	// Compute keyAuthorization: token + "." + jwkThumbprint
	var $vt_keyAuth : Text
	$vt_keyAuth:=$vt_token+"."+This:C1470._signer.jwkThumbprint()
	
	// Publish the challenge
	var $vo_pubResult : Object
	$vo_pubResult:=This:C1470._challenge.publish($vt_token; $vt_keyAuth)
	If (Not:C34($vo_pubResult.success))
		$result.error:="Challenge publish failed: "+$vo_pubResult.error
		return $result
	End if 
	
	// Notify CA to validate (POST challenge URL with empty object payload)
	var $vo_notifyResponse : Object
	$vo_notifyResponse:=This:C1470._transport.post($vt_challengeUrl; New object:C1471)
	If (Not:C34($vo_notifyResponse.success)) && ($vo_notifyResponse.status#200)
		This:C1470._challenge.unpublish($vt_token)
		$result.error:="Challenge notification failed: "+$vo_notifyResponse.error
		return $result
	End if 
	
	// Poll authorization until valid or timeout
	var $vo_pollResult : Object
	$vo_pollResult:=This:C1470._pollAuthorization($vt_authUrl; $vt_token)
	
	// Always unpublish after polling (success or failure)
	This:C1470._challenge.unpublish($vt_token)
	
	If (Not:C34($vo_pollResult.success))
		$result.error:=$vo_pollResult.error
		return $result
	End if 
	
	$result.success:=True:C214
	return $result
	
	
Function _findHttp01Challenge($vo_auth : Object) : Object
	// Return the http-01 challenge object from an authorization, or Null.
	If (($vo_auth=Null:C1517) | (Not:C34(OB Is defined:C1231($vo_auth; "challenges"))))
		return Null:C1517
	End if 
	
	var $vc_challenges : Collection
	$vc_challenges:=$vo_auth.challenges
	
	var $i : Integer
	For ($i; 0; $vc_challenges.length-1)
		If (String:C10($vc_challenges[$i]["type"])="http-01")
			return $vc_challenges[$i]
		End if 
	End for 
	
	return Null:C1517
	
	
Function _pollAuthorization($vt_authUrl : Text; $vt_token : Text) : Object
	// Poll the authorization URL until status = "valid", "invalid", or timeout.
	var $result : Object
	$result:=New object:C1471("success"; False:C215; "error"; "")
	
	var $i : Integer
	var $vt_status : Text
	
	For ($i; 1; This:C1470._config.maxPollAttempts)
		DELAY PROCESS:C323(Current process:C322; This:C1470._config.pollIntervalSecs*60)
		
		var $vo_response : Object
		$vo_response:=This:C1470._transport.postAsGet($vt_authUrl)
		
		If (Not:C34($vo_response.success))
			This:C1470._logger.warn("Auth poll request failed"; New object:C1471("attempt"; $i; "error"; $vo_response.error))
		Else 
			$vt_status:=String:C10($vo_response.body.status)
			This:C1470._logger.debug("Auth poll"; New object:C1471("attempt"; $i; "status"; $vt_status))
			
			Case of 
				: ($vt_status="valid")
					$result.success:=True:C214
					return $result
					
				: ($vt_status="invalid")
					var $vt_errDetail : Text
					$vt_errDetail:=""
					If (OB Is defined:C1231($vo_response.body; "challenges"))
						var $j : Integer
						For ($j; 0; $vo_response.body.challenges.length-1)
							If (String:C10($vo_response.body.challenges[$j]["type"])="http-01")
								$vt_errDetail:=String:C10($vo_response.body.challenges[$j].error.detail)
							End if 
						End for 
					End if 
					$result.error:="Authorization invalid: "+$vt_errDetail
					return $result
			End case 
		End if 
	End for 
	
	$result.error:="Authorization polling timed out after "+String:C10(This:C1470._config.maxPollAttempts)+" attempts"
	return $result
	
	
	// ============================================================
	// STEP 3 — FINALIZE
	// ============================================================
	
Function _finalize($vt_certPrivKeyPem : Text) : Object
	var $result : Object
	$result:=New object:C1471("success"; False:C215; "error"; "")
	
	If (Length:C16(This:C1470._finalizeUrl)=0)
		$result.error:="No finalize URL — order may not have been created"
		return $result
	End if 
	
	// Build the CSR for the first identifier (MVP: single hostname)
	var $vo_csr : cs:C1710.ACMECsr
	$vo_csr:=cs:C1710.ACMECsr.new()
	
	var $vt_hostname : Text
	$vt_hostname:=String:C10(This:C1470._config.identifiers[0])
	
	var $vt_csrB64url : Text
	$vt_csrB64url:=$vo_csr.build($vt_certPrivKeyPem; $vt_hostname)
	
	If (Length:C16($vt_csrB64url)=0)
		$result.error:="CSR generation failed"
		This:C1470._logger.error("CSR generation failed"; New object:C1471("hostname"; $vt_hostname))
		return $result
	End if 
	
	var $vo_payload : Object
	$vo_payload:=New object:C1471("csr"; $vt_csrB64url)
	
	var $vo_response : Object
	$vo_response:=This:C1470._transport.post(This:C1470._finalizeUrl; $vo_payload)
	
	If (Not:C34($vo_response.success)) && ($vo_response.status#200)
		$result.error:="Finalize failed: "+$vo_response.error
		This:C1470._logger.error("Order finalize failed"; New object:C1471("error"; $vo_response.error; "status"; $vo_response.status))
		return $result
	End if 
	
	// Update order URL/certUrl from response
	If ($vo_response.body#Null:C1517)
		This:C1470._certUrl:=String:C10($vo_response.body.certificate)
		This:C1470._status:=String:C10($vo_response.body.status)
	End if 
	
	// Poll order until valid
	var $vo_pollResult : Object
	$vo_pollResult:=This:C1470._pollOrder()
	If (Not:C34($vo_pollResult.success))
		$result.error:=$vo_pollResult.error
		return $result
	End if 
	
	$result.success:=True:C214
	return $result
	
	
Function _pollOrder() : Object
	// Poll the order URL until status = "valid" (cert ready to download).
	var $result : Object
	$result:=New object:C1471("success"; False:C215; "error"; "")
	
	If (Length:C16(This:C1470._orderUrl)=0)
		$result.error:="No order URL to poll"
		return $result
	End if 
	
	var $i : Integer
	For ($i; 1; This:C1470._config.maxPollAttempts)
		DELAY PROCESS:C323(Current process:C322; This:C1470._config.pollIntervalSecs*60)
		
		var $vo_response : Object
		$vo_response:=This:C1470._transport.postAsGet(This:C1470._orderUrl)
		
		If ($vo_response.success) && ($vo_response.body#Null:C1517)
			var $vt_status : Text
			$vt_status:=String:C10($vo_response.body.status)
			This:C1470._logger.debug("Order poll"; New object:C1471("attempt"; $i; "status"; $vt_status))
			
			Case of 
				: ($vt_status="valid")
					This:C1470._certUrl:=String:C10($vo_response.body.certificate)
					This:C1470._saveOrderState()
					$result.success:=True:C214
					return $result
					
				: ($vt_status="invalid")
					$result.error:="Order became invalid"
					return $result
			End case 
		End if 
	End for 
	
	$result.error:="Order polling timed out"
	return $result
	
	
	// ============================================================
	// STEP 4 — DOWNLOAD CERTIFICATE
	// ============================================================
	
Function _downloadCertificate() : Text
	// Download the PEM certificate chain from the order's certificate URL.
	If (Length:C16(This:C1470._certUrl)=0)
		This:C1470._logger.error("No certificate URL to download"; Null:C1517)
		return ""
	End if 
	
	var $vo_response : Object
	$vo_response:=This:C1470._transport.postAsGet(This:C1470._certUrl)
	
	If (Not:C34($vo_response.success))
		This:C1470._logger.error("Certificate download failed"; New object:C1471("error"; $vo_response.error; "url"; This:C1470._certUrl))
		return ""
	End if 
	
	// Body may be text (PEM) or an object — expect text/PEM from LE
	// For some reason 4D returns '38' or 'is Object' when testing value type on blob data stored in an object, so testing both just in case.
	If (Value type:C1509($vo_response.body)=Is BLOB:K8:12) || (Value type:C1509($vo_response.body)=Is object:K8:27)
		return BLOB to text:C555($vo_response.body; UTF8 text without length:K22:17)
	End if 
	
	If (Value type:C1509($vo_response.body)=Is text:K8:3)
		return String:C10($vo_response.body)
	End if 
	
	return ""
	
	
	// ============================================================
	// STATE PERSISTENCE
	// ============================================================
	
Function _saveOrderState()
	// Persist order URL, finalize URL, cert URL, and auth URLs to disk
	// so that an interrupted run can be resumed.
	var $vt_storePath : Text
	$vt_storePath:=This:C1470._config.effectiveStorePath()
	
	var $vt_hostname : Text
	$vt_hostname:=String:C10(This:C1470._config.identifiers[0])
	// Sanitise hostname for filename
	$vt_hostname:=Replace string:C233($vt_hostname; "*"; "wildcard")
	$vt_hostname:=Replace string:C233($vt_hostname; "."; "-")
	
	var $vo_state : Object
	$vo_state:=New object:C1471(\
		"orderUrl"; This:C1470._orderUrl; \
		"finalizeUrl"; This:C1470._finalizeUrl; \
		"certUrl"; This:C1470._certUrl; \
		"authUrls"; This:C1470._authUrls; \
		"status"; This:C1470._status; \
		"savedAt"; String:C10(Current date:C33; ISO date:K1:8; Current time:C178))
	
	var $vf_state : 4D:C1709.File
	$vf_state:=File:C1566($vt_storePath+"order-"+$vt_hostname+".json"; fk platform path:K87:2)
	Try
		$vf_state.setText(JSON Stringify:C1217($vo_state); "utf-8")
	Catch
		This:C1470._logger.warn("Could not save order state"; Null:C1517)
	End try
	
	
Function loadOrderState() : Boolean
	// Load a previously persisted order state. Returns True if a resumable
	// pending/processing order was found for the first configured identifier.
	var $vt_storePath : Text
	$vt_storePath:=This:C1470._config.effectiveStorePath()
	
	var $vt_hostname : Text
	$vt_hostname:=String:C10(This:C1470._config.identifiers[0])
	$vt_hostname:=Replace string:C233($vt_hostname; "*"; "wildcard")
	$vt_hostname:=Replace string:C233($vt_hostname; "."; "-")
	
	var $vf_state : 4D:C1709.File
	$vf_state:=File:C1566($vt_storePath+"order-"+$vt_hostname+".json"; fk platform path:K87:2)
	
	If (Not:C34($vf_state.exists))
		return False:C215
	End if 
	
	Try
		var $vt_json : Text
		var $vo_state : Object
		$vt_json:=$vf_state.getText("utf-8")
		$vo_state:=JSON Parse:C1218($vt_json)
		
		If ($vo_state=Null:C1517)
			return False:C215
		End if 
		
		This:C1470._orderUrl:=String:C10($vo_state.orderUrl)
		This:C1470._finalizeUrl:=String:C10($vo_state.finalizeUrl)
		This:C1470._certUrl:=String:C10($vo_state.certUrl)
		This:C1470._authUrls:=$vo_state.authUrls
		This:C1470._status:=String:C10($vo_state.status)
		return (Length:C16(This:C1470._orderUrl)>0)
	Catch
		return False:C215
	End try
	