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

property _config : cs.acme.ACMEConfig
property _logger : cs.acme.ACMELogger
property _transport : cs.acme.ACMETransport
property _challenge : cs.acme.ACMEChallenge
property _signer : cs.acme.ACMEJwsSigner
property _orderUrl : Text
property _finalizeUrl : Text
property _certUrl : Text
property _authUrls : Collection
property _status : Text


Class constructor(\
	$config : cs.acme.ACMEConfig; \
	$logger : cs.acme.ACMELogger; \
	$transport : cs.acme.ACMETransport; \
	$challenge : cs.acme.ACMEChallenge; \
	$signer : cs.acme.ACMEJwsSigner)

	This._config:=$config
	This._logger:=$logger
	This._transport:=$transport
	This._challenge:=$challenge
	This._signer:=$signer
	This._orderUrl:=""
	This._finalizeUrl:=""
	This._certUrl:=""
	This._authUrls:=New collection
	This._status:=""


// ============================================================
// MAIN ENTRY POINT
// ============================================================

Function issueCertificate($vt_privateKeyPem : Text) : Object
	// Full order → authorize → finalize → download flow.
	// $vt_privateKeyPem: the cert private key PEM (NOT the account key).
	// Returns { success, certPem, error, orderUrl }
	var $result : Object
	$result:=New object("success"; False; "certPem"; ""; "error"; ""; "orderUrl"; "")

	// Step 1: Create order
	var $vo_order : Object
	$vo_order:=This._createOrder()
	If (Not($vo_order.success))
		$result.error:=$vo_order.error
		return $result
	End if
	$result.orderUrl:=This._orderUrl

	// Step 2: Process each authorization
	var $i : Integer
	For ($i; 0; This._authUrls.length-1)
		var $vo_authResult : Object
		$vo_authResult:=This._processAuthorization(This._authUrls[$i])
		If (Not($vo_authResult.success))
			$result.error:=$vo_authResult.error
			return $result
		End if
	End for

	// Step 3: Finalize — submit CSR
	var $vo_finResult : Object
	$vo_finResult:=This._finalize($vt_privateKeyPem)
	If (Not($vo_finResult.success))
		$result.error:=$vo_finResult.error
		return $result
	End if

	// Step 4: Download certificate
	var $vt_certPem : Text
	$vt_certPem:=This._downloadCertificate()
	If (Length($vt_certPem)=0)
		$result.error:="Certificate download failed or returned empty response"
		return $result
	End if

	$result.success:=True
	$result.certPem:=$vt_certPem
	This._logger.info("Certificate issued successfully"; New object("orderUrl"; This._orderUrl))
	return $result


// ============================================================
// STEP 1 — CREATE ORDER
// ============================================================

Function _createOrder() : Object
	var $result : Object
	$result:=New object("success"; False; "error"; "")

	var $vt_newOrderUrl : Text
	$vt_newOrderUrl:=This._transport.directoryUrl("newOrder")
	If (Length($vt_newOrderUrl)=0)
		$result.error:="newOrder URL not available from directory"
		return $result
	End if

	// Build identifiers array from config
	var $vc_identifiers : Collection
	$vc_identifiers:=New collection
	var $i : Integer
	For ($i; 0; This._config.identifiers.length-1)
		$vc_identifiers.push(New object("type"; "dns"; "value"; This._config.identifiers[$i]))
	End for

	var $vo_payload : Object
	$vo_payload:=New object("identifiers"; $vc_identifiers)

	var $vo_response : Object
	$vo_response:=This._transport.post($vt_newOrderUrl; $vo_payload)

	If (Not($vo_response.success)) && ($vo_response.status#201)
		$result.error:="newOrder failed: "+$vo_response.error
		This._logger.error("newOrder failed"; New object("error"; $vo_response.error; "status"; $vo_response.status))
		return $result
	End if

	This._orderUrl:=$vo_response.location
	var $vo_order : Object
	$vo_order:=($vo_response.body#Null) ? $vo_response.body : New object

	This._finalizeUrl:=String($vo_order.finalize)
	This._authUrls:=New collection
	If (OB Is defined($vo_order; "authorizations"))
		This._authUrls:=$vo_order.authorizations
	End if
	This._status:=String($vo_order.status)

	This._saveOrderState()
	This._logger.info("Order created"; New object("orderUrl"; This._orderUrl; "status"; This._status))

	$result.success:=True
	return $result


// ============================================================
// STEP 2 — PROCESS AUTHORIZATION
// ============================================================

Function _processAuthorization($vt_authUrl : Text) : Object
	var $result : Object
	$result:=New object("success"; False; "error"; "")

	// Fetch the authorization object (POST-as-GET per RFC 8555 §6.3)
	var $vo_response : Object
	$vo_response:=This._transport.postAsGet($vt_authUrl)

	If (Not($vo_response.success))
		$result.error:="Failed to fetch authorization: "+$vo_response.error
		return $result
	End if

	var $vo_auth : Object
	$vo_auth:=$vo_response.body

	// Check if already valid (possible on re-run within validity window)
	If (String($vo_auth.status)="valid")
		This._logger.info("Authorization already valid"; New object("url"; $vt_authUrl))
		$result.success:=True
		return $result
	End if

	// Find the http-01 challenge
	var $vo_challenge : Object
	$vo_challenge:=This._findHttp01Challenge($vo_auth)

	If ($vo_challenge=Null)
		$result.error:="No http-01 challenge found in authorization"
		return $result
	End if

	var $vt_token : Text
	var $vt_challengeUrl : Text
	$vt_token:=String($vo_challenge.token)
	$vt_challengeUrl:=String($vo_challenge.url)

	// Compute keyAuthorization: token + "." + jwkThumbprint
	var $vt_keyAuth : Text
	$vt_keyAuth:=$vt_token+"."+This._signer.jwkThumbprint()

	// Publish the challenge
	var $vo_pubResult : Object
	$vo_pubResult:=This._challenge.publish($vt_token; $vt_keyAuth)
	If (Not($vo_pubResult.success))
		$result.error:="Challenge publish failed: "+$vo_pubResult.error
		return $result
	End if

	// Notify CA to validate (POST challenge URL with empty object payload)
	var $vo_notifyResponse : Object
	$vo_notifyResponse:=This._transport.post($vt_challengeUrl; New object)
	If (Not($vo_notifyResponse.success)) && ($vo_notifyResponse.status#200)
		This._challenge.unpublish($vt_token)
		$result.error:="Challenge notification failed: "+$vo_notifyResponse.error
		return $result
	End if

	// Poll authorization until valid or timeout
	var $vo_pollResult : Object
	$vo_pollResult:=This._pollAuthorization($vt_authUrl; $vt_token)

	// Always unpublish after polling (success or failure)
	This._challenge.unpublish($vt_token)

	If (Not($vo_pollResult.success))
		$result.error:=$vo_pollResult.error
		return $result
	End if

	$result.success:=True
	return $result


Function _findHttp01Challenge($vo_auth : Object) : Object
	// Return the http-01 challenge object from an authorization, or Null.
	If (($vo_auth=Null) | (Not(OB Is defined($vo_auth; "challenges"))))
		return Null
	End if

	var $vc_challenges : Collection
	$vc_challenges:=$vo_auth.challenges

	var $i : Integer
	For ($i; 0; $vc_challenges.length-1)
		If (String($vc_challenges[$i]["type"])="http-01")
			return $vc_challenges[$i]
		End if
	End for

	return Null


Function _pollAuthorization($vt_authUrl : Text; $vt_token : Text) : Object
	// Poll the authorization URL until status = "valid", "invalid", or timeout.
	var $result : Object
	$result:=New object("success"; False; "error"; "")

	var $i : Integer
	var $vt_status : Text

	For ($i; 1; This._config.maxPollAttempts)
		DELAY PROCESS(Current process; This._config.pollIntervalSecs*60)

		var $vo_response : Object
		$vo_response:=This._transport.postAsGet($vt_authUrl)

		If (Not($vo_response.success))
			This._logger.warn("Auth poll request failed"; New object("attempt"; $i; "error"; $vo_response.error))
		Else
			$vt_status:=String($vo_response.body.status)
			This._logger.debug("Auth poll"; New object("attempt"; $i; "status"; $vt_status))

			Case of
				: ($vt_status="valid")
					$result.success:=True
					return $result

				: ($vt_status="invalid")
					var $vt_errDetail : Text
					$vt_errDetail:=""
					If (OB Is defined($vo_response.body; "challenges"))
						var $j : Integer
						For ($j; 0; $vo_response.body.challenges.length-1)
							If (String($vo_response.body.challenges[$j]["type"])="http-01")
								$vt_errDetail:=String($vo_response.body.challenges[$j].error.detail)
							End if
						End for
					End if
					$result.error:="Authorization invalid: "+$vt_errDetail
					return $result
			End case
		End if
	End for

	$result.error:="Authorization polling timed out after "+String(This._config.maxPollAttempts)+" attempts"
	return $result


// ============================================================
// STEP 3 — FINALIZE
// ============================================================

Function _finalize($vt_certPrivKeyPem : Text) : Object
	var $result : Object
	$result:=New object("success"; False; "error"; "")

	If (Length(This._finalizeUrl)=0)
		$result.error:="No finalize URL — order may not have been created"
		return $result
	End if

	// Build the CSR for the first identifier (MVP: single hostname)
	var $vo_csr : cs.acme.ACMECsr
	$vo_csr:=cs.acme.ACMECsr.new()

	var $vt_hostname : Text
	$vt_hostname:=String(This._config.identifiers[0])

	var $vt_csrB64url : Text
	$vt_csrB64url:=$vo_csr.build($vt_certPrivKeyPem; $vt_hostname)

	If (Length($vt_csrB64url)=0)
		$result.error:="CSR generation failed"
		This._logger.error("CSR generation failed"; New object("hostname"; $vt_hostname))
		return $result
	End if

	var $vo_payload : Object
	$vo_payload:=New object("csr"; $vt_csrB64url)

	var $vo_response : Object
	$vo_response:=This._transport.post(This._finalizeUrl; $vo_payload)

	If (Not($vo_response.success)) && ($vo_response.status#200)
		$result.error:="Finalize failed: "+$vo_response.error
		This._logger.error("Order finalize failed"; New object("error"; $vo_response.error; "status"; $vo_response.status))
		return $result
	End if

	// Update order URL/certUrl from response
	If ($vo_response.body#Null)
		This._certUrl:=String($vo_response.body.certificate)
		This._status:=String($vo_response.body.status)
	End if

	// Poll order until valid
	var $vo_pollResult : Object
	$vo_pollResult:=This._pollOrder()
	If (Not($vo_pollResult.success))
		$result.error:=$vo_pollResult.error
		return $result
	End if

	$result.success:=True
	return $result


Function _pollOrder() : Object
	// Poll the order URL until status = "valid" (cert ready to download).
	var $result : Object
	$result:=New object("success"; False; "error"; "")

	If (Length(This._orderUrl)=0)
		$result.error:="No order URL to poll"
		return $result
	End if

	var $i : Integer
	For ($i; 1; This._config.maxPollAttempts)
		DELAY PROCESS(Current process; This._config.pollIntervalSecs*60)

		var $vo_response : Object
		$vo_response:=This._transport.postAsGet(This._orderUrl)

		If ($vo_response.success) && ($vo_response.body#Null)
			var $vt_status : Text
			$vt_status:=String($vo_response.body.status)
			This._logger.debug("Order poll"; New object("attempt"; $i; "status"; $vt_status))

			Case of
				: ($vt_status="valid")
					This._certUrl:=String($vo_response.body.certificate)
					This._saveOrderState()
					$result.success:=True
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
	If (Length(This._certUrl)=0)
		This._logger.error("No certificate URL to download"; Null)
		return ""
	End if

	var $vo_response : Object
	$vo_response:=This._transport.postAsGet(This._certUrl)

	If (Not($vo_response.success))
		This._logger.error("Certificate download failed"; New object("error"; $vo_response.error; "url"; This._certUrl))
		return ""
	End if

	// Body may be text (PEM) or an object — expect text/PEM from LE
	If (Value type($vo_response.body)=Is text)
		return String($vo_response.body)
	End if

	return ""


// ============================================================
// STATE PERSISTENCE
// ============================================================

Function _saveOrderState()
	// Persist order URL, finalize URL, cert URL, and auth URLs to disk
	// so that an interrupted run can be resumed.
	var $vt_storePath : Text
	$vt_storePath:=This._config.effectiveStorePath()

	var $vt_hostname : Text
	$vt_hostname:=String(This._config.identifiers[0])
	// Sanitise hostname for filename
	$vt_hostname:=Replace string($vt_hostname; "*"; "wildcard")
	$vt_hostname:=Replace string($vt_hostname; "."; "-")

	var $vo_state : Object
	$vo_state:=New object(\
		"orderUrl"; This._orderUrl; \
		"finalizeUrl"; This._finalizeUrl; \
		"certUrl"; This._certUrl; \
		"authUrls"; This._authUrls; \
		"status"; This._status; \
		"savedAt"; String(Current date; ISO date; Current time))

	var $vf_state : 4D.File
	$vf_state:=File($vt_storePath+"order-"+$vt_hostname+".json")
	Try
		$vf_state.setText(JSON Stringify($vo_state); "utf-8")
	Catch
		This._logger.warn("Could not save order state"; Null)
	End try


Function loadOrderState() : Boolean
	// Load a previously persisted order state. Returns True if a resumable
	// pending/processing order was found for the first configured identifier.
	var $vt_storePath : Text
	$vt_storePath:=This._config.effectiveStorePath()

	var $vt_hostname : Text
	$vt_hostname:=String(This._config.identifiers[0])
	$vt_hostname:=Replace string($vt_hostname; "*"; "wildcard")
	$vt_hostname:=Replace string($vt_hostname; "."; "-")

	var $vf_state : 4D.File
	$vf_state:=File($vt_storePath+"order-"+$vt_hostname+".json")

	If (Not($vf_state.exists))
		return False
	End if

	Try
		var $vt_json : Text
		var $vo_state : Object
		$vt_json:=$vf_state.getText("utf-8")
		$vo_state:=JSON Parse($vt_json)

		If ($vo_state=Null)
			return False
		End if

		This._orderUrl:=String($vo_state.orderUrl)
		This._finalizeUrl:=String($vo_state.finalizeUrl)
		This._certUrl:=String($vo_state.certUrl)
		This._authUrls:=$vo_state.authUrls
		This._status:=String($vo_state.status)
		return (Length(This._orderUrl)>0)
	Catch
		return False
	End try
