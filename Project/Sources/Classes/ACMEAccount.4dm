// ----------------------------------------------------
// Class: ACMEAccount
// Manages the ACME account key pair and registration state.
//
// The account key is a 2048-bit RSA key pair generated once per deployment
// and persisted to the store path. It is reused for all subsequent requests
// to the same CA — there is no expiry on the account key itself.
//
// Persistent state stored as JSON in <storePath>/account.json:
//   {
//     "accountUrl": "<kid from CA>",
//     "email":      "<contact email>",
//     "createdAt":  "<ISO8601>",
//     "ca":         "<directoryUrl>"
//   }
//
// The private key PEM is stored separately in <storePath>/account-key.pem
// (never in account.json to prevent it appearing in logs).
//
// IMPORTANT: The private key file must have permissions restricted to
// the 4D process user. The component does not set file permissions (not
// available in the 4D v20 cross-platform API); this is the deployer's
// responsibility.
// ----------------------------------------------------

property _config : cs:C1710.ACMEConfig
property _logger : cs:C1710.ACMELogger
property accountUrl : Text  // kid — set after registration
property email : Text
property isRegistered : Boolean
property _privateKeyPem : Text  // NEVER log


Class constructor($config : cs:C1710.ACMEConfig; $logger : cs:C1710.ACMELogger)
	This:C1470._config:=$config
	This:C1470._logger:=$logger
	This:C1470.accountUrl:=""
	This:C1470.email:=""
	This:C1470.isRegistered:=False:C215
	This:C1470._privateKeyPem:=""
	
	
	// ============================================================
	// LOAD / SAVE
	// ============================================================
	
Function load() : Boolean
	// Load existing account state from the store path.
	// Returns True if a valid account was found, False if none exists yet.
	var $vt_storePath : Text
	$vt_storePath:=This:C1470._config.effectiveStorePath()
	
	// Ensure store directory exists
	var $vf_store : 4D:C1709.Folder
	$vf_store:=Folder:C1567($vt_storePath; fk platform path:K87:2)
	If (Not:C34($vf_store.exists))
		$vf_store.create()
	End if 
	
	// Load private key
	var $vf_keyFile : 4D:C1709.File
	$vf_keyFile:=File:C1566($vt_storePath+"account-key.pem"; fk platform path:K87:2)
	If (Not:C34($vf_keyFile.exists))
		return False:C215
	End if 
	
	Try
		This:C1470._privateKeyPem:=$vf_keyFile.getText("utf-8")
	Catch
		This:C1470._logger.error("Failed to read account key file"; New object:C1471("path"; $vt_storePath+"account-key.pem"))
		return False:C215
	End try
	
	// Load account metadata
	var $vf_meta : 4D:C1709.File
	$vf_meta:=File:C1566($vt_storePath+"account.json"; fk platform path:K87:2)
	If (Not:C34($vf_meta.exists))
		// Key exists but no registration — treat as partial state
		return False:C215
	End if 
	
	var $vt_json : Text
	var $vo_meta : Object
	Try
		$vt_json:=$vf_meta.getText("utf-8")
		$vo_meta:=JSON Parse:C1218($vt_json)
	Catch
		This:C1470._logger.warn("Could not parse account.json; will re-register"; Null:C1517)
		return False:C215
	End try
	
	If ($vo_meta=Null:C1517) | (Length:C16(String:C10($vo_meta.accountUrl))=0)
		return False:C215
	End if 
	
	This:C1470.accountUrl:=String:C10($vo_meta.accountUrl)
	This:C1470.email:=String:C10($vo_meta.email)
	This:C1470.isRegistered:=True:C214
	This:C1470._logger.info("Account loaded from store"; New object:C1471("accountUrl"; This:C1470.accountUrl))
	return True:C214
	
	
Function save()
	// Persist account state. Key is written to a separate file from metadata.
	var $vt_storePath : Text
	$vt_storePath:=This:C1470._config.effectiveStorePath()
	
	var $vf_store : 4D:C1709.Folder
	$vf_store:=Folder:C1567($vt_storePath; fk platform path:K87:2)
	If (Not:C34($vf_store.exists))
		$vf_store.create()
	End if 
	
	// Write private key (key material — never log contents)
	var $vf_keyFile : 4D:C1709.File
	$vf_keyFile:=File:C1566($vt_storePath+"account-key.pem"; fk platform path:K87:2)
	Try
		$vf_keyFile.setText(This:C1470._privateKeyPem; "utf-8")
	Catch
		This:C1470._logger.error("Failed to write account key file"; New object:C1471("path"; $vt_storePath+"account-key.pem"))
		return 
	End try
	
	// Write metadata (no key material)
	var $vo_meta : Object
	$vo_meta:=New object:C1471(\
		"accountUrl"; This:C1470.accountUrl; \
		"email"; This:C1470.email; \
		"createdAt"; String:C10(Current date:C33; ISO date:K1:8; Current time:C178); \
		"ca"; This:C1470._config.directoryUrl)
	
	var $vf_meta : 4D:C1709.File
	$vf_meta:=File:C1566($vt_storePath+"account.json"; fk platform path:K87:2)
	Try
		$vf_meta.setText(JSON Stringify:C1217($vo_meta); "utf-8")
	Catch
		This:C1470._logger.error("Failed to write account.json"; Null:C1517)
	End try
	
	
	// ============================================================
	// KEY GENERATION
	// ============================================================
	
Function generateKey()
	// Generate a new 2048-bit RSA key pair and store PEM in memory.
	// Call this before register() when no existing key is found.
	var $vo_cryptoKey : 4D:C1709.CryptoKey
	var $vo_params : Object
	$vo_params:=New object:C1471(\
		"type"; "RSA"; \
		"size"; 2048)
	$vo_cryptoKey:=4D:C1709.CryptoKey.new($vo_params)
	This:C1470._privateKeyPem:=$vo_cryptoKey.getPrivateKey()
	This:C1470._logger.info("New account key pair generated"; Null:C1517)
	
	
Function privateKeyPem() : Text
	// Return the private key PEM — caller must not log this value.
	return This:C1470._privateKeyPem
	
	
	// ============================================================
	// REGISTRATION
	// ============================================================
	
Function register($transport : cs:C1710.ACMETransport; $signer : cs:C1710.ACMEJwsSigner) : Object
	// Register a new account with the CA (POST newAccount).
	// Returns a standard result object:
	//   { success, accountUrl, error }
	var $result : Object
	$result:=New object:C1471("success"; False:C215; "accountUrl"; ""; "error"; "")
	
	var $vt_newAccountUrl : Text
	$vt_newAccountUrl:=$transport.directoryUrl("newAccount")
	If (Length:C16($vt_newAccountUrl)=0)
		$result.error:="newAccount URL not available from directory"
		return $result
	End if 
	
	var $vo_payload : Object
	$vo_payload:=New object:C1471(\
		"termsOfServiceAgreed"; True:C214; \
		"contact"; New collection:C1472("mailto:"+This:C1470._config.contactEmail))
	
	var $vo_response : Object
	$vo_response:=$transport.post($vt_newAccountUrl; $vo_payload)
	
	If (Not:C34($vo_response.success)) && ($vo_response.status#200) && ($vo_response.status#201)
		$result.error:=$vo_response.error
		This:C1470._logger.error("Account registration failed"; New object:C1471("error"; $vo_response.error; "status"; $vo_response.status))
		return $result
	End if 
	
	// Both 200 (existing account) and 201 (new account) are valid
	var $vt_accountUrl : Text
	$vt_accountUrl:=$vo_response.location
	
	If (Length:C16($vt_accountUrl)=0) && ($vo_response.body#Null:C1517)
		// Some CAs omit Location; fall back to status check
		$vt_accountUrl:=String:C10($vo_response.body["url"])
	End if 
	
	If (Length:C16($vt_accountUrl)=0) && ($vo_response.headers#Null:C1517)
		$vt_accountUrl:=$vo_response.headers.location
	End if 
	
	If (Length:C16($vt_accountUrl)=0)
		$result.error:="CA did not return an account URL"
		return $result
	End if 
	
	This:C1470.accountUrl:=$vt_accountUrl
	This:C1470.email:=This:C1470._config.contactEmail
	This:C1470.isRegistered:=True:C214
	
	// Switch signer to KID mode now that we have the account URL
	$signer.setKid($vt_accountUrl)
	
	This:C1470._logger.info("Account registered/confirmed"; New object:C1471("accountUrl"; $vt_accountUrl))
	
	$result.success:=True:C214
	$result.accountUrl:=$vt_accountUrl
	return $result
	