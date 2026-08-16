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

property _config : cs.acme.ACMEConfig
property _logger : cs.acme.ACMELogger
property accountUrl : Text     // kid — set after registration
property email : Text
property isRegistered : Boolean
property _privateKeyPem : Text  // NEVER log


Class constructor($config : cs.acme.ACMEConfig; $logger : cs.acme.ACMELogger)
	This._config:=$config
	This._logger:=$logger
	This.accountUrl:=""
	This.email:=""
	This.isRegistered:=False
	This._privateKeyPem:=""


// ============================================================
// LOAD / SAVE
// ============================================================

Function load() : Boolean
	// Load existing account state from the store path.
	// Returns True if a valid account was found, False if none exists yet.
	var $vt_storePath : Text
	$vt_storePath:=This._config.effectiveStorePath()

	// Ensure store directory exists
	var $vf_store : 4D.Folder
	$vf_store:=Folder($vt_storePath)
	If (Not($vf_store.exists))
		$vf_store.create()
	End if

	// Load private key
	var $vf_keyFile : 4D.File
	$vf_keyFile:=File($vt_storePath+"account-key.pem")
	If (Not($vf_keyFile.exists))
		return False
	End if

	Try
		This._privateKeyPem:=$vf_keyFile.getText("utf-8")
	Catch
		This._logger.error("Failed to read account key file"; New object("path"; $vt_storePath+"account-key.pem"))
		return False
	End try

	// Load account metadata
	var $vf_meta : 4D.File
	$vf_meta:=File($vt_storePath+"account.json")
	If (Not($vf_meta.exists))
		// Key exists but no registration — treat as partial state
		return False
	End if

	var $vt_json : Text
	var $vo_meta : Object
	Try
		$vt_json:=$vf_meta.getText("utf-8")
		$vo_meta:=JSON Parse($vt_json)
	Catch
		This._logger.warn("Could not parse account.json; will re-register"; Null)
		return False
	End try

	If ($vo_meta=Null) | (Length(String($vo_meta.accountUrl))=0)
		return False
	End if

	This.accountUrl:=String($vo_meta.accountUrl)
	This.email:=String($vo_meta.email)
	This.isRegistered:=True
	This._logger.info("Account loaded from store"; New object("accountUrl"; This.accountUrl))
	return True


Function save()
	// Persist account state. Key is written to a separate file from metadata.
	var $vt_storePath : Text
	$vt_storePath:=This._config.effectiveStorePath()

	var $vf_store : 4D.Folder
	$vf_store:=Folder($vt_storePath)
	If (Not($vf_store.exists))
		$vf_store.create()
	End if

	// Write private key (key material — never log contents)
	var $vf_keyFile : 4D.File
	$vf_keyFile:=File($vt_storePath+"account-key.pem")
	Try
		$vf_keyFile.setText(This._privateKeyPem; "utf-8")
	Catch
		This._logger.error("Failed to write account key file"; New object("path"; $vt_storePath+"account-key.pem"))
		return
	End try

	// Write metadata (no key material)
	var $vo_meta : Object
	$vo_meta:=New object(\
		"accountUrl"; This.accountUrl; \
		"email"; This.email; \
		"createdAt"; String(Current date; ISO date; Current time); \
		"ca"; This._config.directoryUrl)

	var $vf_meta : 4D.File
	$vf_meta:=File($vt_storePath+"account.json")
	Try
		$vf_meta.setText(JSON Stringify($vo_meta); "utf-8")
	Catch
		This._logger.error("Failed to write account.json"; Null)
	End try


// ============================================================
// KEY GENERATION
// ============================================================

Function generateKey()
	// Generate a new 2048-bit RSA key pair and store PEM in memory.
	// Call this before register() when no existing key is found.
	var $vo_cryptoKey : 4D.CryptoKey
	var $vo_params : Object
	$vo_params:=New object(\
		"type"; "RSA"; \
		"size"; 2048)
	$vo_cryptoKey:=4D.CryptoKey.new($vo_params)
	This._privateKeyPem:=$vo_cryptoKey.getPrivateKey()
	This._logger.info("New account key pair generated"; Null)


Function privateKeyPem() : Text
	// Return the private key PEM — caller must not log this value.
	return This._privateKeyPem


// ============================================================
// REGISTRATION
// ============================================================

Function register($transport : cs.acme.ACMETransport; $signer : cs.acme.ACMEJwsSigner) : Object
	// Register a new account with the CA (POST newAccount).
	// Returns a standard result object:
	//   { success, accountUrl, error }
	var $result : Object
	$result:=New object("success"; False; "accountUrl"; ""; "error"; "")

	var $vt_newAccountUrl : Text
	$vt_newAccountUrl:=$transport.directoryUrl("newAccount")
	If (Length($vt_newAccountUrl)=0)
		$result.error:="newAccount URL not available from directory"
		return $result
	End if

	var $vo_payload : Object
	$vo_payload:=New object(\
		"termsOfServiceAgreed"; True; \
		"contact"; New collection("mailto:"+This._config.contactEmail))

	var $vo_response : Object
	$vo_response:=$transport.post($vt_newAccountUrl; $vo_payload)

	If (Not($vo_response.success)) && ($vo_response.status#200) && ($vo_response.status#201)
		$result.error:=$vo_response.error
		This._logger.error("Account registration failed"; New object("error"; $vo_response.error; "status"; $vo_response.status))
		return $result
	End if

	// Both 200 (existing account) and 201 (new account) are valid
	var $vt_accountUrl : Text
	$vt_accountUrl:=$vo_response.location

	If (Length($vt_accountUrl)=0) && ($vo_response.body#Null)
		// Some CAs omit Location; fall back to status check
		$vt_accountUrl:=String($vo_response.body["url"])
	End if

	If (Length($vt_accountUrl)=0)
		$result.error:="CA did not return an account URL"
		return $result
	End if

	This.accountUrl:=$vt_accountUrl
	This.email:=This._config.contactEmail
	This.isRegistered:=True

	// Switch signer to KID mode now that we have the account URL
	$signer.setKid($vt_accountUrl)

	This._logger.info("Account registered/confirmed"; New object("accountUrl"; $vt_accountUrl))

	$result.success:=True
	$result.accountUrl:=$vt_accountUrl
	return $result
