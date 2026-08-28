// ----------------------------------------------------
// Class: ACMEConfig
// Configuration container for the ACME / Let's Encrypt component.
// All site-specific settings live here; nothing is hard-coded elsewhere.
// Provides a fluent setter API — every setter returns This so calls can
// be chained: cs.ACMEConfig.new().setEmail("admin@example.com").setStaging(True)
//
// Defaults to the Let's Encrypt STAGING directory so accidental runs
// during development never consume production rate-limit quota.
//
// Usage (host application):
//   var $cfg : cs.ACMEConfig
//   $cfg:=cs.ACMEConfig.new()
//   $cfg.setEmail("admin@example.com")
//   $cfg.addIdentifier("myhost.example.com")
//   $cfg.setCertPath("/etc/ssl/acme/cert.pem")
//   $cfg.setKeyPath("/etc/ssl/acme/key.pem")
//   $cfg.setStaging(False)  // only when ready for production
//   var $client : cs.ACMEClient
//   $client:=cs.ACMEClient.new($cfg)
// ----------------------------------------------------

// ACME directory endpoint
property directoryUrl : Text

// Contact e-mail registered with the CA (mailto: URI assembled internally)
property contactEmail : Text

// Domain names to include in the certificate (first entry = CN)
property identifiers : Collection

// Filesystem paths for the issued certificate chain (PEM) and private key (PEM).
// The host web server reads these directly. Keys are NEVER logged.
property certPath : Text
property keyPath : Text

// Filesystem path where the account key pair and registration state are persisted.
// Defaults to a subfolder next to certPath when left blank.
property storePath : Text

// Challenge publish strategy: "webserver" | "webroot" | "listener"
//   webserver — register handler with 4D web server (needs port 80 on this process)
//   webroot   — write token file to a directory already served on port 80
//   listener  — bind a temporary minimal HTTP listener on port 80 for the window
property challengeStrategy : Text

// Only used when challengeStrategy = "webroot"
property webrootPath : Text

// Post-renewal action: "restart" | "none"
//   restart — WEB STOP SERVER / WEB START SERVER (brief connection drop, reloads cert)
//   none    — no automatic action; host application handles reload via postRenewFormula
property postRenewAction : Text

// Optional Formula called after a successful renewal (receives result object).
// Ignored when postRenewAction = "restart".
property postRenewFormula : 4D:C1709.Function

// When True, uses the LE staging directory and does not produce trusted certs.
// Set to False only when ready for production issuance.
property staging : Boolean

// Request timeout in seconds for ACME HTTP calls
property timeout : Integer

// Maximum number of polling attempts when waiting for order/challenge status
property maxPollAttempts : Integer

// Seconds between polling attempts
property pollIntervalSecs : Integer

// Let's Encrypt directory URLs
property _urlStaging : Text
property _urlProduction : Text


Class constructor
	
	This:C1470._urlStaging:="https://acme-staging-v02.api.letsencrypt.org/directory"
	This:C1470._urlProduction:="https://acme-v02.api.letsencrypt.org/directory"
	
	// Staging is the safe default — must explicitly opt in to production
	This:C1470.staging:=True:C214
	This:C1470.directoryUrl:=This:C1470._urlStaging
	
	This:C1470.contactEmail:=""
	This:C1470.identifiers:=New collection:C1472
	This:C1470.certPath:=""
	This:C1470.keyPath:=""
	This:C1470.storePath:=""
	This:C1470.challengeStrategy:="webserver"
	This:C1470.webrootPath:=""
	This:C1470.postRenewAction:="restart"
	This:C1470.postRenewFormula:=Null:C1517
	This:C1470.timeout:=30
	This:C1470.maxPollAttempts:=20
	This:C1470.pollIntervalSecs:=5
	
	
	// ============================================================
	// FLUENT SETTERS
	// ============================================================
	
Function setEmail($email : Text) : cs:C1710.ACMEConfig
	// Set the contact e-mail address registered with the CA.
	This:C1470.contactEmail:=$email
	return This:C1470
	
	
Function addIdentifier($hostname : Text) : cs:C1710.ACMEConfig
	// Add a hostname to the list of identifiers for this certificate.
	// The first identifier becomes the certificate Common Name.
	This:C1470.identifiers.push($hostname)
	return This:C1470
	
	
Function setIdentifiers($hostnames : Collection) : cs:C1710.ACMEConfig
	// Replace the entire identifiers list.
	This:C1470.identifiers:=$hostnames
	return This:C1470
	
	
Function setCertPath($path : Text) : cs:C1710.ACMEConfig
	// Path where the PEM certificate chain will be written after issuance.
	This:C1470.certPath:=$path
	return This:C1470
	
	
Function setKeyPath($path : Text) : cs:C1710.ACMEConfig
	// Path where the private key PEM will be written. NEVER log this path's contents.
	This:C1470.keyPath:=$path
	return This:C1470
	
	
Function setStorePath($path : Text) : cs:C1710.ACMEConfig
	// Path to the directory used for account key and order state persistence.
	This:C1470.storePath:=$path
	return This:C1470
	
	
Function setChallengeStrategy($strategy : Text) : cs:C1710.ACMEConfig
	// "webserver" | "webroot" | "listener" — see class header.
	This:C1470.challengeStrategy:=$strategy
	return This:C1470
	
	
Function setWebrootPath($path : Text) : cs:C1710.ACMEConfig
	// Directory from which a port-80 web server already serves files.
	// Required when challengeStrategy = "webroot".
	This:C1470.webrootPath:=$path
	return This:C1470
	
	
Function setPostRenewAction($action : Text) : cs:C1710.ACMEConfig
	// "restart" (default) or "none".
	This:C1470.postRenewAction:=$action
	return This:C1470
	
	
Function setPostRenewFormula($formula : 4D:C1709.Function) : cs:C1710.ACMEConfig
	// Formula called after successful renewal when postRenewAction = "none".
	This:C1470.postRenewFormula:=$formula
	return This:C1470
	
	
Function setStaging($isStaging : Boolean) : cs:C1710.ACMEConfig
	// Pass False to target the production Let's Encrypt endpoint.
	// Staging is the default; switching to production should be deliberate.
	This:C1470.staging:=$isStaging
	If ($isStaging)
		This:C1470.directoryUrl:=This:C1470._urlStaging
	Else 
		This:C1470.directoryUrl:=This:C1470._urlProduction
	End if 
	return This:C1470
	
	
Function setDirectoryUrl($url : Text) : cs:C1710.ACMEConfig
	// Override with a custom ACME directory URL (e.g. a local Pebble instance).
	This:C1470.directoryUrl:=$url
	return This:C1470
	
	
Function setTimeout($seconds : Integer) : cs:C1710.ACMEConfig
	This:C1470.timeout:=$seconds
	return This:C1470
	
	
Function setPollIntervalSecs($seconds : Integer) : cs:C1710.ACMEConfig
	This:C1470.pollIntervalSecs:=$seconds
	return This:C1470
	
	
Function setMaxPollAttempts($attempts : Integer) : cs:C1710.ACMEConfig
	This:C1470.maxPollAttempts:=$attempts
	return This:C1470
	
	
	// ============================================================
	// VALIDATION
	// ============================================================
	
Function isValid() : Boolean
	// Quick sanity-check before attempting any ACME calls.
	If (Length:C16(This:C1470.contactEmail)=0)
		return False:C215
	End if 
	If (This:C1470.identifiers.length=0)
		return False:C215
	End if 
	If (Length:C16(This:C1470.certPath)=0)
		return False:C215
	End if 
	If (Length:C16(This:C1470.keyPath)=0)
		return False:C215
	End if 
	return True:C214
	
	
Function validationError() : Text
	// Human-readable description of the first config problem found.
	If (Length:C16(This:C1470.contactEmail)=0)
		return "contactEmail is required"
	End if 
	If (This:C1470.identifiers.length=0)
		return "at least one identifier (hostname) is required"
	End if 
	If (Length:C16(This:C1470.certPath)=0)
		return "certPath is required"
	End if 
	If (Length:C16(This:C1470.keyPath)=0)
		return "keyPath is required"
	End if 
	return ""
	
	
Function effectiveStorePath() : Text
	// Returns storePath; if blank, derives a sensible default alongside certPath.
	If (Length:C16(This:C1470.storePath)>0)
		return This:C1470.storePath
	End if 
	// Derive from certPath parent directory
	var $vf : 4D:C1709.File
	$vf:=File:C1566(This:C1470.certPath; fk platform path:K87:2)
	return $vf.parent.platformPath+"acme-state"+Folder separator:K24:12
	