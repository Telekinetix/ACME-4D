// ----------------------------------------------------
// Class: ACMEConfig
// Configuration container for the ACME / Let's Encrypt component.
// All site-specific settings live here; nothing is hard-coded elsewhere.
// Provides a fluent setter API — every setter returns This so calls can
// be chained: cs.acme.ACMEConfig.new().setEmail("admin@example.com").setStaging(True)
//
// Defaults to the Let's Encrypt STAGING directory so accidental runs
// during development never consume production rate-limit quota.
//
// Usage (host application):
//   var $cfg : cs.acme.ACMEConfig
//   $cfg:=cs.acme.ACMEConfig.new()
//   $cfg.setEmail("admin@example.com")
//   $cfg.addIdentifier("myhost.example.com")
//   $cfg.setCertPath("/etc/ssl/acme/cert.pem")
//   $cfg.setKeyPath("/etc/ssl/acme/key.pem")
//   $cfg.setStaging(False)  // only when ready for production
//   var $client : cs.acme.ACMEClient
//   $client:=cs.acme.ACMEClient.new($cfg)
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
property postRenewFormula : 4D.Function

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

	This._urlStaging:="https://acme-staging-v02.api.letsencrypt.org/directory"
	This._urlProduction:="https://acme-v02.api.letsencrypt.org/directory"

	// Staging is the safe default — must explicitly opt in to production
	This.staging:=True
	This.directoryUrl:=This._urlStaging

	This.contactEmail:=""
	This.identifiers:=New collection
	This.certPath:=""
	This.keyPath:=""
	This.storePath:=""
	This.challengeStrategy:="webserver"
	This.webrootPath:=""
	This.postRenewAction:="restart"
	This.postRenewFormula:=Null
	This.timeout:=30
	This.maxPollAttempts:=20
	This.pollIntervalSecs:=5


// ============================================================
// FLUENT SETTERS
// ============================================================

Function setEmail($email : Text) : cs.acme.ACMEConfig
	// Set the contact e-mail address registered with the CA.
	This.contactEmail:=$email
	return This


Function addIdentifier($hostname : Text) : cs.acme.ACMEConfig
	// Add a hostname to the list of identifiers for this certificate.
	// The first identifier becomes the certificate Common Name.
	This.identifiers.push($hostname)
	return This


Function setIdentifiers($hostnames : Collection) : cs.acme.ACMEConfig
	// Replace the entire identifiers list.
	This.identifiers:=$hostnames
	return This


Function setCertPath($path : Text) : cs.acme.ACMEConfig
	// Path where the PEM certificate chain will be written after issuance.
	This.certPath:=$path
	return This


Function setKeyPath($path : Text) : cs.acme.ACMEConfig
	// Path where the private key PEM will be written. NEVER log this path's contents.
	This.keyPath:=$path
	return This


Function setStorePath($path : Text) : cs.acme.ACMEConfig
	// Path to the directory used for account key and order state persistence.
	This.storePath:=$path
	return This


Function setChallengeStrategy($strategy : Text) : cs.acme.ACMEConfig
	// "webserver" | "webroot" | "listener" — see class header.
	This.challengeStrategy:=$strategy
	return This


Function setWebrootPath($path : Text) : cs.acme.ACMEConfig
	// Directory from which a port-80 web server already serves files.
	// Required when challengeStrategy = "webroot".
	This.webrootPath:=$path
	return This


Function setPostRenewAction($action : Text) : cs.acme.ACMEConfig
	// "restart" (default) or "none".
	This.postRenewAction:=$action
	return This


Function setPostRenewFormula($formula : 4D.Function) : cs.acme.ACMEConfig
	// Formula called after successful renewal when postRenewAction = "none".
	This.postRenewFormula:=$formula
	return This


Function setStaging($isStaging : Boolean) : cs.acme.ACMEConfig
	// Pass False to target the production Let's Encrypt endpoint.
	// Staging is the default; switching to production should be deliberate.
	This.staging:=$isStaging
	If ($isStaging)
		This.directoryUrl:=This._urlStaging
	Else
		This.directoryUrl:=This._urlProduction
	End if
	return This


Function setDirectoryUrl($url : Text) : cs.acme.ACMEConfig
	// Override with a custom ACME directory URL (e.g. a local Pebble instance).
	This.directoryUrl:=$url
	return This


Function setTimeout($seconds : Integer) : cs.acme.ACMEConfig
	This.timeout:=$seconds
	return This


Function setPollIntervalSecs($seconds : Integer) : cs.acme.ACMEConfig
	This.pollIntervalSecs:=$seconds
	return This


Function setMaxPollAttempts($attempts : Integer) : cs.acme.ACMEConfig
	This.maxPollAttempts:=$attempts
	return This


// ============================================================
// VALIDATION
// ============================================================

Function isValid() : Boolean
	// Quick sanity-check before attempting any ACME calls.
	If (Length(This.contactEmail)=0)
		return False
	End if
	If (This.identifiers.length=0)
		return False
	End if
	If (Length(This.certPath)=0)
		return False
	End if
	If (Length(This.keyPath)=0)
		return False
	End if
	return True


Function validationError() : Text
	// Human-readable description of the first config problem found.
	If (Length(This.contactEmail)=0)
		return "contactEmail is required"
	End if
	If (This.identifiers.length=0)
		return "at least one identifier (hostname) is required"
	End if
	If (Length(This.certPath)=0)
		return "certPath is required"
	End if
	If (Length(This.keyPath)=0)
		return "keyPath is required"
	End if
	return ""


Function effectiveStorePath() : Text
	// Returns storePath; if blank, derives a sensible default alongside certPath.
	If (Length(This.storePath)>0)
		return This.storePath
	End if
	// Derive from certPath parent directory
	var $vf : 4D.File
	$vf:=File(This.certPath)
	return $vf.parent.platformPath+"acme-state"+Folder separator
