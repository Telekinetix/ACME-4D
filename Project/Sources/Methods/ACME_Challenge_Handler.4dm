//%attributes = {"shared":true}
// ----------------------------------------------------
// Method: ACME_Challenge_Handler
// URL handler helper for the "webserver" HTTP-01 challenge strategy.
//
// The host application should route /.well-known/acme-challenge/* requests
// to this method from its On Web Connection database method, or register it
// as a URL handler via 4D.WebHandler if available.
//
// The method reads the request URL from the current web request context
// and serves the keyAuthorization from Storage if a challenge is active.
//
// Usage in On Web Connection:
//   If (Match regex("^\/.well-known\/acme-challenge\/"; $1; 1; $pos; $len))
//     ACME_Challenge_Handler
//     return
//   End if
//
// The client instance reference must be available. In the simplest case,
// check Storage directly (see ACMEChallenge._publishViaWebServer).
// ----------------------------------------------------
//%attributes = {}

#DECLARE($vt_url : Text)

var $vt_keyAuth : Text
var $vt_token : Text
var $vl_pos : Integer

// Extract token from /.well-known/acme-challenge/<token>
$vl_pos:=Position:C15("/.well-known/acme-challenge/"; $vt_url)
If ($vl_pos=0)
	WEB SEND HTTP REDIRECT:C659("/")
	return 
End if 

$vt_token:=Substring:C12($vt_url; $vl_pos+Length:C16("/.well-known/acme-challenge/"))
// Strip query string if present
var $vl_qpos : Integer
$vl_qpos:=Position:C15("?"; $vt_token)
If ($vl_qpos>0)
	$vt_token:=Substring:C12($vt_token; 1; $vl_qpos-1)
End if 

// Look up keyAuthorization from Storage
$vt_keyAuth:=""
If (OB Is defined:C1231(Storage:C1525; "acme")) && (OB Is defined:C1231(Storage:C1525.acme; "challenges"))
	$vt_keyAuth:=String:C10(Storage:C1525.acme.challenges[$vt_token])
End if 

If (Length:C16($vt_keyAuth)>0)
	WEB SEND TEXT:C677($vt_keyAuth; "text/plain")
Else 
	// Challenge not found — return 404
	WEB SEND HTTP REDIRECT:C659("/")
End if 
