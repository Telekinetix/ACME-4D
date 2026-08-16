//%attributes = {}
// ----------------------------------------------------
// Method: ACME_HTTP_Error
// ON ERR CALL handler for 4D.HTTPRequest calls inside the ACME component.
// Captures the 4D-level network / DNS / SSL / timeout error into the
// process variables vl_acmeHttpError / vt_acmeHttpError so the calling
// ACMETransport method can inspect them and build a standard result.
// Never logs credentials or tokens.
// ----------------------------------------------------
var vl_acmeHttpError : Integer
var vt_acmeHttpError : Text
vl_acmeHttpError:=Error
vt_acmeHttpError:=Error method+" Line: "+String(Error line)+" "+Error formula
