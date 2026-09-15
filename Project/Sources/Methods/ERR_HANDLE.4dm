//%attributes = {}

#DECLARE($vt_case : Text)

var vl_acmeError : Integer
var vt_acmeError : Text

Case of 
	: ($vt_case="set")
		vl_acmeError:=0
		vt_acmeError:=""
		
		ON ERR CALL:C155("ACME_Error")
		
	: ($vt_case="clear")
		ON ERR CALL:C155("")
		
End case 
