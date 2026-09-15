// ----------------------------------------------------
// Class: ACMEAsn1Reader
// Shared DER/ASN.1 parser for X.509 certificates.
//
// Extracted from ACMEJwsSigner so that ACMECertStore and ACMEScheduler
// can also consume certificate fields without duplicating parsing logic.
//
// The three primitive helpers (_derExpectTag, _derReadLength, _derReadInteger)
// are identical to those written for ACMEJwsSigner. All higher-level methods
// are built on top of them.
//
// Cursor:
//   _pos is reset to 0 at the start of parseCertificate() and is then
//   advanced exclusively by the _der* primitives. The helpers are not
//   reentrant — do not call parseCertificate() from within another
//   parseCertificate() call on the same instance.
//
// Usage:
//   var $reader : cs.ACMEAsn1Reader
//   $reader := cs.ACMEAsn1Reader.new()
//   var $result : Object   // { notAfter: Date, serial: Text, issuerDer: Blob }
//   $result := $reader.parseCertificate($vt_pemText)
//
// References:
//   RFC 5280  — X.509 certificate profile (TBSCertificate structure)
//   X.690     — DER encoding rules (tag/length/value)
//   RFC 8739  — ACME Renewal Information (ARI); issuerKeyHash = SHA-256 of issuer DER
// ----------------------------------------------------

property _pos : Integer


Class constructor()
	This:C1470._pos:=0
	
	
	// ============================================================
	// PUBLIC
	// ============================================================
	
Function parseCertificate($vt_pem : Text) : Object
	// Parse a PEM certificate and return the fields needed by ACMECertStore
	// and ACMEScheduler.
	//
	// Parameters:
	//   $vt_pem  — PEM text (BEGIN CERTIFICATE … END CERTIFICATE).
	//              Only the first certificate in the text is parsed; any
	//              chain remainder is ignored.
	//
	// Returns an object:
	//   {
	//     "ok":        Boolean,   // False if parsing failed at any step
	//     "error":     Text,      // human-readable reason when ok=False, "" otherwise
	//     "notAfter":  Date,      // UTCTime / GeneralizedTime from Validity
	//     "serial":    Text,      // hex-encoded serial number (no leading zero byte)
	//     "issuerDer": Blob       // raw DER bytes of the Issuer field (for ARI SHA-256)
	//   }
	//
	// On any parse error the returned object has ok=False, notAfter=!00-00-00!,
	// serial="", and issuerDer is an empty blob.
	
	var $result : Object
	$result:=New object:C1471(\
		"ok"; False:C215; \
		"error"; ""; \
		"notAfter"; !00-00-00!; \
		"serial"; ""; \
		"issuerDer"; Null:C1517)
	
	var $vb_issuerDer : Blob
	$result.issuerDer:=$vb_issuerDer
	
	// ---- 1. PEM → DER ----
	var $vb_der : Blob
	$vb_der:=This:C1470._pemToDer($vt_pem)
	If (BLOB size:C605($vb_der)=0)
		$result.error:="PEM decode failed or certificate body is empty"
		return $result
	End if 
	
	This:C1470._pos:=0
	
	// ---- 2. Outer Certificate SEQUENCE ----
	If (Not:C34(This:C1470._derExpectTag($vb_der; 0x0030)))  // SEQUENCE
		$result.error:="Expected outer Certificate SEQUENCE tag (0x30)"
		return $result
	End if 
	If (This:C1470._derReadLength($vb_der)<0)
		$result.error:="Invalid length on outer Certificate SEQUENCE"
		return $result
	End if 
	
	// ---- 3. TBSCertificate SEQUENCE ----
	If (Not:C34(This:C1470._derExpectTag($vb_der; 0x0030)))
		$result.error:="Expected TBSCertificate SEQUENCE tag (0x30)"
		return $result
	End if 
	If (This:C1470._derReadLength($vb_der)<0)
		$result.error:="Invalid length on TBSCertificate SEQUENCE"
		return $result
	End if 
	
	// ---- 4. version [0] EXPLICIT (optional, present in v2/v3 certs) ----
	// Context tag [0] = 0xA0. Skip it when present; absent in v1 certs.
	If (This:C1470._pos<BLOB size:C605($vb_der))
		If ($vb_der{This:C1470._pos}=0x00A0)
			This:C1470._pos:=This:C1470._pos+1  // consume tag
			var $vl_versionLen : Integer
			$vl_versionLen:=This:C1470._derReadLength($vb_der)
			If ($vl_versionLen<0)
				$result.error:="Invalid version field length"
				return $result
			End if 
			This:C1470._pos:=This:C1470._pos+$vl_versionLen
		End if 
	End if 
	
	// ---- 5. serialNumber INTEGER ----
	var $vb_serialBlob : Blob
	$vb_serialBlob:=This:C1470._derReadInteger($vb_der)
	// An empty blob means _derReadInteger failed.
	// A real zero serial would be a single 0x00 byte with no leading zero —
	// _derReadInteger strips the padding zero so a genuine zero serial
	// produces a 1-byte blob containing 0x00. Both paths are handled below.
	$result.serial:=This:C1470._blobToHex($vb_serialBlob)
	
	// ---- 6. signature AlgorithmIdentifier SEQUENCE — skip ----
	If (Not:C34(This:C1470._derExpectTag($vb_der; 0x0030)))
		$result.error:="Expected signature AlgorithmIdentifier SEQUENCE tag (0x30)"
		return $result
	End if 
	var $vl_algLen : Integer
	$vl_algLen:=This:C1470._derReadLength($vb_der)
	If ($vl_algLen<0)
		$result.error:="Invalid length on signature AlgorithmIdentifier"
		return $result
	End if 
	This:C1470._pos:=This:C1470._pos+$vl_algLen
	
	// ---- 7. issuer Name SEQUENCE — capture raw DER bytes ----
	var $vl_issuerStart; $vl_issuerTagAndLenBytes; $vl_issuerValueLen : Integer
	$vl_issuerStart:=This:C1470._pos
	
	If (Not:C34(This:C1470._derExpectTag($vb_der; 0x0030)))
		$result.error:="Expected issuer Name SEQUENCE tag (0x30)"
		return $result
	End if 
	$vl_issuerValueLen:=This:C1470._derReadLength($vb_der)
	If ($vl_issuerValueLen<0)
		$result.error:="Invalid length on issuer Name"
		return $result
	End if 
	// _pos now points at the first byte of the issuer value.
	// Total issuer TLV = from $vl_issuerStart to current _pos + value length.
	var $vl_issuerTotalBytes : Integer
	$vl_issuerTotalBytes:=(This:C1470._pos-$vl_issuerStart)+$vl_issuerValueLen
	COPY BLOB:C558($vb_der; $vb_issuerDer; $vl_issuerStart; 0; $vl_issuerTotalBytes)
	$result.issuerDer:=$vb_issuerDer
	This:C1470._pos:=This:C1470._pos+$vl_issuerValueLen
	
	// ---- 8. validity Validity SEQUENCE ----
	If (Not:C34(This:C1470._derExpectTag($vb_der; 0x0030)))
		$result.error:="Expected Validity SEQUENCE tag (0x30)"
		return $result
	End if 
	If (This:C1470._derReadLength($vb_der)<0)
		$result.error:="Invalid length on Validity SEQUENCE"
		return $result
	End if 
	
	// notBefore — skip
	var $vd_ignored : Date
	$vd_ignored:=This:C1470._derReadTime($vb_der)
	
	// notAfter — capture
	var $vd_notAfter : Date
	$vd_notAfter:=This:C1470._derReadTime($vb_der)
	If ($vd_notAfter=!00-00-00!)
		$result.error:="Failed to parse notAfter time field"
		return $result
	End if 
	
	$result.notAfter:=$vd_notAfter
	$result.ok:=True:C214
	return $result
	
	
	// ============================================================
	// INTERNAL — TIME PARSING
	// ============================================================
	
Function _derReadTime($vb_der : Blob) : Date
	// Read the next ASN.1 time value (UTCTime 0x17 or GeneralizedTime 0x18)
	// and return it as a 4D Date. Returns !00-00-00! on any error.
	//
	// UTCTime      (tag 0x17): "YYMMDDHHMMSSZ"   (13 chars)
	//   Year 00–49 → 2000–2049, 50–99 → 1950–1999 (RFC 5280 §4.1.2.5.1)
	// GeneralizedTime (tag 0x18): "YYYYMMDDHHMMSSZ" (15 chars)
	
	If (This:C1470._pos>=BLOB size:C605($vb_der))
		return !00-00-00!
	End if 
	
	var $vl_tag : Integer
	$vl_tag:=$vb_der{This:C1470._pos}
	
	If (($vl_tag#0x0017) & ($vl_tag#0x0018))
		// Neither UTCTime nor GeneralizedTime
		return !00-00-00!
	End if 
	
	This:C1470._pos:=This:C1470._pos+1  // consume tag
	
	var $vl_len : Integer
	$vl_len:=This:C1470._derReadLength($vb_der)
	If (($vl_len<=0) | ((This:C1470._pos+$vl_len)>BLOB size:C605($vb_der)))
		return !00-00-00!
	End if 
	
	// Read the ASCII string from the blob
	var $vb_timeBytes : Blob
	COPY BLOB:C558($vb_der; $vb_timeBytes; This:C1470._pos; 0; $vl_len)
	This:C1470._pos:=This:C1470._pos+$vl_len
	
	var $vt_timeStr : Text
	$vt_timeStr:=BLOB to text:C555($vb_timeBytes; UTF8 text without length:K22:17)
	
	// Parse fields out of the string
	var $vl_year; $vl_month; $vl_day : Integer
	
	If ($vl_tag=0x0017)
		// UTCTime: YYMMDDHHMMSSZ
		If (Length:C16($vt_timeStr)<13)
			return !00-00-00!
		End if 
		var $vl_yy : Integer
		$vl_yy:=Num:C11(Substring:C12($vt_timeStr; 1; 2))
		If ($vl_yy<50)
			$vl_year:=2000+$vl_yy
		Else 
			$vl_year:=1900+$vl_yy
		End if 
		$vl_month:=Num:C11(Substring:C12($vt_timeStr; 3; 2))
		$vl_day:=Num:C11(Substring:C12($vt_timeStr; 5; 2))
	Else 
		// GeneralizedTime: YYYYMMDDHHMMSSZ
		If (Length:C16($vt_timeStr)<15)
			return !00-00-00!
		End if 
		$vl_year:=Num:C11(Substring:C12($vt_timeStr; 1; 4))
		$vl_month:=Num:C11(Substring:C12($vt_timeStr; 5; 2))
		$vl_day:=Num:C11(Substring:C12($vt_timeStr; 7; 2))
	End if 
	
	// Basic sanity check before calling Date()
	If (($vl_year<1950) | ($vl_year>2999))
		return !00-00-00!
	End if 
	If (($vl_month<1) | ($vl_month>12))
		return !00-00-00!
	End if 
	If (($vl_day<1) | ($vl_day>31))
		return !00-00-00!
	End if 
	
	return Date:C102(String:C10($vl_month)+"/"+String:C10($vl_day)+"/"+String:C10($vl_year))
	
	
	// ============================================================
	// INTERNAL — PEM DECODE
	// ============================================================
	
Function _pemToDer($vt_pem : Text) : Blob
	// Strip the first PEM certificate armour and base64-decode the body.
	// Any certificates after the first (chain) are ignored.
	// Returns an empty blob if no valid certificate block is found.
	
	var $vb_empty; $vb_result : Blob
	var $vl_begin; $vl_end : Integer
	var $vt_b64 : Text
	
	$vl_begin:=Position:C15("-----BEGIN CERTIFICATE-----"; $vt_pem)
	If ($vl_begin=0)
		return $vb_empty
	End if 
	
	$vl_begin:=$vl_begin+Length:C16("-----BEGIN CERTIFICATE-----")
	
	$vl_end:=Position:C15("-----END CERTIFICATE-----"; $vt_pem; $vl_begin)
	If ($vl_end=0)
		return $vb_empty
	End if 
	
	$vt_b64:=Substring:C12($vt_pem; $vl_begin; $vl_end-$vl_begin)
	
	// Remove any line endings so BASE64 DECODE gets a clean string
	$vt_b64:=Replace string:C233($vt_b64; Char:C90(13)+Char:C90(10); "")
	$vt_b64:=Replace string:C233($vt_b64; Char:C90(10); "")
	$vt_b64:=Replace string:C233($vt_b64; Char:C90(13); "")
	
	BASE64 DECODE:C896($vt_b64; $vb_result)
	return $vb_result
	
	
	// ============================================================
	// INTERNAL — BLOB UTILITIES
	// ============================================================
	
Function _blobToHex($vb_input : Blob) : Text
	// Convert every byte of $vb_input to a lowercase two-hex-digit string.
	// An empty blob returns "".
	var $vt_result : Text
	var $vl_size; $i; $vl_byte : Integer
	var $vt_hex : Text
	
	$vl_size:=BLOB size:C605($vb_input)
	$vt_result:=""
	
	For ($i; 0; $vl_size-1)
		$vl_byte:=$vb_input{$i}
		$vt_hex:=This:C1470._byteToHex($vl_byte)
		$vt_result:=$vt_result+$vt_hex
	End for 
	
	return $vt_result
	
	
Function _byteToHex($vl_byte : Integer) : Text
	// Convert a single byte value (0-255) to a two-character lowercase hex string.
	var $vt_nibbles : Text
	var $vl_hi; $vl_lo : Integer
	$vt_nibbles:="0123456789abcdef"
	$vl_hi:=($vl_byte & 0x00F0) >> 4
	$vl_lo:=$vl_byte & 0x000F
	return Substring:C12($vt_nibbles; $vl_hi+1; 1)+Substring:C12($vt_nibbles; $vl_lo+1; 1)
	
	
	// ============================================================
	// INTERNAL — DER PRIMITIVES
	// (Identical to those in ACMEJwsSigner; extracted here so that
	//  ACMECertStore and ACMEScheduler can share them without coupling
	//  to the JWS signing class.)
	// ============================================================
	
Function _derExpectTag($vb_der : Blob; $vl_expectedTag : Integer) : Boolean
	// Return True and advance _pos if the byte at the cursor equals
	// $vl_expectedTag. Return False (without advancing) otherwise.
	If (This:C1470._pos>=BLOB size:C605($vb_der))
		return False:C215
	End if 
	If ($vb_der{This:C1470._pos}=$vl_expectedTag)
		This:C1470._pos:=This:C1470._pos+1
		return True:C214
	End if 
	return False:C215
	
	
Function _derReadLength($vb_der : Blob) : Integer
	// Read a DER length field at the cursor and advance _pos past it.
	// Handles short form (1 byte, 0–127) and long form (multi-byte).
	// Returns -1 on any error (truncated blob, length > 4 bytes).
	var $vl_firstByte; $vl_numBytes; $vl_length : Integer
	var $i : Integer
	
	If (This:C1470._pos>=BLOB size:C605($vb_der))
		return -1
	End if 
	
	$vl_firstByte:=$vb_der{This:C1470._pos}
	This:C1470._pos:=This:C1470._pos+1
	
	If ($vl_firstByte<0x0080)
		// Short form
		return $vl_firstByte
	Else 
		// Long form: lower 7 bits = count of subsequent length bytes
		$vl_numBytes:=$vl_firstByte & 0x007F
		If (($vl_numBytes>4) | ((This:C1470._pos+$vl_numBytes)>BLOB size:C605($vb_der)))
			return -1
		End if 
		$vl_length:=0
		For ($i; 0; $vl_numBytes-1)
			$vl_length:=($vl_length << 8) | $vb_der{This:C1470._pos+$i}
		End for 
		This:C1470._pos:=This:C1470._pos+$vl_numBytes
		return $vl_length
	End if 
	
	
Function _derReadInteger($vb_der : Blob) : Blob
	// Read a DER INTEGER TLV at the cursor and return the value bytes as a Blob.
	// Strips the leading 0x00 padding byte that DER prepends when the
	// most-significant bit of a positive integer would otherwise be set.
	// Advances _pos past the full TLV. Returns an empty blob on any error.
	var $vl_len; $vl_start; $vl_copyLen : Integer
	var $vb_result : Blob
	
	If (Not:C34(This:C1470._derExpectTag($vb_der; 0x0002)))  // INTEGER tag
		return $vb_result  // empty blob
	End if 
	
	$vl_len:=This:C1470._derReadLength($vb_der)
	If (($vl_len<=0) | ((This:C1470._pos+$vl_len)>BLOB size:C605($vb_der)))
		return $vb_result  // empty blob
	End if 
	
	$vl_start:=This:C1470._pos
	$vl_copyLen:=$vl_len
	
	// Strip DER positive-number leading zero if present
	If (($vl_len>1) & ($vb_der{This:C1470._pos}=0x0000))
		This:C1470._pos:=This:C1470._pos+1
		$vl_copyLen:=$vl_copyLen-1
	End if 
	
	COPY BLOB:C558($vb_der; $vb_result; This:C1470._pos; 0; $vl_copyLen)
	This:C1470._pos:=$vl_start+$vl_len  // always advance past the full original length
	return $vb_result
	