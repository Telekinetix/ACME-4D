// ----------------------------------------------------
// Class: ACMECsr
// PKCS#10 Certification Signing Request builder for the ACME component.
//
// Spike 7.1 (from kickoff brief): 4D.CryptoKey does NOT expose a native
// PKCS#10 CSR generator as of v20.0. This class implements the DER encoding
// by hand in 4D — the preferred zero-dependency approach (option b in §7.1).
//
// The CSR DER structure built here (for a single hostname):
//
//   CertificationRequest ::= SEQUENCE {
//     certificationRequestInfo  CertificationRequestInfo,
//     signatureAlgorithm        AlgorithmIdentifier,
//     signature                 BIT STRING
//   }
//
//   CertificationRequestInfo ::= SEQUENCE {
//     version       INTEGER { v1(0) },
//     subject       Name (RDNSequence with CN = hostname),
//     subjectPKInfo SubjectPublicKeyInfo,
//     attributes    [0] IMPLICIT Attributes (containing extensionRequest
//                       with subjectAltName for the hostname)
//   }
//
// Algorithm: RS256 (sha256WithRSAEncryption OID 1.2.840.113549.1.1.11).
//
// The public key DER is extracted from the PEM-encoded public key produced
// by 4D.CryptoKey.getPublicKey().
//
// The ACME finalize endpoint expects the CSR as base64url(DER).
// ----------------------------------------------------

Class constructor
	
	
	// ============================================================
	// PUBLIC — BUILD CSR
	// ============================================================
	
Function build($vt_privateKeyPem : Text; $vt_hostname : Text) : Text
	// Build a PKCS#10 CSR DER for $vt_hostname, signed with $vt_privateKeyPem.
	// Returns the CSR as a base64url string (for the ACME finalize payload).
	// Returns "" on any error.
	
	// 1. Load the private key
	var $vo_cryptoKey : 4D:C1709.CryptoKey
	Try
		$vo_cryptoKey:=4D:C1709.CryptoKey.new(New object:C1471("type"; "PEM"; "pem"; $vt_privateKeyPem))
	Catch
		return ""
	End try
	
	// 2. Get the public key DER bytes (SubjectPublicKeyInfo from PEM)
	var $vb_spki : Blob
	$vb_spki:=This:C1470._publicKeyDerFromPem($vo_cryptoKey)
	If (BLOB size:C605($vb_spki)=0)
		return ""
	End if 
	
	// 3. Build the CertificationRequestInfo DER
	var $vb_cri : Blob
	$vb_cri:=This:C1470._buildCertificationRequestInfo($vt_hostname; $vb_spki)
	
	// 4. Sign the CertificationRequestInfo with RS256
	var $vo_signOpts : Object
	var $vt_criB64 : Text
	var $vb_signature : Blob
	$vo_signOpts:=New object:C1471("algorithm"; "RS256"; "encoding"; "Base64")
	
	// sign() works on text; encode CRI as base64 for input, then get raw bytes
	BASE64 ENCODE:C895($vb_cri; $vt_criB64; *)
	
	// For RS256 DER signing we need the raw signature bytes.
	// 4D.CryptoKey.sign() returns base64 or base64URL text.
	// We request base64 then decode back to a blob for DER wrapping.
	var $vt_sigB64 : Text
	$vt_sigB64:=This:C1470._signBlob($vo_cryptoKey; $vb_cri)
	If (Length:C16($vt_sigB64)=0)
		return ""
	End if 
	BASE64 DECODE:C896($vt_sigB64; $vb_signature)
	
	// 5. Wrap into the outer CertificationRequest SEQUENCE
	var $vb_csr : Blob
	$vb_csr:=This:C1470._buildCertificationRequest($vb_cri; $vb_signature)

	// 6. Base64url-encode the DER
	return This:C1470._base64urlBlob($vb_csr)
	
	
	// ============================================================
	// INTERNAL — DER BUILDING
	// ============================================================
	
Function _buildCertificationRequestInfo($vt_hostname : Text; $vb_spki : Blob) : Blob
	// SEQUENCE {
	//   INTEGER 0  (version v1)
	//   SEQUENCE { SET { SEQUENCE { OID commonName, UTF8String hostname } } }  (subject)
	//   SubjectPublicKeyInfo  (spki, already DER-encoded)
	//   [0] { extensionRequest attribute containing subjectAltName }
	// }
	
	// version: INTEGER 0
	var $vb_version : Blob
	$vb_version:=This:C1470._derInteger(0)
	
	// subject: CN=hostname
	var $vb_subject : Blob
	$vb_subject:=This:C1470._derSubjectCN($vt_hostname)
	
	// subjectPKInfo: already in DER as extracted from PEM
	var $vb_spkiCopy : Blob
	$vb_spkiCopy:=$vb_spki
	
	// attributes [0]: subjectAltName extension request
	var $vb_attrs : Blob
	$vb_attrs:=This:C1470._derExtensionRequestAttr($vt_hostname)
	
	// Concatenate and wrap in SEQUENCE
	var $vb_cri : Blob
	COPY BLOB:C558($vb_version; $vb_cri; 0; BLOB size:C605($vb_cri); BLOB size:C605($vb_version))
	COPY BLOB:C558($vb_subject; $vb_cri; 0; BLOB size:C605($vb_cri); BLOB size:C605($vb_subject))
	COPY BLOB:C558($vb_spkiCopy; $vb_cri; 0; BLOB size:C605($vb_cri); BLOB size:C605($vb_spkiCopy))
	COPY BLOB:C558($vb_attrs; $vb_cri; 0; BLOB size:C605($vb_cri); BLOB size:C605($vb_attrs))
	
	return This:C1470._derSequence($vb_cri)
	
	
Function _buildCertificationRequest($vb_cri : Blob; $vb_signature : Blob) : Blob
	// SEQUENCE {
	//   CertificationRequestInfo (already encoded)
	//   AlgorithmIdentifier { OID sha256WithRSAEncryption, NULL }
	//   BIT STRING { 0x00 || signature_bytes }
	// }
	
	// AlgorithmIdentifier for sha256WithRSAEncryption (OID 1.2.840.113549.1.1.11)
	var $vb_algId : Blob
	$vb_algId:=This:C1470._derAlgorithmIdentifierSha256WithRSA()
	
	// BIT STRING: one unused-bits byte (0x00) + signature bytes
	var $vb_bitStr : Blob
	INSERT IN BLOB:C559($vb_bitStr; 0; 1)
	$vb_bitStr{0}:=0x0000
	COPY BLOB:C558($vb_signature; $vb_bitStr; 0; BLOB size:C605($vb_bitStr); BLOB size:C605($vb_signature))
	var $vb_sigDer : Blob
	$vb_sigDer:=This:C1470._derTag($vb_bitStr; 0x0003)
	
	// Outer SEQUENCE
	var $vb_inner : Blob
	COPY BLOB:C558($vb_cri; $vb_inner; 0; BLOB size:C605($vb_inner); BLOB size:C605($vb_cri))
	COPY BLOB:C558($vb_algId; $vb_inner; 0; BLOB size:C605($vb_inner); BLOB size:C605($vb_algId))
	COPY BLOB:C558($vb_sigDer; $vb_inner; 0; BLOB size:C605($vb_inner); BLOB size:C605($vb_sigDer))
	
	return This:C1470._derSequence($vb_inner)
	
	
	// ============================================================
	// INTERNAL — DER PRIMITIVES
	// ============================================================
	
Function _derTLV($vl_tag : Integer; $vb_value : Blob) : Blob
	// Build a DER TLV: tag byte + length encoding + value bytes.
	var $vb_tlv : Blob
	var $vl_len : Integer
	$vl_len:=BLOB size:C605($vb_value)
	
	INSERT IN BLOB:C559($vb_tlv; 0; 1)
	$vb_tlv{0}:=$vl_tag
	
	// Length encoding
	
	Case of 
		: ($vl_len<0x0080)
			INSERT IN BLOB:C559($vb_tlv; BLOB size:C605($vb_tlv); 1)
			$vb_tlv{BLOB size:C605($vb_tlv)-1}:=$vl_len
		: ($vl_len<=0x00FF)
			INSERT IN BLOB:C559($vb_tlv; BLOB size:C605($vb_tlv); 2)
			$vb_tlv{BLOB size:C605($vb_tlv)-2}:=0x0081
			$vb_tlv{BLOB size:C605($vb_tlv)-1}:=$vl_len
		: ($vl_len<=0xFFFF)
			INSERT IN BLOB:C559($vb_tlv; BLOB size:C605($vb_tlv); 3)
			$vb_tlv{BLOB size:C605($vb_tlv)-3}:=0x0082
			$vb_tlv{BLOB size:C605($vb_tlv)-2}:=($vl_len >> 8) & 0x00FF
			$vb_tlv{BLOB size:C605($vb_tlv)-1}:=$vl_len & 0x00FF
	End case 
	
	// Append value bytes
	COPY BLOB:C558($vb_value; $vb_tlv; 0; BLOB size:C605($vb_tlv); BLOB size:C605($vb_value))
	return $vb_tlv
	
Function _derTag($vb_value : Blob; $vl_tag : Integer) : Blob
	return This:C1470._derTLV($vl_tag; $vb_value)
	
	
Function _derSequence($vb_content : Blob) : Blob
	return This:C1470._derTLV(0x0030; $vb_content)
	
	
Function _derSet($vb_content : Blob) : Blob
	return This:C1470._derTLV(0x0031; $vb_content)
	
	
Function _derInteger($vl_value : Integer) : Blob
	// Encode a small non-negative integer as DER INTEGER.
	var $vb_val : Blob
	INSERT IN BLOB:C559($vb_val; 0; 1)
	$vb_val{0}:=$vl_value & 0x00FF
	// Ensure positive (prepend 0x00 if high bit set)
	If ($vb_val{0}>=0x0080)
		var $vb_padded : Blob
		INSERT IN BLOB:C559($vb_padded; 0; 1)
		$vb_padded{0}:=0x0000
		COPY BLOB:C558($vb_val; $vb_padded; 0; BLOB size:C605($vb_padded); BLOB size:C605($vb_val))
		$vb_val:=$vb_padded
	End if 
	return This:C1470._derTLV(0x0002; $vb_val)
	
	
Function _derOctetString($vb_value : Blob) : Blob
	return This:C1470._derTLV(0x0004; $vb_value)
	
	
Function _derUtf8String($vt_value : Text) : Blob
	var $vb_value : Blob
	TEXT TO BLOB:C554($vt_value; $vb_value; UTF8 text without length:K22:17)
	return This:C1470._derTLV(0x000C; $vb_value)
	
	
Function _derIA5String($vt_value : Text) : Blob
	// IA5String (used in subjectAltName dNSName)
	var $vb_value : Blob
	TEXT TO BLOB:C554($vt_value; $vb_value; UTF8 text without length:K22:17)
	return This:C1470._derTLV(0x0016; $vb_value)
	
	
Function _derOid($vc_oid : Collection) : Blob
	// Encode an OID from its integer arc array, e.g. [1,2,840,113549,1,1,11]
	// First two arcs are combined: first_arc * 40 + second_arc
	var $vb_oid : Blob
	var $i; $vl_arc; $vl_first : Integer
	
	$vl_first:=$vc_oid[0]*40+$vc_oid[1]
	$vb_oid:=This:C1470._encodeBase128($vl_first)
	
	For ($i; 2; $vc_oid.length-1)
		$vl_arc:=$vc_oid[$i]
		var $vb_arc : Blob
		$vb_arc:=This:C1470._encodeBase128($vl_arc)
		COPY BLOB:C558($vb_arc; $vb_oid; 0; BLOB size:C605($vb_oid); BLOB size:C605($vb_arc))
	End for 
	
	return This:C1470._derTLV(0x0006; $vb_oid)
	
	
Function _encodeBase128($vl_value : Integer) : Blob
	// Encode a non-negative integer in base-128 (DER OID arc encoding).
	var $vb_result : Blob
	var $vl_work : Integer
	$vl_work:=$vl_value
	
	If ($vl_work=0)
		INSERT IN BLOB:C559($vb_result; 0; 1)
		$vb_result{0}:=0
		return $vb_result
	End if 
	
	// Build bytes from LSB to MSB, then reverse
	var $vc_bytes : Collection
	$vc_bytes:=New collection:C1472
	While ($vl_work>0)
		$vc_bytes.unshift($vl_work & 0x007F)
		$vl_work:=$vl_work >> 7
	End while 
	
	var $j : Integer
	For ($j; 0; $vc_bytes.length-1)
		INSERT IN BLOB:C559($vb_result; BLOB size:C605($vb_result); 1)
		If ($j<($vc_bytes.length-1))
			$vb_result{BLOB size:C605($vb_result)-1}:=($vc_bytes[$j] | 0x0080)
		Else 
			$vb_result{BLOB size:C605($vb_result)-1}:=$vc_bytes[$j]
		End if 
	End for 
	return $vb_result
	
	
Function _derSubjectCN($vt_cn : Text) : Blob
	// Build the subject Name: SEQUENCE { SET { SEQUENCE { OID-cn, UTF8String cn } } }
	// OID for commonName: 2.5.4.3
	var $vb_oidCN : Blob
	$vb_oidCN:=This._derOid(New collection(2; 5; 4; 3))
	
	var $vb_cnStr : Blob
	$vb_cnStr:=This._derUtf8String($vt_cn)
	
	// SEQUENCE { OID, UTF8String }
	var $vb_attrSeq : Blob
	COPY BLOB($vb_oidCN; $vb_attrSeq; 0; BLOB size($vb_attrSeq); BLOB size($vb_oidCN))
	COPY BLOB($vb_cnStr; $vb_attrSeq; 0; BLOB size($vb_attrSeq); BLOB size($vb_cnStr))
	var $vb_attrSeqWrapped : Blob
	$vb_attrSeqWrapped:=This._derSequence($vb_attrSeq)
	
	// SET { SEQUENCE {...} }
	var $vb_attrSet : Blob
	$vb_attrSet:=This._derSet($vb_attrSeqWrapped)
	
	// SEQUENCE { SET {...} }
	return This._derSequence($vb_attrSet)
	
	
Function _derAlgorithmIdentifierSha256WithRSA() : Blob
	// AlgorithmIdentifier { OID sha256WithRSAEncryption (1.2.840.113549.1.1.11), NULL }
	var $vb_oid : Blob
	$vb_oid:=This:C1470._derOid(New collection:C1472(1; 2; 840; 113549; 1; 1; 11))
	
	var $vb_null : Blob
	INSERT IN BLOB:C559($vb_null; 0; 2)
	$vb_null{0}:=0x0005  // NULL tag
	$vb_null{1}:=0x0000  // zero length
	
	var $vb_inner : Blob
	COPY BLOB:C558($vb_oid; $vb_inner; 0; BLOB size:C605($vb_inner); BLOB size:C605($vb_oid))
	COPY BLOB:C558($vb_null; $vb_inner; 0; BLOB size:C605($vb_inner); BLOB size:C605($vb_null))
	
	return This:C1470._derSequence($vb_inner)
	
	
Function _derExtensionRequestAttr($vt_hostname : Text) : Blob
	// Attributes [0] IMPLICIT { extensionRequest (OID 1.2.840.113549.1.9.14)
	//   containing Extensions { Extension { subjectAltName, dNSName hostname } } }
	//
	// This is the attribute wrapper that carries the SAN extension in a CSR:
	//   [0] { SEQUENCE { OID extensionRequest, SET { SEQUENCE { extensions } } } }
	
	// subjectAltName extension OID: 2.5.29.17
	var $vb_oidSAN : Blob
	$vb_oidSAN:=This:C1470._derOid(New collection:C1472(2; 5; 29; 17))
	
	// dNSName [2] IMPLICIT IA5String (context tag 2)
	var $vb_dnsName : Blob
	var $vb_hostname : Blob
	TEXT TO BLOB:C554($vt_hostname; $vb_hostname; UTF8 text without length:K22:17)
	$vb_dnsName:=This:C1470._derTLV(0x0082; $vb_hostname)  // [2] IMPLICIT
	
	// GeneralNames SEQUENCE { dNSName }
	var $vb_generalNames : Blob
	$vb_generalNames:=This:C1470._derSequence($vb_dnsName)
	
	// subjectAltName extension value is OCTET STRING wrapping GeneralNames DER
	var $vb_extValue : Blob
	$vb_extValue:=This:C1470._derOctetString($vb_generalNames)
	
	// Extension SEQUENCE { OID, OCTET STRING }
	var $vb_extInner : Blob
	COPY BLOB:C558($vb_oidSAN; $vb_extInner; 0; BLOB size:C605($vb_extInner); BLOB size:C605($vb_oidSAN))
	COPY BLOB:C558($vb_extValue; $vb_extInner; 0; BLOB size:C605($vb_extInner); BLOB size:C605($vb_extValue))
	var $vb_extension : Blob
	$vb_extension:=This:C1470._derSequence($vb_extInner)
	
	// Extensions SEQUENCE { Extension }
	var $vb_extensions : Blob
	$vb_extensions:=This:C1470._derSequence($vb_extension)
	
	// extensionRequest OID: 1.2.840.113549.1.9.14
	var $vb_oidER : Blob
	$vb_oidER:=This:C1470._derOid(New collection:C1472(1; 2; 840; 113549; 1; 9; 14))
	
	// Attribute value SET { SEQUENCE { Extensions } }
	var $vb_attrVal : Blob
	$vb_attrVal:=This:C1470._derSet($vb_extensions)
	
	// Attribute SEQUENCE { OID extensionRequest, SET { ... } }
	var $vb_attrInner : Blob
	COPY BLOB:C558($vb_oidER; $vb_attrInner; 0; BLOB size:C605($vb_attrInner); BLOB size:C605($vb_oidER))
	COPY BLOB:C558($vb_attrVal; $vb_attrInner; 0; BLOB size:C605($vb_attrInner); BLOB size:C605($vb_attrVal))
	var $vb_attr : Blob
	$vb_attr:=This:C1470._derSequence($vb_attrInner)
	
	// Wrap in [0] context tag (attributes context-tagged implicit SEQUENCE in PKCS#10)
	return This:C1470._derTLV(0x00A0; $vb_attr)
	
	
	// ============================================================
	// INTERNAL — KEY AND SIGNING HELPERS
	// ============================================================
	
Function _publicKeyDerFromPem($vo_cryptoKey : 4D:C1709.CryptoKey) : Blob
	// Extract the SubjectPublicKeyInfo DER from the 4D.CryptoKey.
	// getPublicKey() returns PEM; we strip headers and base64-decode.
	var $vt_pem : Text
	var $vb_der : Blob
	
	Try
		$vt_pem:=$vo_cryptoKey.getPublicKey()
	Catch
		return $vb_der
	End try
	
	// Strip PEM header/footer and newlines, then base64-decode
	var $vt_b64 : Text
	$vt_b64:=$vt_pem
	$vt_b64:=Replace string:C233($vt_b64; "-----BEGIN PUBLIC KEY-----"; "")
	$vt_b64:=Replace string:C233($vt_b64; "-----END PUBLIC KEY-----"; "")
	$vt_b64:=Replace string:C233($vt_b64; Char:C90(13); "")
	$vt_b64:=Replace string:C233($vt_b64; Char:C90(10); "")
	$vt_b64:=Replace string:C233($vt_b64; " "; "")
	BASE64 DECODE:C896($vt_b64; $vb_der)
	return $vb_der
	
	
Function _signBlob($vo_cryptoKey : 4D:C1709.CryptoKey; $vb_data : Blob) : Text
	// Sign raw DER bytes using RSASSA-PKCS1-v1_5 with SHA-256 (RS256).
	// Returns base64-encoded signature.
	// 4D.CryptoKey.sign() accepts a Blob directly; the RSA algorithm is
	// determined by the key type, not the options object.
	
	var $vt_signature : Text
	Try
		$vt_signature:=$vo_cryptoKey.sign($vb_data; New object(\
			"hash"; "SHA256"; \
			"encoding"; "Base64"))
	Catch
		return ""
	End try
	
	return $vt_signature
	
	
	// ============================================================
	// INTERNAL — BASE64URL
	// ============================================================
	
Function _base64urlBlob($vb_input : Blob) : Text
	var $vt_b64 : Text
	BASE64 ENCODE:C895($vb_input; $vt_b64; *)
	$vt_b64:=Replace string:C233($vt_b64; "+"; "-")
	$vt_b64:=Replace string:C233($vt_b64; "/"; "_")
	$vt_b64:=Replace string:C233($vt_b64; "="; "")
	return $vt_b64
	