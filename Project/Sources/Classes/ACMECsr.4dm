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
	var $vo_cryptoKey : 4D.CryptoKey
	Try
		$vo_cryptoKey:=4D.CryptoKey.new(New object("type"; "PEM"; "pem"; $vt_privateKeyPem))
	Catch
		return ""
	End try

	// 2. Get the public key DER bytes (SubjectPublicKeyInfo from PEM)
	var $vb_spki : Blob
	$vb_spki:=This._publicKeyDerFromPem($vo_cryptoKey)
	If (BLOB size($vb_spki)=0)
		return ""
	End if

	// 3. Build the CertificationRequestInfo DER
	var $vb_cri : Blob
	$vb_cri:=This._buildCertificationRequestInfo($vt_hostname; $vb_spki)

	// 4. Sign the CertificationRequestInfo with RS256
	var $vo_signOpts : Object
	var $vt_criB64 : Text
	var $vb_signature : Blob
	$vo_signOpts:=New object("algorithm"; "RS256"; "encoding"; "Base64")

	// sign() works on text; encode CRI as base64 for input, then get raw bytes
	BASE64 ENCODE($vb_cri; $vt_criB64; *)

	// For RS256 DER signing we need the raw signature bytes.
	// 4D.CryptoKey.sign() returns base64 or base64URL text.
	// We request base64 then decode back to a blob for DER wrapping.
	var $vt_sigB64 : Text
	$vt_sigB64:=This._signBlob($vo_cryptoKey; $vb_cri)
	If (Length($vt_sigB64)=0)
		return ""
	End if
	BASE64 DECODE($vt_sigB64; $vb_signature)

	// 5. Wrap into the outer CertificationRequest SEQUENCE
	var $vb_csr : Blob
	$vb_csr:=This._buildCertificationRequest($vb_cri; $vb_signature)

	// 6. Base64url-encode the DER
	return This._base64urlBlob($vb_csr)


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
	$vb_version:=This._derInteger(0)

	// subject: CN=hostname
	var $vb_subject : Blob
	$vb_subject:=This._derSubjectCN($vt_hostname)

	// subjectPKInfo: already in DER as extracted from PEM
	var $vb_spkiCopy : Blob
	$vb_spkiCopy:=$vb_spki

	// attributes [0]: subjectAltName extension request
	var $vb_attrs : Blob
	$vb_attrs:=This._derExtensionRequestAttr($vt_hostname)

	// Concatenate and wrap in SEQUENCE
	var $vb_cri : Blob
	COPY BLOB($vb_version; $vb_cri; 0; BLOB size($vb_cri); BLOB size($vb_version))
	COPY BLOB($vb_subject; $vb_cri; 0; BLOB size($vb_cri); BLOB size($vb_subject))
	COPY BLOB($vb_spkiCopy; $vb_cri; 0; BLOB size($vb_cri); BLOB size($vb_spkiCopy))
	COPY BLOB($vb_attrs; $vb_cri; 0; BLOB size($vb_cri); BLOB size($vb_attrs))

	return This._derSequence($vb_cri)


Function _buildCertificationRequest($vb_cri : Blob; $vb_signature : Blob) : Blob
	// SEQUENCE {
	//   CertificationRequestInfo (already encoded)
	//   AlgorithmIdentifier { OID sha256WithRSAEncryption, NULL }
	//   BIT STRING { 0x00 || signature_bytes }
	// }

	// AlgorithmIdentifier for sha256WithRSAEncryption (OID 1.2.840.113549.1.1.11)
	var $vb_algId : Blob
	$vb_algId:=This._derAlgorithmIdentifierSha256WithRSA()

	// BIT STRING: one unused-bits byte (0x00) + signature bytes
	var $vb_bitStr : Blob
	INSERT IN BLOB($vb_bitStr; 0; 1)
	$vb_bitStr{0}:=0x00
	COPY BLOB($vb_signature; $vb_bitStr; 0; BLOB size($vb_bitStr); BLOB size($vb_signature))
	var $vb_sigDer : Blob
	$vb_sigDer:=This._derTag($vb_bitStr; 0x03)

	// Outer SEQUENCE
	var $vb_inner : Blob
	COPY BLOB($vb_cri; $vb_inner; 0; BLOB size($vb_inner); BLOB size($vb_cri))
	COPY BLOB($vb_algId; $vb_inner; 0; BLOB size($vb_inner); BLOB size($vb_algId))
	COPY BLOB($vb_sigDer; $vb_inner; 0; BLOB size($vb_inner); BLOB size($vb_sigDer))

	return This._derSequence($vb_inner)


// ============================================================
// INTERNAL — DER PRIMITIVES
// ============================================================

Function _derTLV($vl_tag : Integer; $vb_value : Blob) : Blob
	// Build a DER TLV: tag byte + length encoding + value bytes.
	var $vb_tlv : Blob
	var $vl_len : Integer
	$vl_len:=BLOB size($vb_value)

	INSERT IN BLOB($vb_tlv; 0; 1)
	$vb_tlv{0}:=$vl_tag

	// Length encoding
	If ($vl_len<0x80)
		INSERT IN BLOB($vb_tlv; BLOB size($vb_tlv); 1)
		$vb_tlv{BLOB size($vb_tlv)-1}:=$vl_len
	Else If ($vl_len<=0xFF)
		INSERT IN BLOB($vb_tlv; BLOB size($vb_tlv); 2)
		$vb_tlv{BLOB size($vb_tlv)-2}:=0x81
		$vb_tlv{BLOB size($vb_tlv)-1}:=$vl_len
	Else If ($vl_len<=0xFFFF)
		INSERT IN BLOB($vb_tlv; BLOB size($vb_tlv); 3)
		$vb_tlv{BLOB size($vb_tlv)-3}:=0x82
		$vb_tlv{BLOB size($vb_tlv)-2}:=($vl_len>>8) & 0xFF
		$vb_tlv{BLOB size($vb_tlv)-1}:=$vl_len & 0xFF
	End if

	// Append value bytes
	COPY BLOB($vb_value; $vb_tlv; 0; BLOB size($vb_tlv); BLOB size($vb_value))
	return $vb_tlv


Function _derTag($vb_value : Blob; $vl_tag : Integer) : Blob
	return This._derTLV($vl_tag; $vb_value)


Function _derSequence($vb_content : Blob) : Blob
	return This._derTLV(0x30; $vb_content)


Function _derSet($vb_content : Blob) : Blob
	return This._derTLV(0x31; $vb_content)


Function _derInteger($vl_value : Integer) : Blob
	// Encode a small non-negative integer as DER INTEGER.
	var $vb_val : Blob
	INSERT IN BLOB($vb_val; 0; 1)
	$vb_val{0}:=$vl_value & 0xFF
	// Ensure positive (prepend 0x00 if high bit set)
	If ($vb_val{0}>=0x80)
		var $vb_padded : Blob
		INSERT IN BLOB($vb_padded; 0; 1)
		$vb_padded{0}:=0x00
		COPY BLOB($vb_val; $vb_padded; 0; BLOB size($vb_padded); BLOB size($vb_val))
		$vb_val:=$vb_padded
	End if
	return This._derTLV(0x02; $vb_val)


Function _derOctetString($vb_value : Blob) : Blob
	return This._derTLV(0x04; $vb_value)


Function _derUtf8String($vt_value : Text) : Blob
	var $vb_value : Blob
	TEXT TO BLOB($vt_value; $vb_value; UTF8 text without length)
	return This._derTLV(0x0C; $vb_value)


Function _derIA5String($vt_value : Text) : Blob
	// IA5String (used in subjectAltName dNSName)
	var $vb_value : Blob
	TEXT TO BLOB($vt_value; $vb_value; UTF8 text without length)
	return This._derTLV(0x16; $vb_value)


Function _derOid($vc_oid : Collection) : Blob
	// Encode an OID from its integer arc array, e.g. [1,2,840,113549,1,1,11]
	// First two arcs are combined: first_arc * 40 + second_arc
	var $vb_oid : Blob
	var $i; $vl_arc; $vl_first : Integer

	$vl_first:=$vc_oid[0]*40+$vc_oid[1]
	$vb_oid:=This._encodeBase128($vl_first)

	For ($i; 2; $vc_oid.length-1)
		$vl_arc:=$vc_oid[$i]
		var $vb_arc : Blob
		$vb_arc:=This._encodeBase128($vl_arc)
		COPY BLOB($vb_arc; $vb_oid; 0; BLOB size($vb_oid); BLOB size($vb_arc))
	End for

	return This._derTLV(0x06; $vb_oid)


Function _encodeBase128($vl_value : Integer) : Blob
	// Encode a non-negative integer in base-128 (DER OID arc encoding).
	var $vb_result : Blob
	var $vl_work : Integer
	$vl_work:=$vl_value

	If ($vl_work=0)
		INSERT IN BLOB($vb_result; 0; 1)
		$vb_result{0}:=0
		return $vb_result
	End if

	// Build bytes from LSB to MSB, then reverse
	var $vc_bytes : Collection
	$vc_bytes:=New collection
	While ($vl_work>0)
		$vc_bytes.unshift($vl_work & 0x7F)
		$vl_work:=$vl_work>>7
	End while

	var $j : Integer
	For ($j; 0; $vc_bytes.length-1)
		INSERT IN BLOB($vb_result; BLOB size($vb_result); 1)
		If ($j<$vc_bytes.length-1)
			$vb_result{BLOB size($vb_result)-1}:=($vc_bytes[$j] | 0x80)
		Else
			$vb_result{BLOB size($vb_result)-1}:=$vc_bytes[$j]
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

	var $vb_attrSeq : Blob
	COPY BLOB($vb_oidCN; $vb_attrSeq; 0; BLOB size($vb_attrSeq); BLOB size($vb_oidCN))
	COPY BLOB($vb_cnStr; $vb_attrSeq; 0; BLOB size($vb_attrSeq); BLOB size($vb_cnStr))

	var $vb_attrSet : Blob
	$vb_attrSet:=This._derSet(This._derSequence($vb_attrSeq))

	return This._derSequence($vb_attrSet)


Function _derAlgorithmIdentifierSha256WithRSA() : Blob
	// AlgorithmIdentifier { OID sha256WithRSAEncryption (1.2.840.113549.1.1.11), NULL }
	var $vb_oid : Blob
	$vb_oid:=This._derOid(New collection(1; 2; 840; 113549; 1; 1; 11))

	var $vb_null : Blob
	INSERT IN BLOB($vb_null; 0; 2)
	$vb_null{0}:=0x05  // NULL tag
	$vb_null{1}:=0x00  // zero length

	var $vb_inner : Blob
	COPY BLOB($vb_oid; $vb_inner; 0; BLOB size($vb_inner); BLOB size($vb_oid))
	COPY BLOB($vb_null; $vb_inner; 0; BLOB size($vb_inner); BLOB size($vb_null))

	return This._derSequence($vb_inner)


Function _derExtensionRequestAttr($vt_hostname : Text) : Blob
	// Attributes [0] IMPLICIT { extensionRequest (OID 1.2.840.113549.1.9.14)
	//   containing Extensions { Extension { subjectAltName, dNSName hostname } } }
	//
	// This is the attribute wrapper that carries the SAN extension in a CSR:
	//   [0] { SEQUENCE { OID extensionRequest, SET { SEQUENCE { extensions } } } }

	// subjectAltName extension OID: 2.5.29.17
	var $vb_oidSAN : Blob
	$vb_oidSAN:=This._derOid(New collection(2; 5; 29; 17))

	// dNSName [2] IMPLICIT IA5String (context tag 2)
	var $vb_dnsName : Blob
	var $vb_hostname : Blob
	TEXT TO BLOB($vt_hostname; $vb_hostname; UTF8 text without length)
	$vb_dnsName:=This._derTLV(0x82; $vb_hostname)  // [2] IMPLICIT

	// GeneralNames SEQUENCE { dNSName }
	var $vb_generalNames : Blob
	$vb_generalNames:=This._derSequence($vb_dnsName)

	// subjectAltName extension value is OCTET STRING wrapping GeneralNames DER
	var $vb_extValue : Blob
	$vb_extValue:=This._derOctetString($vb_generalNames)

	// Extension SEQUENCE { OID, OCTET STRING }
	var $vb_extInner : Blob
	COPY BLOB($vb_oidSAN; $vb_extInner; 0; BLOB size($vb_extInner); BLOB size($vb_oidSAN))
	COPY BLOB($vb_extValue; $vb_extInner; 0; BLOB size($vb_extInner); BLOB size($vb_extValue))
	var $vb_extension : Blob
	$vb_extension:=This._derSequence($vb_extInner)

	// Extensions SEQUENCE { Extension }
	var $vb_extensions : Blob
	$vb_extensions:=This._derSequence($vb_extension)

	// extensionRequest OID: 1.2.840.113549.1.9.14
	var $vb_oidER : Blob
	$vb_oidER:=This._derOid(New collection(1; 2; 840; 113549; 1; 9; 14))

	// Attribute value SET { SEQUENCE { Extensions } }
	var $vb_attrValInner : Blob
	$vb_attrValInner:=This._derSequence($vb_extensions)
	var $vb_attrVal : Blob
	$vb_attrVal:=This._derSet($vb_attrValInner)

	// Attribute SEQUENCE { OID extensionRequest, SET { ... } }
	var $vb_attrInner : Blob
	COPY BLOB($vb_oidER; $vb_attrInner; 0; BLOB size($vb_attrInner); BLOB size($vb_oidER))
	COPY BLOB($vb_attrVal; $vb_attrInner; 0; BLOB size($vb_attrInner); BLOB size($vb_attrVal))
	var $vb_attr : Blob
	$vb_attr:=This._derSequence($vb_attrInner)

	// Wrap in [0] context tag (attributes context-tagged implicit SEQUENCE in PKCS#10)
	return This._derTLV(0xA0; $vb_attr)


// ============================================================
// INTERNAL — KEY AND SIGNING HELPERS
// ============================================================

Function _publicKeyDerFromPem($vo_cryptoKey : 4D.CryptoKey) : Blob
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
	$vt_b64:=Replace string($vt_b64; "-----BEGIN PUBLIC KEY-----"; "")
	$vt_b64:=Replace string($vt_b64; "-----END PUBLIC KEY-----"; "")
	$vt_b64:=Replace string($vt_b64; Char(13); "")
	$vt_b64:=Replace string($vt_b64; Char(10); "")
	$vt_b64:=Replace string($vt_b64; " "; "")
	BASE64 DECODE($vt_b64; $vb_der)
	return $vb_der


Function _signBlob($vo_cryptoKey : 4D.CryptoKey; $vb_data : Blob) : Text
	// Sign raw bytes using RS256; returns base64-encoded signature.
	// 4D.CryptoKey.sign() takes Text input — we pass the base64 of the data
	// and request base64 output, then the caller decodes the signature.
	// NOTE: This is a workaround for the absence of a raw-blob sign API.
	// The ACME spec requires signing the raw DER bytes. We encode the CRI
	// to base64, sign that string, then get the signature bytes back.
	//
	// IMPORTANT: This approach is INCORRECT for PKCS#10 — the signature must
	// cover the raw DER bytes of CertificationRequestInfo, not the base64.
	// This is a known spike issue raised for resolution (see §7.1 of brief).
	// For correctness, this needs 4D support for signing arbitrary blobs,
	// or an external SHA256 hash of the DER followed by RSA sign of the hash.
	//
	// As an interim workaround until resolved: we convert the DER to text
	// via a reversible encoding and sign that. This does NOT produce a valid
	// CSR for production use. Flag this as a blocker.
	//
	// TODO: Resolve with platform team — confirm if sign() can accept blob
	// input in a future 4D v20 patch, or use the Generate digest + raw RSA path.

	var $vt_dataB64 : Text
	var $vo_signOpts : Object
	BASE64 ENCODE($vb_data; $vt_dataB64; *)
	$vo_signOpts:=New object("algorithm"; "RS256"; "encoding"; "Base64")
	return Try($vo_cryptoKey.sign($vo_signOpts; $vt_dataB64))


// ============================================================
// INTERNAL — BASE64URL
// ============================================================

Function _base64urlBlob($vb_input : Blob) : Text
	var $vt_b64 : Text
	BASE64 ENCODE($vb_input; $vt_b64; *)
	$vt_b64:=Replace string($vt_b64; "+"; "-")
	$vt_b64:=Replace string($vt_b64; "/"; "_")
	$vt_b64:=Replace string($vt_b64; "="; "")
	return $vt_b64
