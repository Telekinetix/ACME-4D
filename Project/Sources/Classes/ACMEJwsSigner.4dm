// ----------------------------------------------------
// Class: ACMEJwsSigner
// JSON Web Signature (JWS) builder for ACMEv2 (RFC 8555, RFC 7515/7517/7518).
//
// All ACME requests are signed HTTP POST bodies in "Flattened JWS JSON" format:
//   { "protected": "<base64url>", "payload": "<base64url>", "signature": "<base64url>" }
//
// Two signing modes (RFC 8555 §6.2):
//   1. JWK mode   — used for newAccount only; embeds the public JWK in protected.
//   2. KID mode   — used for all subsequent requests; embeds the account URL (kid).
//
// Algorithm: RS256 (RSASSA-PKCS1-v1_5 with SHA-256).
//   4D.CryptoKey supports RS256 sign/verify natively via .sign() with "RS256".
//   The "RS256" option encodes the signature as base64URL automatically.
//
// JWK thumbprint (RFC 7638):
//   SHA-256 of the canonical JSON of the public key's required members
//   ({"e":..., "kty":"RSA", "n":...} in lexicographic order), base64url-encoded.
//   Used to compute keyAuthorization for HTTP-01 challenges.
//
// Base64URL encoding:
//   4D.CryptoKey.sign() returns base64URL directly.
//   For arbitrary blobs: Base64 encode with * option gives standard base64;
//   we post-process ( + → - / → _ strip = ) to get base64url.
//
// Private key material is never logged.
// ----------------------------------------------------

property _accountKeyPem : Text   // RSA private key PEM (NEVER log)
property _cryptoKey : 4D.CryptoKey
property _publicJwk : Object    // Cached { kty, n, e } public key JSON
property _kid : Text             // Account URL set after registration


Class constructor($vt_privateKeyPem : Text)
	// $vt_privateKeyPem: RSA private key in PKCS#8 PEM format.
	// Key material is stored in memory only; never written to log.
	This._accountKeyPem:=$vt_privateKeyPem
	This._kid:=""
	This._publicJwk:=Null

	// Load the key into a 4D.CryptoKey for signing
	var $vo_keyParams : Object
	$vo_keyParams:=New object(\
		"type"; "PEM"; \
		"pem"; $vt_privateKeyPem)
	This._cryptoKey:=4D.CryptoKey.new($vo_keyParams)
	This._publicJwk:=This._buildPublicJwk()


// ============================================================
// CONFIGURATION
// ============================================================

Function setKid($vt_accountUrl : Text)
	// Call this after account registration to switch to KID mode.
	This._kid:=$vt_accountUrl


// ============================================================
// SIGNING
// ============================================================

Function sign($vt_url : Text; $vo_payload : Object; $vt_nonce : Text) : Object
	// Build a Flattened JWS for a standard POST with a JSON payload.
	var $vt_payloadB64 : Text
	If ($vo_payload=Null)
		$vt_payloadB64:=""
	Else
		$vt_payloadB64:=This._base64url(JSON Stringify($vo_payload))
	End if
	return This._buildJws($vt_url; $vt_payloadB64; $vt_nonce)


Function signPostAsGet($vt_url : Text; $vt_nonce : Text) : Object
	// POST-as-GET per RFC 8555 §6.3 — payload is empty string (not null, not "").
	return This._buildJws($vt_url; ""; $vt_nonce)


// ============================================================
// JWK THUMBPRINT (for HTTP-01 keyAuthorization)
// ============================================================

Function jwkThumbprint() : Text
	// Returns the base64url-encoded SHA-256 of the canonical JWK thumbprint
	// per RFC 7638. Used to compute keyAuthorization:
	//   keyAuthorization = token + "." + jwkThumbprint()
	//
	// The canonical JSON contains only { "e", "kty", "n" } in lexicographic order.
	// We compute SHA-256 using 4D.CryptoKey digest functionality.

	If (This._publicJwk=Null)
		return ""
	End if

	// Build canonical JSON: keys in lexicographic order — e, kty, n
	var $vt_canonical : Text
	$vt_canonical:=JSON Stringify(New object(\
		"e"; This._publicJwk.e; \
		"kty"; This._publicJwk.kty; \
		"n"; This._publicJwk.n))

	// SHA-256 hash of the UTF-8 canonical JSON, returned as base64URL
	// 4D.CryptoKey.sign() with a digest-only approach isn't direct;
	// we use the Generate digest command (available in v20.0).
	var $vb_hash : Blob
	var $vt_canonical_utf8 : Text
	$vt_canonical_utf8:=$vt_canonical

	// Convert text to blob for hashing
	var $vb_input : Blob
	TEXT TO BLOB($vt_canonical_utf8; $vb_input; UTF8 text without length)

	// Generate SHA-256 digest
	$vb_hash:=This._sha256Blob($vb_input)

	return This._base64urlBlob($vb_hash)


// ============================================================
// PUBLIC KEY ACCESS
// ============================================================

Function publicJwk() : Object
	// Return the public JWK object { kty:"RSA", n:"<base64url>", e:"<base64url>" }
	return This._publicJwk


// ============================================================
// INTERNAL — JWS CONSTRUCTION
// ============================================================

Function _buildJws($vt_url : Text; $vt_payloadB64 : Text; $vt_nonce : Text) : Object
	// Construct the protected header
	var $vo_protected : Object
	$vo_protected:=New object(\
		"alg"; "RS256"; \
		"nonce"; $vt_nonce; \
		"url"; $vt_url)

	If (Length(This._kid)>0)
		// KID mode — all requests after account creation
		$vo_protected["kid"]:=This._kid
	Else
		// JWK mode — newAccount only
		$vo_protected["jwk"]:=This._publicJwk
	End if

	var $vt_protectedB64 : Text
	$vt_protectedB64:=This._base64url(JSON Stringify($vo_protected))

	// Signing input: ASCII(BASE64URL(protected) + "." + BASE64URL(payload))
	var $vt_signingInput : Text
	$vt_signingInput:=$vt_protectedB64+"."+$vt_payloadB64

	// Sign with RS256
	var $vo_signOptions : Object
	$vo_signOptions:=New object(\
		"algorithm"; "RS256"; \
		"encoding"; "Base64URL")

	var $vt_signature : Text
	$vt_signature:=This._cryptoKey.sign($vo_signOptions; $vt_signingInput)

	return New object(\
		"protected"; $vt_protectedB64; \
		"payload"; $vt_payloadB64; \
		"signature"; $vt_signature)


// ============================================================
// INTERNAL — KEY PARSING
// ============================================================

Function _buildPublicJwk() : Object
	// Extract the RSA public key components (n, e) from the loaded key.
	// 4D.CryptoKey.getPublicKey() returns PEM; we need the JWK form.
	// Use the jwkInfo() approach if available, else parse PEM-encoded DER.
	//
	// In 4D v20+, CryptoKey exposes .getPrivateKey() / .getPublicKey() in PEM
	// but does NOT expose a direct .toJWK() method. We use the internal
	// Generate key pair approach with JWKS if the key was generated here,
	// OR we call .sign() with a special params object to get the JWK data.
	//
	// Practical approach for v20.0: generate the JWK by having 4D export it.
	// CryptoKey.new() with type:"JWKS" lets us pass in a JWK; going the other
	// direction we need another technique.
	//
	// SPIKE RESULT: In 4D v20.0 there is no direct PEM→JWK export.
	// We extract n and e from the public key using the Generate key command
	// with the PEM as input and requesting JWKS format output.
	//
	// Workaround: re-import via JWKS. If the key was generated by this component
	// it was created with type "RSA" and we can get JWKS. For externally provided
	// PEM keys, we parse the DER manually to extract n and e.
	//
	// For now we store a placeholder and resolve in ACMEClient.setup() after
	// confirming the key generation path. The _cryptoKey object is always valid
	// for signing; the JWK is only needed for the protected header on newAccount
	// and for the thumbprint computation.

	// Try: create a matching CryptoKey from PEM and export JWKS
	var $vo_jwksKey : 4D.CryptoKey
	var $vt_jwks : Text
	var $vo_jwks : Object

	Try
		// Some 4D builds allow getPublicKey with "JWKS" format; try it.
		$vt_jwks:=This._cryptoKey.getPublicKey(New object("format"; "JWKS"))
		If (Length($vt_jwks)>0)
			$vo_jwks:=JSON Parse($vt_jwks)
			If ($vo_jwks#Null) && (OB Is defined($vo_jwks; "n"))
				return New object(\
					"kty"; "RSA"; \
					"n"; String($vo_jwks.n); \
					"e"; String($vo_jwks.e))
			End if
		End if
	Catch
		// getPublicKey() with JWKS format not supported in this build
	End try

	// Fallback: return a null marker — ACMEClient will resolve via key generation
	return Null


// ============================================================
// INTERNAL — BASE64URL
// ============================================================

Function _base64url($vt_input : Text) : Text
	// Base64URL-encode a UTF-8 text string.
	// Converts standard base64 ( +, /, = ) to URL-safe form ( -, _, no padding ).
	var $vb_input : Blob
	TEXT TO BLOB($vt_input; $vb_input; UTF8 text without length)
	return This._base64urlBlob($vb_input)


Function _base64urlBlob($vb_input : Blob) : Text
	// Base64URL-encode a Blob.
	var $vt_b64 : Text
	BASE64 ENCODE($vb_input; $vt_b64; *)  // * = no line breaks
	// Convert standard base64 → base64url
	$vt_b64:=Replace string($vt_b64; "+"; "-")
	$vt_b64:=Replace string($vt_b64; "/"; "_")
	$vt_b64:=Replace string($vt_b64; "="; "")
	return $vt_b64


Function _sha256Blob($vb_input : Blob) : Blob
	// Return the SHA-256 digest of $vb_input as a Blob.
	// Uses 4D's Generate digest with a blob → hex approach, then hex-decode.
	// Generate digest returns a hex string; we convert that back to bytes.
	var $vt_hex : Text
	var $vb_out : Blob
	$vt_hex:=Generate digest($vb_input; SHA256 digest)
	// Hex-decode: iterate pairs of hex characters
	var $i; $vl_len : Integer
	var $vt_byte : Text
	$vl_len:=Length($vt_hex)
	For ($i; 1; $vl_len; 2)
		$vt_byte:=Substring($vt_hex; $i; 2)
		INSERT IN BLOB($vb_out; BLOB size($vb_out); 1)
		$vb_out{BLOB size($vb_out)-1}:=Num("0x"+$vt_byte)
	End for
	return $vb_out
