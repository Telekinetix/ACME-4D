# ACMEJwsSigner

JSON Web Signature (JWS) builder for ACMEv2 (RFC 8555, RFC 7515/7517/7518).

Constructs the Flattened JWS JSON serialisation required by every ACME POST request, using the account's RSA private key. Also computes the JWK thumbprint used to build `keyAuthorization` values for HTTP-01 challenges.

## Constructor

```4d
var $signer : cs.acme.ACMEJwsSigner
$signer:=cs.acme.ACMEJwsSigner.new($privateKeyPem)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$vt_privateKeyPem` | Text | RSA private key in PKCS#8 PEM format. **Never log this value.** |

The key is loaded into a `4D.CryptoKey` at construction time and cached for signing. The public JWK (`{ kty, n, e }`) is extracted automatically.

## JWS Modes

RFC 8555 requires two distinct signing modes:

| Mode | Protected header field | Used for |
|------|------------------------|---------|
| **JWK** | `"jwk": { kty, n, e }` | `newAccount` only — before the account URL (kid) is known |
| **KID** | `"kid": "<accountUrl>"` | All subsequent requests |

Call `setKid()` after a successful account registration to switch from JWK to KID mode.

## Public Functions

### setKid

```4d
$signer.setKid("https://acme-v02.api.letsencrypt.org/acme/acct/123456")
```

Switches the signer to KID mode. Called by `ACMEClient.setup()` after account registration.

| Parameter | Type | Description |
|-----------|------|-------------|
| `$vt_accountUrl` | Text | Account URL returned by the CA as the `Location` header on `newAccount` |

---

### sign

Builds a Flattened JWS for a standard POST with a JSON payload.

```4d
var $jws : Object
$jws:=$signer.sign($url; $payloadObject; $nonce)
// $jws = { "protected": "...", "payload": "...", "signature": "..." }
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$vt_url` | Text | Request URL (placed in the `url` protected-header field) |
| `$vo_payload` | Object | JSON payload to sign. Pass `Null` to produce an empty-string payload. |
| `$vt_nonce` | Text | Current `Replay-Nonce` from the CA |
| **Return** | Object | Flattened JWS JSON `{ protected, payload, signature }` |

---

### signPostAsGet

Builds a Flattened JWS for a POST-as-GET request (RFC 8555 §6.3). The payload is the empty string `""` — not `null`, not `{}`.

```4d
var $jws : Object
$jws:=$signer.signPostAsGet($url; $nonce)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$vt_url` | Text | Resource URL to fetch |
| `$vt_nonce` | Text | Current `Replay-Nonce` |
| **Return** | Object | Flattened JWS JSON |

---

### jwkThumbprint

Computes the base64url-encoded SHA-256 thumbprint of the account public key per RFC 7638. Used to build the `keyAuthorization` for HTTP-01 challenges:

```
keyAuthorization = token + "." + jwkThumbprint()
```

```4d
var $thumbprint : Text
$thumbprint:=$signer.jwkThumbprint()
```

| | Type | Description |
|---|---|---|
| **Return** | Text | Base64url SHA-256 of the canonical JWK (`{ "e", "kty", "n" }` lexicographic order), or `""` on failure |

---

### publicJwk

```4d
var $jwk : Object
$jwk:=$signer.publicJwk()
// { "kty": "RSA", "n": "<base64url>", "e": "<base64url>" }
```

Returns the cached public JWK object. Used in the `protected` header for `newAccount` requests (JWK mode).

> **Spike note:** JWK extraction from an externally provided PEM key requires `getPublicKey({format:"JWKS"})` — available in some 4D v20 builds. If this returns `Null`, `ACMEClient` falls back to regenerating the account key pair via the native `type:"RSA"` CryptoKey path which does support JWKS export. See the kickoff §7.1.

## Algorithm

- **RS256** — RSASSA-PKCS1-v1_5 with SHA-256, via `4D.CryptoKey.sign()`.
- `4D.CryptoKey.sign()` with `{ algorithm: "RS256", encoding: "Base64URL" }` returns the signature as base64url directly.
- All other base64url encoding (payloads, protected headers) is performed by post-processing standard base64: `+`→`-`, `/`→`_`, padding stripped.

## Internal Methods

`_buildJws`, `_buildPublicJwk`, `_base64url`, `_base64urlBlob`, `_sha256Blob` — encoding and signing pipeline. The SHA-256 digest for the JWK thumbprint uses 4D's `Generate digest` with hex output, then hex-decodes to a blob for base64url encoding.
