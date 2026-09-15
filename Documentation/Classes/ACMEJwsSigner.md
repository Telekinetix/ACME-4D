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

## JWK Extraction (former spike — resolved)

4D exposes no JWK or JWKS export: [`getPublicKey()`](https://developer.4d.com/docs/API/CryptoKeyClass)
returns PEM and nothing else. `_buildPublicJwk()` therefore derives the JWK itself:

1. `getPublicKey()` → PEM.
2. `_pemToDer()` strips the `-----BEGIN/END PUBLIC KEY-----` armour and whitespace, then
   `BASE64 DECODE` to raw DER.
3. `_parseRsaPublicKey()` walks the `SubjectPublicKeyInfo` ASN.1 structure — outer `SEQUENCE`, skip
   the `AlgorithmIdentifier` `SEQUENCE`, `BIT STRING` plus its unused-bits byte, inner `SEQUENCE`,
   then two `INTEGER`s — and returns the modulus and exponent.
4. Each integer is base64url-encoded (with the DER leading-zero pad stripped) into `n` and `e`.

This runs once, in the constructor, and the result is cached in `_publicJwk`.

> `ACMEClient._regenerateKeyViaJwks()` remains as a fallback for the case where `publicJwk()` returns
> `Null`, but its name is now misleading — there is no JWKS path. It generates a fresh account key and
> re-parses it by exactly the route above. It refuses to run once the account is registered.

## Algorithm

- **RS256** — RSASSA-PKCS1-v1_5 with SHA-256, via `4D.CryptoKey.sign()`.
- All other base64url encoding (payloads, protected headers) is performed by post-processing standard base64: `+`→`-`, `/`→`_`, padding stripped.

> **Inconsistency worth knowing about.** `_buildJws()` passes
> `{ algorithm: "RS256", encoding: "Base64URL" }`, but the
> [4D.CryptoKey documentation](https://developer.4d.com/docs/API/CryptoKeyClass) lists the `.sign()`
> option keys as `hash`, `encoding` and `pss` — `algorithm` is not among them. `ACMECsr._signBlob()`
> correctly uses `hash: "SHA256"`. The JWS path works because SHA-256 is the default digest, not
> because the option is being honoured. Tracked in [`docs/review-findings.md`](../../docs/review-findings.md).

## Internal Methods

| Function | Purpose |
|----------|---------|
| `_buildJws` | Assembles the protected header (JWK or KID mode), joins `protected.payload`, signs, returns the flattened JWS |
| `_buildPublicJwk` | PEM → DER → `{ kty, n, e }`; called once from the constructor |
| `_pemToDer` | Strips PEM armour and base64-decodes to a DER blob |
| `_parseRsaPublicKey` | Walks `SubjectPublicKeyInfo` and returns base64url `n` and `e` |
| `_derExpectTag` | Asserts the byte at the cursor is the expected ASN.1 tag, advances past it |
| `_derReadLength` | Reads short- and long-form DER length encodings (up to 4 length bytes); returns `-1` on error |
| `_derReadInteger` | Reads a DER `INTEGER` into a blob, stripping the positive-number leading zero |
| `_base64url` | Base64url-encodes UTF-8 text |
| `_base64urlBlob` | Base64url-encodes a blob (standard base64, then `+`→`-`, `/`→`_`, strip `=`) |
| `_sha256Blob` | SHA-256 digest of a blob, returned as **base64url Text** — uses `Generate digest` (hex), then `_hexToInt` per pair to rebuild the digest blob |
| `_hexToInt` | Converts a two-character hex string to `0`–`255` |

> The DER reader keeps its cursor in the instance property `_pos` rather than threading it through
> the helpers. It is reset at the start of `_parseRsaPublicKey()` and only ever used from the
> constructor, so it is safe as written — but the `_der*` helpers are not reentrant.

> `_buildPublicJwk` is followed in the source by a large commented-out block describing an abandoned
> `getPublicKey({format:"JWKS"})` approach, including a "SPIKE RESULT" note that contradicts the
> working implementation above it. Ignore it; it is dead.
