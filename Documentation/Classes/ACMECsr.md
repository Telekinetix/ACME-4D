# ACMECsr

PKCS#10 Certification Signing Request (CSR) builder for the `tk-acme` component.

Builds a DER-encoded CSR entirely within 4D — no external tools, no shell commands. The CSR DER is base64url-encoded and submitted to the ACME `finalize` endpoint.

## Background — Spike 7.1 (resolved)

`4D.CryptoKey` (v18+) provides key generation, `sign()`, `verify()`, and PEM export, but does **not** expose a native PKCS#10 CSR generator. This class implements the CSR DER encoding by hand in 4D: a small, bounded ASN.1/DER encoder covering exactly what a single-hostname PKCS#10 requires.

> **Single hostname only.** `build()` takes one hostname and emits one CN and one SAN `dNSName`. If `ACMEConfig` is given several identifiers, `ACMEOrder._finalize()` still builds the CSR from `identifiers[0]` — the order authorizes every name, then finalize is rejected for a CSR/identifier mismatch. Configure exactly one hostname until SAN support lands. See [`docs/review-findings.md`](../../docs/review-findings.md).

## Constructor

```4d
var $csr : cs.acme.ACMECsr
$csr:=cs.acme.ACMECsr.new()
```

No parameters.

## Public Functions

### build

Builds a PKCS#10 CSR DER for a single hostname, signs it with the provided private key, and returns it as a base64url string ready for the ACME `finalize` payload.

```4d
var $csrB64url : Text
$csrB64url:=$csr.build($certPrivateKeyPem; "myhost.example.com")
// pass $csrB64url in the finalize payload: { "csr": $csrB64url }
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$vt_privateKeyPem` | Text | The **certificate** private key PEM (not the account key). **Never log.** |
| `$vt_hostname` | Text | The single hostname to certify (placed in both CN and `subjectAltName dNSName`) |
| **Return** | Text | `base64url(DER)` of the signed CSR, or `""` on failure |

### CSR Structure Built

```
CertificationRequest SEQUENCE {
  CertificationRequestInfo SEQUENCE {
    version                INTEGER 0
    subject                SEQUENCE { SET { SEQUENCE { OID-commonName, UTF8String hostname } } }
    subjectPublicKeyInfo   <extracted from key PEM>
    attributes [0] {
      extensionRequest SEQUENCE {
        OID 1.2.840.113549.1.9.14
        SET { Extensions SEQUENCE {
          Extension SEQUENCE {
            OID subjectAltName (2.5.29.17)
            OCTET STRING { GeneralNames SEQUENCE { [2] dNSName hostname } }
          }
        } }
      }
    }
  }
  AlgorithmIdentifier   sha256WithRSAEncryption (OID 1.2.840.113549.1.1.11)
  BIT STRING            { 0x00 || RS256 signature }
}
```

## Signing Over Raw DER (former Spike 7.1 blocker — resolved)

PKCS#10 requires the signature to cover the raw DER bytes of `CertificationRequestInfo`, not a
base64-encoded representation of them. An earlier implementation signed the base64 text, which does
not produce a standards-compliant CSR — this was the project's headline blocker.

It is resolved. [`4D.CryptoKey.sign()`](https://developer.4d.com/docs/API/CryptoKeyClass) has a Blob
overload alongside the Text one:

```
.sign(message : Text ; options : Object) : Text
.sign(message : Blob ; options : Object) : Text
```

`_signBlob()` therefore passes the `CertificationRequestInfo` blob straight through:

```4d
$vt_signature:=$vo_cryptoKey.sign($vb_data; New object("hash"; "SHA256"; "encoding"; "Base64"))
```

The returned base64 signature is decoded back to a blob and wrapped in the outer `BIT STRING`
(one `0x00` unused-bits byte, then the signature bytes). No external tooling, no `Generate digest`
workaround.

> Leftover from the previous approach: `build()` still declares `$vo_signOpts` and `$vt_criB64`
> and performs an unused `BASE64 ENCODE` of the CRI. Harmless, but dead.

## DER Primitive Helpers (Internal)

The class includes a complete minimal ASN.1/DER encoder:

| Function | Tag | Description |
|----------|-----|-------------|
| `_derSequence` | `0x30` | SEQUENCE wrapper |
| `_derSet` | `0x31` | SET wrapper |
| `_derInteger` | `0x02` | Small non-negative INTEGER |
| `_derOctetString` | `0x04` | OCTET STRING |
| `_derUtf8String` | `0x0C` | UTF8String |
| `_derIA5String` | `0x16` | IA5String (used in dNSName) |
| `_derOid` | `0x06` | OID from integer arc array |
| `_derTLV` / `_derTag` | any | Generic TLV encoder (handles 1/2/3-byte length encoding) |
| `_encodeBase128` | — | OID arc base-128 encoding |
| `_derSubjectCN` | — | Full CN subject Name structure |
| `_derAlgorithmIdentifierSha256WithRSA` | — | `sha256WithRSAEncryption` AlgId |
| `_derExtensionRequestAttr` | — | `extensionRequest` attribute carrying `subjectAltName` |
