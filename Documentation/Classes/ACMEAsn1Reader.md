# ACMEAsn1Reader

Shared DER/ASN.1 parser for X.509 certificates.

Extracted from `ACMEJwsSigner` so that `ACMECertStore` and `ACMEScheduler` can consume certificate
fields without duplicating parsing logic or coupling to the JWS signing class.

## Constructor

```4d
var $reader : cs.ACMEAsn1Reader
$reader := cs.ACMEAsn1Reader.new()
```

No parameters. The internal cursor `_pos` is initialised to `0` and is reset at the start of every
`parseCertificate()` call.

## Public Functions

### `parseCertificate($vt_pem)` → Object

Parse the first PEM certificate in `$vt_pem` and return the fields needed by `ACMECertStore` and
`ACMEScheduler`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `$vt_pem` | Text | PEM text containing at least one `BEGIN CERTIFICATE` / `END CERTIFICATE` block. If a chain is present only the first (leaf) certificate is parsed. |

**Return value:**

| Field | Type | Description |
|-------|------|-------------|
| `ok` | Boolean | `True` if parsing succeeded; `False` on any error. |
| `error` | Text | Human-readable reason when `ok` is `False`; `""` otherwise. |
| `notAfter` | Date | The certificate's `notAfter` date extracted from the `Validity` field. `!00-00-00!` when `ok` is `False`. |
| `serial` | Text | Hex-encoded serial number (lower-case, no `0x` prefix, no leading zero byte). `""` when `ok` is `False`. |
| `issuerDer` | Blob | Raw DER bytes of the `Issuer` Name field (tag + length + value). Used by `ACMEScheduler._buildAriUrl()` to compute the `issuerKeyHash` (SHA-256 of these bytes per RFC 8739 §4.1). Empty blob when `ok` is `False`. |

```4d
var $reader : cs.ACMEAsn1Reader
var $cert   : Object
$reader := cs.ACMEAsn1Reader.new()
$cert   := $reader.parseCertificate($vt_pemText)

If ($cert.ok)
    var $vd_notAfter : Date
    $vd_notAfter := $cert.notAfter     // e.g. !2025-09-14!
    var $vt_serial : Text
    $vt_serial   := $cert.serial       // e.g. "03a1b2c3d4e5f6"
    var $vb_issuer : Blob
    $vb_issuer   := $cert.issuerDer    // raw DER for SHA-256 → ARI key hash
Else
    // $cert.error contains the reason
End if
```

## Internal Methods

| Function | Purpose |
|----------|---------|
| `_derExpectTag` | Asserts the byte at the cursor is the expected ASN.1 tag, advances past it. Identical to the helper in `ACMEJwsSigner`. |
| `_derReadLength` | Reads short- and long-form DER length encodings (up to 4 length bytes); returns `-1` on error. Identical to the helper in `ACMEJwsSigner`. |
| `_derReadInteger` | Reads a DER `INTEGER` TLV into a blob, stripping the DER positive-number leading zero byte. Identical to the helper in `ACMEJwsSigner`. |
| `_derReadTime` | Reads a `UTCTime` (tag `0x17`) or `GeneralizedTime` (tag `0x18`) TLV and returns a 4D `Date`. Returns `!00-00-00!` on error. |
| `_pemToDer` | Strips PEM armour from the first certificate block and base64-decodes the body to a blob. |
| `_blobToHex` | Converts every byte of a blob to a lowercase two-hex-digit string (used for the serial number). |
| `_byteToHex` | Converts a single byte value (0–255) to a two-character lowercase hex string. |

> The cursor `_pos` is an instance property shared by all `_der*` helpers. It is reset to `0` at
> the start of `parseCertificate()`. Do not call `parseCertificate()` recursively on the same
> instance.

## TBSCertificate Walk Order

`parseCertificate()` walks the `TBSCertificate` sequence in the order mandated by RFC 5280 §4.1:

```
Certificate          ::= SEQUENCE {
    tbsCertificate       TBSCertificate,    ← outer SEQUENCE, entered
    signatureAlgorithm   ...,               ← not reached (parsing stops after Validity)
    signature            ...
}

TBSCertificate  ::= SEQUENCE {
    version         [0] EXPLICIT INTEGER OPTIONAL,   ← skipped when present
    serialNumber         INTEGER,                    ← captured → serial
    signature            AlgorithmIdentifier,        ← skipped
    issuer               Name,                       ← captured as raw DER → issuerDer
    validity             Validity {
        notBefore        Time,                       ← skipped
        notAfter         Time                        ← captured → notAfter
    },
    ...                                              ← not reached
}
```

## Time Parsing

`_derReadTime` handles both encoding variants defined in RFC 5280 §4.1.2.5:

| Tag | Format | Year interpretation |
|-----|--------|---------------------|
| `UTCTime` (0x17) | `YYMMDDHHMMSSZ` | 00–49 → 2000–2049; 50–99 → 1950–1999 |
| `GeneralizedTime` (0x18) | `YYYYMMDDHHMMSSZ` | Four-digit year, taken as-is |

Only the date portion (`year`, `month`, `day`) is retained; the time-of-day and `Z` suffix are
discarded because 4D's `Date` type has no sub-day resolution and renewal decisions are day-grained.

## Relationship to ACMEJwsSigner

`ACMEJwsSigner` contains private copies of `_derExpectTag`, `_derReadLength`, and `_derReadInteger`
that remain in place to avoid a dependency from the JWS signing class on the ASN.1 reader. The two
sets of helpers are intentionally identical; any bug fix must be applied to both until the
`ACMEJwsSigner` copies are retired.

## Known Limitations

- **SHA-256 of issuerDer is not computed here.** `ACMEScheduler._buildAriUrl()` must hash
  `issuerDer` itself using the existing `_sha256Blob` helper (or equivalent) to produce the
  base64url `issuerKeyHash` required by RFC 8739.
- **Time zones.** All ACME-issued certificates use `Z` (UTC). The parser does not handle the rare
  non-UTC offset form; it would return `!00-00-00!` for such a certificate.
- **Parsing stops at `notAfter`.** Fields after `Validity` (subject, SPKI, extensions) are not
  read. Extend `parseCertificate()` if additional fields are needed in future.

Tracked in [`docs/review-findings.md`](../../docs/review-findings.md).
