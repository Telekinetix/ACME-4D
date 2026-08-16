# ACMEAccount

Manages the ACME account key pair and registration state for the `tk-acme` component.

The account key is a 2048-bit RSA key pair generated once per deployment and persisted to the store path. It is reused for all requests to the same CA — there is no expiry on the account key itself.

## Persistent Storage Layout

```
<storePath>/
  account-key.pem    ← RSA private key (NEVER appears in logs)
  account.json       ← Registration metadata (no key material)
```

`account.json` schema:
```json
{
  "accountUrl": "https://acme-v02.api.letsencrypt.org/acme/acct/123456",
  "email":      "admin@example.com",
  "createdAt":  "2026-03-15",
  "ca":         "https://acme-v02.api.letsencrypt.org/directory"
}
```

## Constructor

```4d
var $account : cs.acme.ACMEAccount
$account:=cs.acme.ACMEAccount.new($config; $logger)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$config` | `cs.acme.ACMEConfig` | Configuration (used for `effectiveStorePath()` and `contactEmail`) |
| `$logger` | `cs.acme.ACMELogger` | Shared logger |

## Properties

| Property | Type | Description |
|----------|------|-------------|
| `accountUrl` | Text | Account URL (`kid`) — set after registration |
| `email` | Text | Contact e-mail registered with the CA |
| `isRegistered` | Boolean | `True` once a valid account URL has been loaded or registered |

## Public Functions

### load

Attempts to load the account key and registration metadata from the store path.

```4d
var $found : Boolean
$found:=$account.load()
If (Not($found))
    $account.generateKey()
End if
```

| | Type | Description |
|---|---|---|
| **Return** | Boolean | `True` if both `account-key.pem` and `account.json` were found and valid |

---

### save

Writes the account key (to `account-key.pem`) and metadata (to `account.json`) to the store path. Creates the store directory if it does not exist.

```4d
$account.save()
```

> Call this after a successful `register()` call, and again if the account details change.

---

### generateKey

Generates a new 2048-bit RSA key pair and holds it in memory. Call this when `load()` returns `False`.

```4d
$account.generateKey()
// then:
$account.save()
```

---

### privateKeyPem

Returns the private key PEM string held in memory.

```4d
var $pem : Text
$pem:=$account.privateKeyPem()
// Pass to ACMEJwsSigner.new() — DO NOT log this value
```

| | Type | Description |
|---|---|---|
| **Return** | Text | RSA private key PEM. **Never log.** |

---

### register

Registers a new account with the CA or confirms an existing one (RFC 8555 §7.3). On success, switches the signer to KID mode and sets `isRegistered = True`.

```4d
var $result : Object
$result:=$account.register($transport; $signer)
If ($result.success)
    $account.save()
End if
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `$transport` | `cs.acme.ACMETransport` | Wired transport for sending `newAccount` POST |
| `$signer` | `cs.acme.ACMEJwsSigner` | Signer instance — `setKid()` is called on it when the account URL is obtained |

| | Type | Description |
|---|---|---|
| **Return** | Object | `{ success: Boolean, accountUrl: Text, error: Text }` |

Both HTTP 201 (new account) and HTTP 200 (existing account) are treated as success — this makes the registration call idempotent.

## Security Notes

- `account-key.pem` must have filesystem permissions restricted to the 4D process user. The component creates the file but does not set permissions — this is the deployer's responsibility.
- The private key is never included in `account.json` or any log entry.
- To rotate the account key, delete `account-key.pem` and `account.json` from the store path and call `setup()` again. The CA will create a new account.
