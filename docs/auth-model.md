# LumenFlow Auth Model

Every contract function and its required authorisation.

| Function | Required Auth | Notes |
|---|---|---|
| `set_admin` | `admin` (one-time) | Caller must be the address being set as admin; fails if admin already set |
| `set_payment_cleanup_period` | Admin | |
| `set_large_payment_threshold` | Admin | |
| `set_max_refunds_per_order` | Admin | |
| `register_merchant` | `merchant_address` | Self-registration only |
| `deactivate_merchant` | Admin | |
| `verify_merchant` | Admin | |
| `unverify_merchant` | Admin | |
| `get_merchant` | None | Public read |
| `is_registered` | None | Public read |
| `process_payment_with_signature` | `payer` | Also verifies merchant ed25519 signature over payload |
| `batch_payment` | `payer` | Also verifies per-item merchant ed25519 signatures |
| `get_payment_by_id` | `caller` (payer, merchant, or admin) | Returns `Unauthorized` for anyone else |
| `get_payment_summary` | None | Public summary (no payer address exposed) |
| `update_payment_status` | Admin or merchant | |
| `archive_payment_record` | Admin | |
| `cleanup_expired_payments` | Admin | |
| `get_merchant_payment_history` | `merchant` | Own history only |
| `get_payer_payment_history` | `payer` | Own history only |
| `get_global_payment_stats` | Admin | |
| `initiate_refund` | `caller` (payer or merchant) | Enforced by identity check after auth |
| `approve_refund` | Admin or merchant | |
| `reject_refund` | Admin or merchant | |
| `execute_refund` | `merchant_address` (implicit via `require_auth` on transfer) | |
| `get_refund` | None | Public read |
| `initiate_multisig_payment` | `initiator` | |
| `sign_multisig_payment` | `signer` (must be in signers list) | |
| `get_multisig_payment` | `caller` (admin, merchant, or signer) | |
| `execute_multisig_payment` | `payer` | |
| `create_payment_request` | `merchant` | |
| `pay_payment_request` | `payer` | |

## Auth Helpers (`helper.rs`)

| Helper | Behaviour |
|---|---|
| `require_admin` | Reads stored admin; returns `Unauthorized` if caller doesn't match or admin not set |
| `require_admin_or(caller, other)` | Passes if caller is admin **or** equals `other` |

---

## SEP-0010 Web Authentication

[SEP-0010](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0010.md) is the Stellar Ecosystem Proposal for web authentication. It allows any Stellar-compliant wallet to prove ownership of an account address without signing an on-chain transaction. LumenFlow uses SEP-0010 tokens to authenticate users on the frontend, decoupling authentication from Freighter-only flows.

### Supported Wallets

| Wallet | Identifier | Notes |
|---|---|---|
| Freighter | `freighter` | Default browser extension wallet |
| LOBSTR Vault | `lobstr` | Browser extension + mobile |
| Solar Wallet | `solar` | Desktop + mobile |

### Challenge–Response Flow

```
┌────────┐          ┌──────────────┐          ┌──────────────┐
│ Client │          │ Auth Server  │          │   Wallet     │
└───┬────┘          └──────┬───────┘          └──────┬───────┘
    │  GET /?account=G...  │                         │
    │─────────────────────>│                         │
    │  { transaction, network_passphrase }            │
    │<─────────────────────│                         │
    │                      │  signTransaction(xdr)   │
    │────────────────────────────────────────────────>
    │  signed XDR          │                         │
    │<────────────────────────────────────────────────
    │  POST / { transaction: signedXdr }              │
    │─────────────────────>│                         │
    │  { token: "eyJ..." } │                         │
    │<─────────────────────│                         │
```

1. The client GETs `{WEB_AUTH_ENDPOINT}?account={account}` — the server returns an unsigned challenge transaction XDR and the network passphrase.
2. The client passes the XDR to the active wallet for signing.
3. The signed XDR is POSTed back to `{WEB_AUTH_ENDPOINT}` — the server verifies the signature and returns a JWT.
4. The JWT is cached in `sessionStorage` with a 24-hour expiry.

### JWT Caching

Tokens are stored in `sessionStorage` under the key `lumenflow_jwt_{account}`. Each cached entry includes the JWT string and an `expiresAt` Unix timestamp. A token is considered expired when `Date.now() >= expiresAt`. On expiry the entry is automatically removed and a fresh challenge is initiated.

```javascript
// Retrieve a valid cached token (returns null if absent or expired)
const token = getStoredToken('GABC...');

// Manually invalidate a token (e.g. on logout)
clearToken('GABC...');
```

### Using the Unified `authenticate()` Helper

`frontend/lumenflow-shared.js` exports `authenticate(account, walletType)` which handles the full flow:

```javascript
import { authenticate, SUPPORTED_WALLETS } from './lumenflow-shared.js';

// Using Freighter (default)
const { token, fromCache } = await authenticate('GABC...', SUPPORTED_WALLETS.FREIGHTER);

// Using LOBSTR
const { token } = await authenticate('GABC...', SUPPORTED_WALLETS.LOBSTR);

// Using Solar Wallet
const { token } = await authenticate('GABC...', SUPPORTED_WALLETS.SOLAR);

// Attach the token to API/RPC requests
fetch('/api/payments', {
  headers: { Authorization: `Bearer ${token}` },
});
```

If `LUMENFLOW_WEB_AUTH_ENDPOINT` is not configured, `authenticate()` returns a demo token so pages render correctly during local development without a live auth server.

### Configuring the Auth Endpoint

Set `window.LUMENFLOW_WEB_AUTH_ENDPOINT` before loading `lumenflow-shared.js`:

```html
<script>
  window.LUMENFLOW_WEB_AUTH_ENDPOINT = 'https://auth.lumenflow.io';
</script>
<script src="lumenflow-shared.js"></script>
```

Or inject via a server-side template / build-time environment variable.
