# Utils — Utility Functions & Cache Manager

This package provides cryptographic utility functions and the in-memory public data cache used by Holders and Verifiers.

## `utils.py` — Cryptographic Utilities

| Function | Parameters | Returns | Description |
|----------|-----------|---------|-------------|
| `gen_link_secret(size=32)` | `int` | `str` | Generates a hex-encoded random link secret via `os.urandom`. |
| `gen_nonce()` | — | `bytes` | Returns 32 bytes of OS randomness. Used by Issuers and Verifiers for session freshness and challenge nonces. |

## `cache.py` — PublicDataCache

An in-memory manager for `IssuerPublicData` records. Used by Holders and Verifiers to implement a "Cache-First, Registry-Second" resolution strategy.

### Cache Entries

Each cached record is stored as a `CacheEntry` dataclass containing:

| Field | Type | Description |
|-------|------|-------------|
| `data` | `IssuerPublicData` | The issuer's public metadata |
| `obtained_at` | `datetime` | UTC timestamp of when the record was cached |

### Methods

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `update(issuer_name, data)` | `str`, `IssuerPublicData` | — | Upserts a record with a current UTC timestamp |
| `get(issuer_name)` | `str` | `IssuerPublicData \| None` | Returns metadata on hit, `None` on miss |
| `get_entry(issuer_name)` | `str` | `CacheEntry \| None` | Returns the full entry including timestamp |
| `clear()` | — | — | Purges all cached records |
| `get_cache_info()` | — | `str` | Formatted summary of all cached issuers |
| `check_bit_index(issuer, bit_index_hex)` | `str`, `str` | `bool` | Revocation status check via cached bitstring. Raises `IssuerNotFoundInCacheError` if not cached. |

### Cache-First Resolution Pattern (Technical Detail)

The "Cache-First, Registry-Second" resolution is implemented as a **Stateful Suspension** pattern in `holder.py` and `verifier.py`:

1. **Detection**: During `issuance_request()` (Holder) or `complete_presentation()` (Verifier), the entity calls `self.cache.get(issuer_name)`.
2. **Suspension**: If the cache returns `None`, the entity:
   - Sets its internal state to a "suspended" mode (e.g., `State.pending_issuer_name = issuer_name` or `State.queued_response = vp`).
   - Short-circuits the method by returning a `GetIssuerDetailsRequest`.
3. **External Action**: The Orchestrator receives the request, delivers it to the Registry, and receives an `IssuerDetailsResponse`.
4. **Resumption**: The Orchestrator passes the response back into the entity's `process_request()`. The entity:
   - Updates its local cache with the new data.
   - **Auto-Trigger**: Detects the suspended state, pulls the parked parameters/VP, and re-invokes the original logic (e.g., `_complete_presentation_internal()`), ensuring the protocol flow resumes seamlessly from where it stalled.
