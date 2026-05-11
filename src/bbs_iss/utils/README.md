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

### Cache-First Resolution Pattern

Entities follow a consistent resolution pattern:

1. Check local `PublicDataCache` for the Issuer's metadata.
2. **Cache hit** → proceed immediately with cached data.
3. **Cache miss** → suspend the current interaction, emit a `GetIssuerDetailsRequest`, and return it to the orchestrator (or caller) for delivery to the Registry.
4. When the `IssuerDetailsResponse` arrives, update the cache and automatically resume the suspended interaction.
