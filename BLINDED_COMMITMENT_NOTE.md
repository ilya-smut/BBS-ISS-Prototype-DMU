# Note on Blinded Commitment Verification and Potential Data Leakage

## Context
In the `ursa_bbs_signatures` library, the `VerifyBlindedCommitmentRequest` model takes a list of `blinded_indices` as `IndexedMessage` objects. Each `IndexedMessage` contains both an `index` (int) and a `message` (str).

## Analysis of `ursa_bbs_signatures`
A technical analysis of the library's Python wrapper reveals the following:
- **Consistency**: The library uses `IndexedMessage` for all index-related parameters to maintain API consistency, even when the actual message value is not required.
- **Implementation**: In `ursa_bbs_signatures/api.py`, the `verify_blinded_commitment` function iterates through the `blinded_indices` and **only extracts the `.index` field**.
- **Security**: The `.message` field is ignored by the library and is never passed to the underlying FFI (Foreign Function Interface) calls. Therefore, the cryptographic verification process remains blind.

## Potential Risk in Prototype Implementation
While the library handles the data safely internally, there is a **data leakage risk** at the application level during transport:
- If a `BlindSignRequest` or `VerifyBlindedCommitmentRequest` is populated with actual secret values (as currently done in `src/bbs_iss/interfaces/requests_api.py`) and then serialized (e.g., to JSON) for network transmission, the **secret values will be exposed in the serialized data**.
- Even though the receiver's BBS library will ignore these values, any intermediary or log-capturing system will see the "blinded" messages in plain text.

## Recommendation
To ensure true blindness during transmission:
1.  The Prover (client) should strip the message values from `blinded_indices` before sending the request.
2.  This can be done by creating new `IndexedMessage` objects with dummy strings (e.g., `""`) for the `message` field, while keeping the correct `index`.

---
*Date: 2026-03-20*
