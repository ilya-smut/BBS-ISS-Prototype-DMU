# BBS Library Fix - ursa_bbs_signatures

This document explains the fixes applied to the `ursa_bbs_signatures` library within the local virtual environment (`.venv`) to enable proper blinded commitment verification.

## Issues Identified

1.  **API Handle Management**: In `ursa_bbs_signatures/api.py`, the `verify_blinded_commitment` function failed to pass the internal context `handle` to several FFI (Foreign Function Interface) calls. This resulted in `TypeError` during runtime.
2.  **FFI Type Inconsistency**: In `ursa_bbs_signatures/_ffi/bindings/bbs_verify_blind_commitment.py`, the function `bbs_verify_blind_commitment_context_set_public_key` was incorrectly typed to expect an `FfiByteBuffer` directly instead of `bytes`, and it lacked the necessary encoding step.

## Applied Fixes

### 1. `ursa_bbs_signatures/api.py`
The `verify_blinded_commitment` function was updated to correctly pass the `handle` to the following functions:
- `bbs_verify_blind_commitment_context_set_nonce_bytes`
- `bbs_verify_blind_commitment_context_set_proof`
- `bbs_verify_blind_commitment_context_set_public_key`

```python
# Before
bbs_verify_blind_commitment.bbs_verify_blind_commitment_context_set_nonce_bytes(request.nonce)
bbs_verify_blind_commitment.bbs_verify_blind_commitment_context_set_proof(request.proof)
bbs_verify_blind_commitment.bbs_verify_blind_commitment_context_set_public_key(request.public_key)

# After
bbs_verify_blind_commitment.bbs_verify_blind_commitment_context_set_nonce_bytes(handle, request.nonce)
bbs_verify_blind_commitment.bbs_verify_blind_commitment_context_set_proof(handle, request.proof)
bbs_verify_blind_commitment.bbs_verify_blind_commitment_context_set_public_key(handle, request.public_key.public_key)
```

### 2. `ursa_bbs_signatures/_ffi/bindings/bbs_verify_blind_commitment.py`
The `bbs_verify_blind_commitment_context_set_public_key` binding was updated to:
- Accept `bytes` as the second argument.
- Use `encode_bytes(public_key)` to convert the input to the required `FfiByteBuffer` format.

```python
# Before
def bbs_verify_blind_commitment_context_set_public_key(
    handle: int, public_key: FfiByteBuffer
) -> None:
    # ...
    func(handle, public_key, err)

# After
def bbs_verify_blind_commitment_context_set_public_key(
    handle: int, public_key: bytes
) -> None:
    # ...
    func(handle, encode_bytes(public_key), err)
```

## Additional Audit Fixes

Following a thorough check of the library, several other dormant bugs were identified and fixed to prevent future issues:

### 1. Copy-Paste Errors in FFI Bindings
- **`ursa_bbs_signatures/_ffi/bindings/bbs_blind_commitment.py`**: Fixed `bbs_blind_commitment_context_set_nonce_string` which was incorrectly calling the native function for setting the public key.
- **`ursa_bbs_signatures/_ffi/bindings/bbs_verify.py`**: Fixed `bbs_verify_context_add_message_bytes` which was incorrectly calling the native function for adding a message string.

### 2. Inconsistent Error Handling (`byref(err)`)
In several FFI binding files (`bbs_verify.py` and `bbs_verify_blind_commitment.py`), the `ExternError` structure was being passed by value instead of by reference (`byref(err)`). While this sometimes works by luck if `ctypes` performs implicit conversion, it is technically incorrect and can lead to undefined behavior. All these calls have been updated to use `byref(err)` consistently.

### 3. Missing Return Types
- **`ursa_bbs_signatures/_ffi/bindings/bbs_verify_proof.py`**: Added explicit `return_type=c_int32` to `bbs_get_total_messages_count_for_proof` for consistency.

## Verification
The existing library test suite was run after all fixes:
- **Total Tests**: 13
- **Result**: `OK` (All tests passed)

Combined with the earlier verification of the blinded commitment proof, the library is now in a much more stable and reliable state.
