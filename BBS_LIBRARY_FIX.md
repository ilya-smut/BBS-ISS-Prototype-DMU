# BBS Library Fixes (`ursa_bbs_signatures`)

This document details the bug fixes and modifications applied to the official `ursa_bbs_signatures` Python wrapper. These fixes resolve critical FFI (Foreign Function Interface) bugs and memory safety issues that originally prevented the verification of blinded commitments from functioning. 

The patched library is now vendored within this project as a Git Submodule under `vendor/ffi-bbs-signatures`.

## 1. API Corrections (`api.py`)

### Missing Context Handles
**Bug:** The `verify_blinded_commitment` function initialized an FFI context handle but failed to pass it to subsequent setter functions.
**Fix:** Added the `handle` argument as the first parameter to `bbs_verify_blind_commitment_context_set_nonce_bytes`, `set_proof`, and `set_public_key`.
**Reason:** Without passing the handle, the C library attempted to operate on undefined memory, immediately causing a Python `TypeError` and entirely breaking the blinded commitment verification flow.

### Public Key Extraction
**Bug:** `verify_blinded_commitment` passed the entire `PublicKey` wrapper object into the FFI instead of the raw key bytes.
**Fix:** Altered the call to pass `request.public_key.public_key`.
**Reason:** FFI bindings expect raw byte buffers, not Python class instances.

### Return Type Parsing
**Bug:** Verification functions incorrectly returned a raw boolean (`result == 0`) which didn't map to the library's internal status enums.
**Fix:** Modified the return to utilize the `SignatureProofStatus(result)` enum.
**Reason:** This ensures the Python implementation correctly interprets integer status codes (like invalid proofs vs. system errors) returned by the Rust backend.

### Enum Value Reversion (`SignatureProofStatus.py`)
**Bug:** A previous commit erroneously changed the enum values in `SignatureProofStatus` from HTTP-like status codes (`200`, `400`, `401`, `402`) to sequential integers (`0`, `1`, `2`, `3`). This caused a `ValueError` when parsing the Rust backend's successful verification response (`200`).
**Fix:** Reverted the enum values back to their original `200`, `400`, `401`, `402` mapping.
**Reason:** The underlying Rust cryptography engine returns these specific HTTP-like integer codes. The Python wrapper must match them exactly to prevent runtime crashes during verification.

## 2. FFI Binding Corrections (`_ffi/bindings/`)

### C-Types Memory Safety (`byref`)
**Bug:** Across multiple FFI bindings (`bbs_blind_commitment.py`, `bbs_verify.py`, `bbs_verify_blind_commitment.py`), the `ExternError` structure was passed by value into the native functions instead of by reference.
**Fix:** Updated all `err` arguments to explicitly use `byref(err)`.
**Reason:** Passing C-structs by value to functions expecting pointers causes undefined behavior and memory corruption. While Python's `ctypes` sometimes implicitly allows this, it is technically invalid and causes silent failures.

### Incorrect Input Types (`bbs_verify_blind_commitment.py`)
**Bug:** `bbs_verify_blind_commitment_context_set_public_key` expected a pre-encoded `FfiByteBuffer` instead of raw Python `bytes`.
**Fix:** Altered the Python wrapper method signature to accept `bytes`, and internally wrapped the argument with `encode_bytes(public_key)` before calling the native C function.
**Reason:** This standardizes the internal API to accept standard Python types while pushing memory allocation concerns down into the FFI utilities.

### Copy-Paste Native Function Errors
**Bug:** Two bindings were calling the wrong underlying Rust functions:
- In `bbs_blind_commitment.py`, `bbs_blind_commitment_context_set_nonce_string` was incorrectly calling the native `set_public_key` function.
- In `bbs_verify.py`, `bbs_verify_context_add_message_bytes` was incorrectly calling `add_message_string`.
**Fix:** Updated the bindings to invoke the correct C function pointers.
**Reason:** Calling the wrong C function causes data to be routed to the wrong internal Rust structs, resulting in cryptic "Unexpected Information" verification exceptions.

### Missing Return Definitions (`bbs_verify_proof.py`)
**Bug:** `bbs_get_total_messages_count_for_proof` lacked a defined C return type.
**Fix:** Added explicit `func.restype = c_int32`.
**Reason:** `ctypes` defaults to returning standard integers, but explicitly defining sizes prevents stack alignment and pointer truncation issues across different architectures.

### Missing c_int32 Import (`bbs_verify_proof.py`)
**Bug:** The `c_int32` type was used in `bbs_get_total_messages_count_for_proof` but never imported from `ctypes`.
**Fix:** Added `c_int32` to the `ctypes` import statement at the top of the file.
**Reason:** Attempting to retrieve the total message count from a proof threw a `NameError`, preventing VP verification requests from being constructed.

## 3. Native Binary Bundling

**Addition:** A pre-compiled `libbbs.so` binary has been bundled directly into `vendor/ffi-bbs-signatures/wrappers/python/ursa_bbs_signatures/`.
**Reason:** The official `ursa_bbs_signatures` package requires a local Rust toolchain to compile the underlying cryptography engine from source. Bundling the Linux `.so` shared object library bypasses this, allowing the Prototype to run out-of-the-box without forcing users to configure Rust.
