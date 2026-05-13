# Verifier UI

This subdirectory contains the Flask-based web interface for the **Verifier** entity. It provides an interface for requesting presentations and inspecting verification results with advanced ABAC enforcement.

## Architecture & Integration

The application is initialized via `create_verifier_ui(orch: VerifierOrchestrator, port=8003)` in `app.py`.

### Technical Implementation: ABAC Engine
The Verifier dashboard extends standard cryptographic ZKP verification with an **Attribute-Based Access Control (ABAC)** policy engine. This logic is implemented in the `VerifierAppState._build_enriched_result()` method.

#### 1. Exact Matching
For most attributes, the engine performs a standard case-sensitive string comparison between the disclosed value in the `VerifiablePresentation` and the `expected_val` defined in the verifier's policy.

#### 2. Date of Birth Predicates
The `dateOfBirth` attribute receives specialized chronological handling.
- **Regex Parsing**: The policy string is parsed using the pattern: `r'^(<=|>=|<|>|==)?(\d{2}-\d{2}-\d{4})$'`.
- **Validation**:
  - The disclosed value must be in strict `DD-MM-YYYY` format.
  - The target date in the policy must also be in strict `DD-MM-YYYY` format.
  - Failure to parse either date results in an immediate ABAC failure.
- **Comparison Logic**: Parsed dates are converted to `datetime` objects and compared using the extracted operator.

#### 3. Granular Result Feedback
Instead of a monolithic pass/fail, the backend populates an `abac_mismatches` list.
- **Rationale**: This allows the UI to maintain high usability by highlighting exactly which fields violated the policy (rendered in red) while keeping successful matches blue, even if the strings aren't identical (e.g., in a predicate match).

## Endpoints & Workflows

### 1. Dashboard (`GET /`)
- **Active Request Panel**: If the verifier is in an "awaiting" state, this panel pulses. It auto-refreshes every 3 seconds by polling `/api/verification-results`.
- **Presentation Results**: Expandable records showing the overall validity and a detailed breakdown of checks (BBS+ Proof, Field Completeness, Expiration, Revocation, and ABAC).

### 2. Request Presentation (`GET /request`, `POST /request`)
- **Dynamic Field Selection**: The form uses the cached `CredentialSchema` to generate checkboxes for each revealable attribute.
- **ABAC Toggle**: Enabling the ABAC checkbox reveals input fields for specifying the policy.
- **Front-end Validation**: The `request.html` template includes JavaScript regex validation to ensure that `dateOfBirth` predicates are correctly formatted before submission.

### 3. Verification & Completion
When a `ForwardVPResponse` arrives at the protocol listener (port 5002), the listener delegates to `orch.complete_presentation()`.
- **Resolution Strategy**: If the VP comes from an unknown issuer, the verifier automatically suspends verification, resolves the issuer via the Registry, and resumes once the public key is cached.

## Templates & Assets
- `templates/dashboard.html`: Verification results overview with granular field highlighting.
- `templates/request.html`: Schema-driven request builder with ABAC predicate support.
- `static/style.css`: Shared terminal aesthetic.
