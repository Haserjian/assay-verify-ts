# Open Work Items

## 1. Manifest schema / normalization gate

**Priority**: Medium
**Context**: The verifier currently uses `Array.isArray()` guards to handle malformed manifest fields. A proper approach would validate manifest shape structurally before any semantic verification begins.

**Desired state**:
1. Parse raw manifest JSON
2. Validate required fields and types (schema gate)
3. Produce typed internal manifest OR structured shape errors
4. Only then run containment, hash, signature, and attestation checks

**Benefit**: Reduces scattered type guards. Makes proof tiers cleaner (structural validity → containment → content integrity → semantic validity). Aligns with PACK_CONTRACT §11 step 0 (schema validation).

## 2. Explicit structural error codes

**Priority**: Low-Medium
**Context**: When manifest fields have wrong types (e.g., `files: "not-an-array"`), the verifier currently falls through to downstream errors or silent empty-array coercion. It should emit specific codes.

**Proposed codes**:
- `E_MANIFEST_SHAPE` — manifest field has wrong type or missing required field
- `E_MANIFEST_FILES_SHAPE` — `files` is not an array or entries lack required fields
- `E_MANIFEST_EXPECTED_FILES_SHAPE` — `expected_files` is not an array

**Benefit**: Makes the verifier useful as a diagnostic tool, not just a pass/fail gate. Enables clearer conformance testing of structural rejection behavior.
