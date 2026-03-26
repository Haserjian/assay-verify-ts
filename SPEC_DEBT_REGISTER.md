# Spec Debt Register

Tracked deviations from external standards and known protocol debt.

## Active Debt

### SD-1: Assay JCS Profile v1 — Exponent Formatting

**Standard**: RFC 8785 (JSON Canonicalization Scheme)
**Deviation**: Scientific notation uses uppercase `E` without explicit `+` sign (`1E21` instead of `1e+21`)
**Origin**: Python's `Decimal`-based number formatting produces uppercase `E`. Frozen into conformance corpus before deviation was identified.
**Blast radius**: Only affects numbers with adjusted exponent > 20 or < -6. Receipt payloads rarely contain such numbers.
**Migration trigger**: External system requires strict RFC 8785 interop for Assay evidence
**Exit path**: Assay JCS Profile v2 with RFC-native formatting. Requires re-hashing affected packs and re-signing manifests. Both Python and TS implementations would need updates.
**Current status**: Documented in CANONICALIZATION_PROFILE.md and PACK_CONTRACT §3. Both implementations match the v1 profile.

### SD-2: Duplicate Receipt ID Error Surface

**Standard**: PACK_CONTRACT §12-§13
**Deviation**: Python surfaces duplicate receipt_id as `E_MANIFEST_TAMPER` on `receipt_integrity` (pack-level cross-check). TypeScript surfaces it as `E_DUPLICATE_ID` (direct detection).
**Origin**: Python's `verify_pack_manifest` doesn't propagate receipt-level errors to the pack result.
**Blast radius**: One adversarial specimen (`duplicate_receipt_id`). Fault class agreement is maintained.
**Migration trigger**: Third implementation or buyer requires exact error-code matching
**Exit path**: Propagate receipt-level errors in Python's pack verifier, or formalize fault-class comparison as the canonical cross-implementation surface.
**Current status**: Documented in PACK_CONTRACT §13. Both implementations agree on fault class.

## Resolved Debt

None currently. Debt items are resolved by either fixing the deviation or explicitly promoting the deviation to permanent contract behavior with a version bump.
