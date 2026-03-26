# Assay JCS Profile v1

**Status**: Active. This is the canonicalization profile used by `assay-ai` 1.19.0 and the `assay-verify` TypeScript implementation.

## Relationship to RFC 8785

Assay canonicalization is **based on RFC 8785** (JSON Canonicalization Scheme) with one enumerated deviation. It is not unqualified RFC 8785 conformance.

The conformance corpus validates Assay JCS Profile v1 behavior, not raw RFC 8785 behavior.

## Deviation: Scientific Notation Exponent Format

| Property | RFC 8785 (ECMAScript-native) | Assay JCS Profile v1 |
|----------|------------------------------|---------------------|
| Exponent character | Lowercase `e` | Uppercase `E` |
| Positive exponent sign | Explicit `+` (e.g., `1e+21`) | No `+` (e.g., `1E21`) |
| Negative exponent sign | `-` (e.g., `1e-7`) | `-` (e.g., `1E-7`) |

**Example**:
- RFC 8785 / ECMAScript: `{"a":1e+21}` and `{"a":1e-7}`
- Assay JCS Profile v1: `{"a":1E21}` and `{"a":1E-7}`

**Origin**: The Python reference implementation (`assay._receipts.jcs._encode_number`) uses `Decimal`-based formatting which produces uppercase `E` without explicit `+` sign. This behavior was frozen into the conformance corpus before the deviation was identified.

**Scope**: This deviation only affects numbers whose absolute value has an adjusted exponent > 20 or < -6 (the thresholds where plain notation switches to scientific notation per RFC 8785). Receipt payloads rarely contain such numbers.

**Evidence**: RFC 8785 Section 3.2.3 examples show `1e+30` and `1e-27` (lowercase, explicit +). ECMAScript's `JSON.stringify(1e21)` produces `1e+21`. The V8 reference cited by RFC 8785 produces the same lowercase form.

## All Other Behavior

All other canonicalization behavior matches RFC 8785:
- Object keys sorted by UTF-16 code unit order
- Compact separators (no whitespace)
- Non-finite numbers rejected
- Non-string keys rejected
- Negative zero serializes as `0`
- Strings use `JSON.stringify` escaping (non-ASCII passes through unescaped)
- Number formatting follows RFC 8785 thresholds (-6 ≤ adjusted ≤ 20 → plain notation)

## Versioning

| Profile | Behavior | Status |
|---------|----------|--------|
| `assay-jcs-v1` | Uppercase `E`, no `+` sign | **Active** — current corpus and all implementations |
| `assay-jcs-v2` (future) | RFC 8785 / ECMAScript-native form | Not yet implemented. Migration would require re-hashing any packs containing scientific-notation numbers and re-signing affected manifests. |

## Implementation Notes

**Python** (`assay._receipts.jcs._encode_number`): Produces v1 behavior natively via `Decimal` formatting.

**TypeScript** (`jcs.ts`): JavaScript's `JSON.stringify` produces RFC-native form. A transform converts `e+` → `E` and `e-` → `E-` to match Assay JCS Profile v1.

Both implementations must produce identical bytes for the same input. The conformance corpus is the arbiter.
