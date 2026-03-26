# Protocol Invariants

Hard rules for the Assay verification protocol. These do not soften.

1. **Descriptive metadata never changes verifier dispatch.** Fields like `hash_alg`, `signature_alg`, `canon_version`, and `signature_scope` are informational. Verifier behavior is defined by the contract, not by field values. (OCD-10)

2. **All proof-critical omissions fail explicitly.** If an attestation claims a value and the verifier cannot recompute the comparator, that is an explicit error — never a silent skip, never a degraded pass.

3. **Verdict comparison is normalized at the fault-class layer.** Implementations MUST agree on pass/fail and canonical fault class. Raw error codes SHOULD converge but MAY differ where explicitly documented. (PACK_CONTRACT §12-§13)

4. **The portable verifier surface must remain runtime-neutral.** `verifyPack(PackContents)` has zero Node imports, zero SubtleCrypto dependency, zero async requirement. That boundary is load-bearing.

5. **Corpus is normative for mechanical behavior.** If two implementations disagree on a corpus specimen, the investigation goes to the contract and corpus — not to either implementation's code.

6. **Named deviations from external standards must remain explicit.** Assay JCS Profile v1 deviates from RFC 8785 on scientific notation exponent formatting. That deviation is documented, versioned, and tracked in SPEC_DEBT_REGISTER.md. No new deviations may be introduced silently.

7. **Second implementations instantiate frozen doctrine. They do not discover it.** If a second implementation reveals an ambiguity, the fix goes into the contract docs and corpus first, then both implementations conform.
