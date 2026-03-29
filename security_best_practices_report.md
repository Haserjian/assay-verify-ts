# Assay Crypto and Key Audit

## Executive Summary

I reviewed the TypeScript verifier and the local Assay key store with a focus on cryptography, signature handling, and key management.

Confirmed issues:

1. The verifier can throw on malformed base64 key material instead of returning a structured failure.
2. The active local signing key file is world-readable on disk.
3. The verifier does not enforce any external trust anchor for signer identity; it only checks self-consistency of the embedded key and signature.

## Findings

### 1. High: malformed `signature` / `signer_pubkey` can crash verification

Evidence:

- `base64Decode()` calls `atob()` directly with no error boundary in [verify-core.ts](/Users/timmymacbookpro/assay-verify-ts/src/verify-core.ts#L83).
- `verifyPack()` decodes `manifest.signature` before any `try/catch` in [verify-core.ts](/Users/timmymacbookpro/assay-verify-ts/src/verify-core.ts#L405-L406).
- `verifyPack()` decodes `manifest.signer_pubkey` the same way in [verify-core.ts](/Users/timmymacbookpro/assay-verify-ts/src/verify-core.ts#L443-L444).

Impact:

- A malicious pack with schema-valid but invalid base64 in either field can terminate the verifier with an exception instead of producing a normal `VerifyResult`.
- I reproduced this locally with `signature: "%%%"`; the verifier threw `InvalidCharacterError` rather than returning `passed: false`.

Recommendation:

- Wrap both decode sites in explicit validation or `try/catch`.
- Return `E_PACK_SIG_INVALID` for malformed base64 so untrusted input cannot turn verification into a process-level failure.

### 2. High: active private key file is world-readable on disk

Evidence:

- `/Users/timmymacbookpro/.assay/keys/.active_signer` points to `assay-local`.
- `/Users/timmymacbookpro/.assay/keys/assay-local.key` is mode `0644`.
- The sibling private key files `assay-demo.key` and `test-signer.key` are `0600`, so `assay-local.key` is the outlier.

Impact:

- If `assay-local.key` is a live private signing key or seed, any local user/process can read it.
- That is a key-exposure condition, not just a hygiene issue.

Recommendation:

- Restrict private key files to `0600` or tighter.
- Confirm that the active signer path never stores long-lived private material in a world-readable location.
- If this file is only a test artifact, move it out of the active signer path and label it explicitly as non-sensitive.

### 3. Medium: signer identity is not bound to a trusted key root

Evidence:

- The schema requires `signer_id`, `signer_pubkey`, and `signer_pubkey_sha256` in [schema-definitions.ts](/Users/timmymacbookpro/assay-verify-ts/src/schema-definitions.ts#L165-L171), [schema-definitions.ts](/Users/timmymacbookpro/assay-verify-ts/src/schema-definitions.ts#L239-L246).
- `verifyPack()` only checks that the embedded public key matches the embedded fingerprint and that the signature validates under that same embedded key in [verify-core.ts](/Users/timmymacbookpro/assay-verify-ts/src/verify-core.ts#L440-L459).
- I did not find any allowlist, trust store, or external key pinning in the verifier.

Impact:

- The verifier proves internal consistency, not signer provenance.
- If downstream consumers believe `signer_id` or the fingerprint field implies a trusted identity, that expectation is not enforced here.

Recommendation:

- If provenance matters, add an external trust anchor or pinned signer registry.
- If provenance is intentionally out of scope, document that this verifier only checks self-consistency of a pack-supplied keypair.

### 4. High: dev signing and TSA private keys are committed in `loom-publish`

Evidence:

- The repo tracks private PEMs at [dev_signing_ed25519.pem](/Users/timmymacbookpro/loom-publish/tools/receipts/keys/dev/dev_signing_ed25519.pem) and [dev_tsa_ed25519.pem](/Users/timmymacbookpro/loom-publish/tools/receipts/keys/dev/dev_tsa_ed25519.pem).
- `git ls-files` confirms both files are versioned.
- [tools/receipts/keyring.py](/Users/timmymacbookpro/loom-publish/tools/receipts/keyring.py#L27-L35) defaults the active profile to `dev` and points that profile at those PEMs.
- I inspected the file headers; both are PEM-encoded `PRIVATE KEY` material.

Impact:

- Anyone with repo access gets the signing and TSA private keys.
- Because the default profile is `dev`, the insecure path is also the default path.

Recommendation:

- Remove private keys from the repository.
- Replace them with generated test fixtures, mocks, or environment-provided secrets.
- Make `prod` the only path for real signing and require explicit operator opt-in for any dev key material.

### 5. High: signing seeds are stored in plaintext JSON without permission hardening

Evidence:

- [api/keys/store__keys.py](/Users/timmymacbookpro/loom-publish/api/keys/store__keys.py#L36-L38) sets the default signing-store path to `api/keys/signing_keys.json`.
- The signing store writes private seed material into that JSON in `_save_locked()` with a plain `open("w")` call in [store__keys.py](/Users/timmymacbookpro/loom-publish/api/keys/store__keys.py#L648-L652).
- `set_key()` serializes the seed directly into the `"seed"` field in [store__keys.py](/Users/timmymacbookpro/loom-publish/api/keys/store__keys.py#L725-L746).

Impact:

- The private signing material is stored in cleartext base64 on disk.
- File creation uses the process umask, not an explicit restrictive mode, so the exposure depends on runtime defaults rather than code policy.

Recommendation:

- Store private seeds outside the repository, encrypt them at rest, and create them with restrictive permissions.
- If the store is meant for non-prod only, make that explicit and keep it isolated from any production runtime.

### 6. High: privacy sealing is wired in, but the implementation is still a placeholder

Evidence:

- `engine/sensing/context.py` calls `seal_value()` on active privacy paths in [context.py](/Users/timmymacbookpro/loom-publish/engine/sensing/context.py#L292-L309).
- `seal_value()` itself is a placeholder that returns a plain dict, not a sealed object, in [receipts/privacy.py](/Users/timmymacbookpro/loom-publish/receipts/privacy.py#L82-L102).
- `seal_sensitive_payload()` is also a no-op placeholder in [receipts/privacy.py](/Users/timmymacbookpro/loom-publish/receipts/privacy.py#L58-L79).
- `receipts/writer.py` calls `seal_sensitive_payload()` during payload canonicalization in [writer.py](/Users/timmymacbookpro/loom-publish/receipts/writer.py#L533-L543).

Impact:

- The privacy path is not cryptographic protection yet.
- In `engine/sensing/context.py`, the current return shape is incompatible with the caller's `.digest` / `.envelope` access, so privacy-mode execution is likely to fail at runtime if that branch is exercised.
- In `receipts/writer.py`, the current no-op means sensitive payloads are not actually sealed before write-out.

Recommendation:

- Replace the placeholder with a real envelope format and a real sealing primitive.
- Add tests that assert the sealed payload cannot be recovered from the plaintext path and that privacy-mode execution does not crash.

## Notes

- The Ed25519 and SHA-256 primitives themselves look standard.
- I did not find evidence of custom crypto primitives or homegrown signature algorithms.
- I did not inspect the contents of `/Users/timmymacbookpro/.assay/keys/*.key`; the key-risk finding above is based on file naming, pairing, and permissions.
