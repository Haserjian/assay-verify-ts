# assay-verify

Independent TypeScript verifier for Assay proof packs.

## What This Is

A second implementation of the Assay pack verification contract, built from the contract specification and conformance corpus — not from reading the Python source.

This verifier proves that the Assay pack contract is portable across implementations. It does not define doctrine; it instantiates frozen doctrine.

## API

Two entry points:

```typescript
// Runtime-neutral core (Node + browser)
import { verifyPack, PackContents } from "assay-verify/dist/verify.js";
const result = verifyPack({ manifest, files }); // sync, no I/O

// Node convenience wrapper (reads files from disk)
import { verifyPackManifest } from "assay-verify/dist/verify.js";
const result = await verifyPackManifest("/path/to/pack"); // async, reads files
```

`verifyPack()` takes pre-loaded pack contents as `PackContents`:
- `manifest`: parsed `pack_manifest.json` object
- `files`: `ReadonlyMap<string, Uint8Array>` of filename → raw bytes

Browser callers load files via fetch/FileReader/drag-drop and call `verifyPack()` directly. No Node, no SubtleCrypto, no async required.

## What It Verifies

Given a 5-file proof pack:
- File hash integrity (SHA-256)
- Ed25519 signature verification (embedded pubkey)
- Attestation hash linkage
- Detached signature parity
- D12 invariant (pack_root_sha256 == attestation_sha256)
- Head hash computation and cross-check
- Receipt count cross-check
- Signer fingerprint verification
- Path containment

## Canonicalization

Uses **Assay JCS Profile v1** — based on RFC 8785 with one documented deviation in scientific notation formatting. See [CANONICALIZATION_PROFILE.md](CANONICALIZATION_PROFILE.md).

This is explicitly Assay canonicalization doctrine, not unqualified RFC 8785 conformance.

## Development

```bash
npm ci          # install exact deps from lockfile
npm run build   # compile TypeScript → dist/
npm test        # build + run all conformance tests
```

Tests run against the Assay conformance corpus. Locally, the default path is `~/assay/tests/contracts/vectors/`. Set `ASSAY_VECTORS_DIR` to override. In CI, the corpus is checked out from the `Haserjian/assay` repo automatically.

### CI

GitHub Actions runs `npm ci && npm run build && npm test` on Node 20 and 22, then re-runs conformance tests against a fresh checkout of the Assay corpus. See `.github/workflows/ci.yml`.

## Contract References

- Pack contract: `assay/docs/contracts/PACK_CONTRACT.md`
- Verification layers: `assay/docs/contracts/VERIFICATION_LAYERS.md`
- Conformance corpus: `assay/tests/contracts/vectors/`

## Dependencies

- `@noble/ed25519` — audited Ed25519 implementation
- `@noble/hashes` — SHA-512 for Ed25519 internals
- Node.js `crypto` — SHA-256
- Node.js >= 20

## Doctrine

Second implementations instantiate frozen doctrine. They do not discover it.

If this verifier disagrees with the Python reference on a corpus specimen, the investigation goes to the contract and corpus — not to either implementation's code.
