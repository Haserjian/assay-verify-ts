# Browser Demo Non-Goals

The browser verifier demo is a conformance probe, not a product.

## What it IS

- Client-side proof pack verification with zero backend
- Stage-by-stage audit trace visible to non-implementers
- First hostile-runtime test of the verification contract
- Proof that Assay evidence is independently checkable

## What it is NOT

- Not a pack builder or pack editor
- Not a general file manager or file browser
- Not a trust-chain management UI
- Not a publishing / sharing / collaboration flow
- Not long-term storage or pack archive
- Not a replacement for CLI verification (`assay verify-pack`)
- Not a framework-based application (no React, no Vue, no build system)
- Not a polished product UX (no auth, no persistence, no state)

## Acceptance Criteria

Done means exactly:
1. User drops 5 pack files (or selects them via file input)
2. Verifier runs fully client-side using `verifyPack(PackContents)`
3. Stage receipts render cleanly (stage name + ok/fail)
4. Golden specimen shows green pass
5. Adversarial specimen shows red fail with fault class + error code
6. Single HTML file, no build step, no server required
7. Can be opened from `file://` or hosted on GitHub Pages
