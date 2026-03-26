/**
 * Build a browser-compatible ESM bundle of the verifier core.
 *
 * Since verify-core.ts has zero Node imports, no stubbing is needed.
 * browser.ts imports only from verify-core and jcs — both runtime-neutral.
 */
import { build } from "esbuild";

await build({
  entryPoints: ["src/browser.ts"],
  bundle: true,
  format: "esm",
  outfile: "browser/assay-verify.js",
  target: "es2022",
  // No plugins needed — verify-core.ts has zero Node imports
});

console.log("browser/assay-verify.js built (no Node stubs needed)");
