/**
 * Build a browser-compatible ESM bundle of the verifier core.
 *
 * Stubs out Node-only imports (readFile, join) since the browser
 * bundle only exports verifyPack(), not verifyPackManifest().
 */
import { build } from "esbuild";

await build({
  entryPoints: ["src/browser.ts"],
  bundle: true,
  format: "esm",
  outfile: "browser/assay-verify.js",
  target: "es2022",
  // Stub Node imports — they are only used by verifyPackManifest (not exported)
  plugins: [{
    name: "stub-node",
    setup(build) {
      build.onResolve({ filter: /^node:/ }, (args) => ({
        path: args.path,
        namespace: "stub-node",
      }));
      build.onLoad({ filter: /.*/, namespace: "stub-node" }, () => ({
        contents: "export default undefined; export const readFile = undefined; export const join = undefined;",
        loader: "js",
      }));
    },
  }],
});

console.log("browser/assay-verify.js built");
