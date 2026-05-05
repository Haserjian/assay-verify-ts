/**
 * Assay Proof Pack Verifier — combined exports.
 *
 * Re-exports both the runtime-neutral core and the Node convenience
 * wrapper from a single module, preserving the existing import surface.
 */

// Runtime-neutral core (works in Node + browser)
export {
  verifyPack,
  type PackContents,
  type VerifyResult,
  type VerifyError,
  type StageReceipt,
} from "./verify-core.js";

export {
  validateJurisdictionReceiptSchema,
  type SchemaValidationError,
} from "./schema-validation.js";

// Node-only convenience wrapper
export { verifyPackManifest } from "./verify-node.js";
