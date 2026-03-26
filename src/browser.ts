/**
 * Browser entry point — exports only runtime-neutral functions.
 * No Node imports (no fs, no path, no node:crypto).
 */
export { verifyPack } from "./verify.js";
export type { PackContents, VerifyResult, VerifyError, StageReceipt } from "./verify.js";
export { canonicalize, canonicalizeToString } from "./jcs.js";
