/**
 * Assay Proof Pack Verifier — independent TypeScript implementation.
 *
 * This verifier implements the mechanical verification contract defined in
 * docs/contracts/PACK_CONTRACT.md. It does NOT read Python source — it
 * works from the contract spec and conformance corpus alone.
 *
 * Second implementations instantiate frozen doctrine. They do not discover it.
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { canonicalize } from "./jcs.js";
import * as ed from "@noble/ed25519";

// noble/ed25519 v2 requires a SHA-512 implementation
import { sha512 } from "@noble/hashes/sha2.js";
ed.etc.sha512Sync = (...m: Uint8Array[]) => {
  const h = sha512.create();
  for (const msg of m) h.update(msg);
  return h.digest();
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface VerifyError {
  code: string;
  message: string;
  field?: string;
}

export interface StageReceipt {
  stage: string;
  status: "ok" | "fail" | "skipped";
  code?: string;
  reason?: string;
  detail?: Record<string, unknown>;
}

export interface VerifyResult {
  passed: boolean;
  errors: VerifyError[];
  stages: StageReceipt[];
  receiptCount: number;
  headHash: string | null;
}

interface FileEntry {
  path: string;
  sha256: string;
  bytes?: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sha256hex(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

function base64Decode(b64: string): Uint8Array {
  return Uint8Array.from(Buffer.from(b64, "base64"));
}

/**
 * Layer 2: Strip top-level signature fields from a receipt.
 * Exclusion set v0: {anchor, cose_signature, receipt_hash, signature, signatures}
 * Root-level only — nested structures are payload.
 *
 * Contract reference: PACK_CONTRACT.md §4
 */
const SIGNATURE_FIELDS_V0 = new Set([
  "anchor",
  "cose_signature",
  "receipt_hash",
  "signature",
  "signatures",
]);

function prepareReceiptForHashing(
  receipt: Record<string, unknown>
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(receipt)) {
    if (!SIGNATURE_FIELDS_V0.has(key)) {
      result[key] = value;
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Manifest signing exclusion set
// ---------------------------------------------------------------------------

/**
 * NORMATIVE: The signing base is JCS(manifest excluding {signature, pack_root_sha256}).
 * Do NOT derive this from the manifest's signature_scope field — it is descriptive only.
 *
 * Contract reference: PACK_CONTRACT.md §6, OCD-8, OCD-10
 */
const MANIFEST_SIGNING_EXCLUSIONS = new Set(["signature", "pack_root_sha256"]);

// ---------------------------------------------------------------------------
// Path containment
// ---------------------------------------------------------------------------

/**
 * Check if a relative path stays within the pack directory.
 * Rejects absolute paths, '..' components, and backslash separators.
 */
function isContainedPath(relativePath: string): boolean {
  if (!relativePath) return false;
  if (relativePath.startsWith("/") || relativePath.startsWith("\\")) return false;
  if (relativePath.includes("\\")) return false;
  const parts = relativePath.split("/");
  return !parts.some((p) => p === "..");
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/**
 * Verify an Assay proof pack from a directory path.
 *
 * Implements the 11-step mechanical verification pipeline from
 * PACK_CONTRACT.md §11.
 *
 * Invariant: no manifest-controlled filesystem access occurs until
 * the manifest has passed basic structural validation and all paths
 * have been containment-checked.
 */
export async function verifyPackManifest(
  packDir: string
): Promise<VerifyResult> {
  const errors: VerifyError[] = [];
  const stages: StageReceipt[] = [];

  // Load manifest
  const manifestBytes = await readFile(join(packDir, "pack_manifest.json"));
  const manifest = JSON.parse(manifestBytes.toString("utf-8"));

  // --- validate_shape ---
  const files: FileEntry[] = Array.isArray(manifest.files) ? manifest.files : [];
  const expectedFiles: string[] = Array.isArray(manifest.expected_files) ? manifest.expected_files : [];
  const shapeOk = Array.isArray(manifest.files) && Array.isArray(manifest.expected_files);
  stages.push({
    stage: "validate_shape",
    status: shapeOk ? "ok" : "fail",
    ...(!shapeOk ? { reason: "manifest.files or manifest.expected_files is not an array" } : {}),
  });
  if (!shapeOk) {
    errors.push({
      code: "E_MANIFEST_TAMPER",
      message: "Manifest has malformed files or expected_files field",
    });
  }

  // --- validate_paths ---
  let pathsOk = true;
  for (const entry of files) {
    if (!isContainedPath(entry.path)) {
      errors.push({
        code: "E_PATH_ESCAPE",
        message: `Path escapes pack directory: ${entry.path}`,
        field: entry.path,
      });
      pathsOk = false;
    }
  }
  for (const name of expectedFiles) {
    if (!isContainedPath(name)) {
      errors.push({
        code: "E_PATH_ESCAPE",
        message: `Expected file path escapes pack directory: ${name}`,
        field: name,
      });
      pathsOk = false;
    }
  }
  stages.push({
    stage: "validate_paths",
    status: pathsOk ? "ok" : "fail",
    detail: { paths_checked: files.length + expectedFiles.length },
  });

  if (!pathsOk) {
    return { passed: false, errors, stages, receiptCount: 0, headHash: null };
  }

  // --- validate_file_hashes ---
  let fileHashOk = true;
  for (const entry of files) {
    let fileData: Buffer;
    try {
      fileData = await readFile(join(packDir, entry.path));
    } catch {
      errors.push({
        code: "E_MANIFEST_TAMPER",
        message: `File missing: ${entry.path}`,
        field: entry.path,
      });
      fileHashOk = false;
      continue;
    }
    const actualHash = sha256hex(fileData);
    if (entry.sha256 && actualHash !== entry.sha256) {
      errors.push({
        code: "E_MANIFEST_TAMPER",
        message: `Hash mismatch for ${entry.path}: expected ${entry.sha256.slice(0, 16)}..., got ${actualHash.slice(0, 16)}...`,
        field: entry.path,
      });
      fileHashOk = false;
    }
  }

  for (const name of expectedFiles) {
    try {
      await readFile(join(packDir, name));
    } catch {
      if (!errors.some((e) => e.field === name)) {
        errors.push({
          code: "E_MANIFEST_TAMPER",
          message: `Expected file missing: ${name}`,
          field: name,
        });
        fileHashOk = false;
      }
    }
  }
  stages.push({
    stage: "validate_file_hashes",
    status: fileHashOk ? "ok" : "fail",
    detail: { files_checked: files.length },
  });

  // --- validate_receipts ---
  let receiptsOk = true;
  const jsonlPath = join(packDir, "receipt_pack.jsonl");
  let receipts: Record<string, unknown>[] = [];
  try {
    const jsonlContent = await readFile(jsonlPath, "utf-8");
    const lines = jsonlContent.split("\n").filter((l) => l.trim());
    receipts = lines.map((l) => JSON.parse(l));
  } catch (e) {
    errors.push({
      code: "E_MANIFEST_TAMPER",
      message: `Cannot parse receipt_pack.jsonl: ${e}`,
      field: "receipt_pack.jsonl",
    });
    receiptsOk = false;
  }

  const expectedCount = manifest.receipt_count_expected;
  if (expectedCount !== undefined && receipts.length !== expectedCount) {
    errors.push({
      code: "E_PACK_OMISSION_DETECTED",
      message: `Receipt count mismatch: manifest says ${expectedCount}, file has ${receipts.length}`,
    });
    receiptsOk = false;
  }

  const seenIds = new Set<string>();
  for (const receipt of receipts) {
    const rid = receipt.receipt_id;
    if (typeof rid === "string") {
      if (seenIds.has(rid)) {
        errors.push({
          code: "E_DUPLICATE_ID",
          message: `Duplicate receipt_id: ${rid}`,
          field: "receipt_id",
        });
        receiptsOk = false;
      }
      seenIds.add(rid);
    }
  }

  let headHash: string | null = null;
  for (const receipt of receipts) {
    try {
      const prepared = prepareReceiptForHashing(receipt);
      const canonical = canonicalize(prepared);
      headHash = sha256hex(canonical);
    } catch {
      headHash = null;
    }
  }

  const attestation = manifest.attestation ?? {};
  const claimedHead = attestation.head_hash;
  if (claimedHead) {
    if (headHash === null) {
      errors.push({
        code: "E_MANIFEST_TAMPER",
        message: "Attestation claims head_hash but verifier could not recompute it",
        field: "head_hash",
      });
      receiptsOk = false;
    } else if (claimedHead !== headHash) {
      errors.push({
        code: "E_MANIFEST_TAMPER",
        message: "Recomputed head_hash does not match attestation",
        field: "head_hash",
      });
      receiptsOk = false;
    }
  }

  stages.push({
    stage: "validate_receipts",
    status: receiptsOk ? "ok" : "fail",
    detail: { receipt_count: receipts.length, head_hash: headHash },
  });

  // --- validate_attestation ---
  let attestationOk = true;
  const attestationSha256 = manifest.attestation_sha256;
  if (attestation && attestationSha256) {
    const attCanonical = canonicalize(attestation);
    const attHash = sha256hex(attCanonical);
    if (attHash !== attestationSha256) {
      errors.push({
        code: "E_MANIFEST_TAMPER",
        message: "Attestation hash mismatch in manifest",
        field: "attestation_sha256",
      });
      attestationOk = false;
    }
  }
  stages.push({
    stage: "validate_attestation",
    status: attestationOk ? "ok" : "fail",
  });

  // --- verify_signature ---
  let signatureOk = true;
  const signatureB64: string | undefined = manifest.signature;
  let signatureBytes: Uint8Array | null = null;

  if (signatureB64) {
    signatureBytes = base64Decode(signatureB64);

    try {
      const sigFileBytes = await readFile(join(packDir, "pack_signature.sig"));
      if (Buffer.compare(Buffer.from(signatureBytes), sigFileBytes) !== 0) {
        errors.push({
          code: "E_PACK_SIG_INVALID",
          message: "Detached signature does not match manifest signature bytes",
          field: "pack_signature.sig",
        });
        signatureOk = false;
      }
    } catch {
      errors.push({
        code: "E_PACK_SIG_INVALID",
        message: "Detached signature file missing: pack_signature.sig",
        field: "pack_signature.sig",
      });
      signatureOk = false;
    }
  } else {
    errors.push({
      code: "E_PACK_SIG_INVALID",
      message: "Manifest has no signature",
    });
    signatureOk = false;
  }

  const unsigned: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(manifest)) {
    if (!MANIFEST_SIGNING_EXCLUSIONS.has(key)) {
      unsigned[key] = value;
    }
  }
  const canonicalBytes = canonicalize(unsigned);

  const signerPubkeyB64: string | undefined = manifest.signer_pubkey;
  const signerPubkeySha256: string | undefined = manifest.signer_pubkey_sha256;

  if (signatureBytes && signerPubkeyB64) {
    const pubkeyBytes = base64Decode(signerPubkeyB64);

    if (signerPubkeySha256) {
      const actualFp = sha256hex(pubkeyBytes);
      if (actualFp !== signerPubkeySha256) {
        errors.push({
          code: "E_PACK_SIG_INVALID",
          message: "Embedded signer_pubkey does not match signer_pubkey_sha256",
          field: "signer_pubkey_sha256",
        });
        signatureOk = false;
      }
    }

    try {
      const valid = ed.verify(signatureBytes, canonicalBytes, pubkeyBytes);
      if (!valid) {
        errors.push({
          code: "E_PACK_SIG_INVALID",
          message: "Manifest signature verification failed",
        });
        signatureOk = false;
      }
    } catch {
      errors.push({
        code: "E_PACK_SIG_INVALID",
        message: "Manifest signature verification failed (exception)",
      });
      signatureOk = false;
    }
  }

  stages.push({
    stage: "verify_signature",
    status: signatureOk ? "ok" : "fail",
  });

  // --- check_d12_invariant ---
  const packRoot = manifest.pack_root_sha256;
  const d12Ok = !packRoot || !attestationSha256 || packRoot === attestationSha256;
  if (!d12Ok) {
    errors.push({
      code: "E_MANIFEST_TAMPER",
      message: "pack_root_sha256 does not match attestation_sha256",
      field: "pack_root_sha256",
    });
  }
  stages.push({
    stage: "check_d12_invariant",
    status: d12Ok ? "ok" : "fail",
  });

  return {
    passed: errors.length === 0,
    errors,
    stages,
    receiptCount: receipts.length,
    headHash,
  };
}
