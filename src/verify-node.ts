/**
 * Node-only convenience wrapper for Assay pack verification.
 *
 * Reads pack files from disk, constructs PackContents, then delegates
 * to the runtime-neutral verifyPack() core.
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { verifyPack } from "./verify-core.js";
import type { VerifyResult } from "./verify-core.js";

/**
 * Verify an Assay proof pack from a directory path.
 *
 * Node-only. Reads all pack files from disk, then delegates to
 * verifyPack() for the actual verification.
 */
export async function verifyPackManifest(
  packDir: string
): Promise<VerifyResult> {
  const manifestBytes = await readFile(join(packDir, "pack_manifest.json"));
  const manifest = JSON.parse(new TextDecoder().decode(manifestBytes));

  // Load all files referenced by the manifest + known kernel files
  const fileNames = new Set<string>();
  const fileEntries = Array.isArray(manifest.files) ? manifest.files : [];
  for (const entry of fileEntries) {
    if (typeof entry.path === "string") fileNames.add(entry.path);
  }
  const expected = Array.isArray(manifest.expected_files) ? manifest.expected_files : [];
  for (const name of expected) {
    if (typeof name === "string") fileNames.add(name);
  }
  // Always try to load the signature file
  fileNames.add("pack_signature.sig");

  const files = new Map<string, Uint8Array>();
  for (const name of fileNames) {
    try {
      const data = await readFile(join(packDir, name));
      files.set(name, new Uint8Array(data));
    } catch {
      // File not found — verifyPack will detect and report
    }
  }

  return verifyPack({ manifest, files });
}
