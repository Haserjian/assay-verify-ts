/**
 * Conformance tests for the independent TypeScript Assay pack verifier.
 *
 * These tests run against the same golden and adversarial specimens
 * used by the Python reference implementation. If both implementations
 * agree on the same corpus, the contract is real.
 *
 * Second implementations instantiate frozen doctrine.
 * They do not discover it.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { canonicalize, canonicalizeToString } from "./jcs.js";
import { verifyPackManifest } from "./verify.js";

// Path to the Assay conformance corpus (relative to repo root)
const ASSAY_VECTORS = join(
  process.env.ASSAY_VECTORS_DIR ??
    join(process.env.HOME!, "assay/tests/contracts/vectors")
);

// ---------------------------------------------------------------------------
// JCS Layer 1 conformance
// ---------------------------------------------------------------------------

describe("JCS conformance (Layer 1)", async () => {
  const vectorsFile = join(ASSAY_VECTORS, "jcs_vectors.json");
  const data = JSON.parse(await readFile(vectorsFile, "utf-8"));
  const vectors: Array<{
    id: string;
    input: unknown;
    expected_canonical_utf8: string;
    expected_sha256: string;
    description: string;
  }> = data.vectors;

  for (const v of vectors) {
    it(`${v.id}: ${v.description}`, () => {
      const canonical = canonicalize(v.input);
      const canonicalStr = new TextDecoder().decode(canonical);

      assert.equal(
        canonicalStr,
        v.expected_canonical_utf8,
        `[${v.id}] Canonical mismatch`
      );

      const hash = createHash("sha256").update(canonical).digest("hex");
      assert.equal(hash, v.expected_sha256, `[${v.id}] SHA-256 mismatch`);
    });
  }

  it("JCS-G09 language-level: -0.0 canonicalizes as 0", () => {
    const canonical = canonicalizeToString({ a: -0 });
    assert.equal(canonical, '{"a":0}');
  });
});

// ---------------------------------------------------------------------------
// Golden pack specimen — full pipeline
// ---------------------------------------------------------------------------

describe("Golden pack specimen (full pipeline)", async () => {
  const packDir = join(ASSAY_VECTORS, "pack/golden_minimal");
  const expectedFile = join(ASSAY_VECTORS, "pack/expected_outputs.json");
  const expected = JSON.parse(await readFile(expectedFile, "utf-8"));

  it("verification passes", async () => {
    const result = await verifyPackManifest(packDir);
    assert.equal(
      result.passed,
      true,
      `Expected pass, got errors: ${JSON.stringify(result.errors)}`
    );
    assert.equal(result.errors.length, 0);
  });

  it("receipt count matches", async () => {
    const result = await verifyPackManifest(packDir);
    assert.equal(result.receiptCount, expected.expected_verification.receipt_count);
  });

  it("head hash matches expected", async () => {
    const result = await verifyPackManifest(packDir);
    assert.equal(result.headHash, expected.expected_verification.head_hash);
  });

  it("file hashes match expected", async () => {
    const manifest = JSON.parse(
      await readFile(join(packDir, "pack_manifest.json"), "utf-8")
    );
    for (const entry of manifest.files) {
      const fileData = await readFile(join(packDir, entry.path));
      const hash = createHash("sha256").update(fileData).digest("hex");
      const expectedHash =
        expected.expected_file_hashes[entry.path as keyof typeof expected.expected_file_hashes];
      assert.equal(hash, expectedHash, `File hash mismatch for ${entry.path}`);
    }
  });

  it("attestation hash matches", async () => {
    const manifest = JSON.parse(
      await readFile(join(packDir, "pack_manifest.json"), "utf-8")
    );
    const attCanonical = canonicalize(manifest.attestation);
    const attHash = createHash("sha256").update(attCanonical).digest("hex");
    assert.equal(attHash, expected.expected_verification.attestation_sha256);
  });

  it("D12 invariant holds", async () => {
    const manifest = JSON.parse(
      await readFile(join(packDir, "pack_manifest.json"), "utf-8")
    );
    assert.equal(manifest.pack_root_sha256, manifest.attestation_sha256);
  });
});

// ---------------------------------------------------------------------------
// Adversarial specimen — tampered receipt content
// ---------------------------------------------------------------------------

describe("Adversarial specimen: tampered receipt content", async () => {
  const packDir = join(ASSAY_VECTORS, "pack/tampered_receipt_content");

  it("verification fails", async () => {
    const result = await verifyPackManifest(packDir);
    assert.equal(result.passed, false);
  });

  it("includes E_MANIFEST_TAMPER on receipt_pack.jsonl", async () => {
    const result = await verifyPackManifest(packDir);
    const tamperErrors = result.errors.filter(
      (e) =>
        e.code === "E_MANIFEST_TAMPER" && e.field === "receipt_pack.jsonl"
    );
    assert.ok(
      tamperErrors.length >= 1,
      `Expected at least one E_MANIFEST_TAMPER on receipt_pack.jsonl, got: ${JSON.stringify(result.errors)}`
    );
  });

  it("error mentions hash mismatch", async () => {
    const result = await verifyPackManifest(packDir);
    const tamperErrors = result.errors.filter(
      (e) =>
        e.code === "E_MANIFEST_TAMPER" && e.field === "receipt_pack.jsonl"
    );
    assert.ok(
      tamperErrors.some((e) => e.message.includes("Hash mismatch")),
      "Error should mention hash mismatch"
    );
  });
});

// ---------------------------------------------------------------------------
// Path containment (security invariant)
// ---------------------------------------------------------------------------

describe("Path containment", () => {
  // Shared helper for creating temp pack dirs with custom manifests
  async function makeTempPack(manifest: unknown): Promise<string> {
    const { mkdtemp, writeFile } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const dir = await mkdtemp(join(tmpdir(), "assay-test-"));
    await writeFile(
      join(dir, "pack_manifest.json"),
      JSON.stringify(manifest)
    );
    return dir;
  }

  it("rejects path traversal in files", async () => {
    const dir = await makeTempPack({
      files: [{ path: "../../../etc/passwd", sha256: "a".repeat(64) }],
      expected_files: ["receipt_pack.jsonl"],
    });
    const result = await verifyPackManifest(dir);
    assert.equal(result.passed, false);
    assert.ok(
      result.errors.some((e) => e.code === "E_PATH_ESCAPE"),
      "Must reject path traversal"
    );
  });

  it("rejects path traversal in expected_files", async () => {
    const dir = await makeTempPack({
      files: [],
      expected_files: ["../outside.txt"],
    });
    const result = await verifyPackManifest(dir);
    assert.equal(result.passed, false);
    assert.ok(
      result.errors.some((e) => e.code === "E_PATH_ESCAPE"),
      "Must reject traversal in expected_files"
    );
  });

  it("rejects absolute path in files", async () => {
    const dir = await makeTempPack({
      files: [{ path: "/etc/passwd", sha256: "a".repeat(64) }],
      expected_files: [],
    });
    const result = await verifyPackManifest(dir);
    assert.equal(result.passed, false);
    assert.ok(
      result.errors.some((e) => e.code === "E_PATH_ESCAPE"),
      "Must reject absolute path"
    );
  });

  it("rejects absolute path in expected_files", async () => {
    const dir = await makeTempPack({
      files: [],
      expected_files: ["/etc/shadow"],
    });
    const result = await verifyPackManifest(dir);
    assert.equal(result.passed, false);
    assert.ok(
      result.errors.some((e) => e.code === "E_PATH_ESCAPE"),
      "Must reject absolute path in expected_files"
    );
  });

  it("aborts before file reads on path escape", async () => {
    // If paths escape, verifier must return immediately — no file I/O
    const dir = await makeTempPack({
      files: [{ path: "../escape", sha256: "a".repeat(64) }],
      expected_files: [],
    });
    const result = await verifyPackManifest(dir);
    assert.equal(result.passed, false);
    // Should ONLY have path escape errors, nothing downstream
    assert.ok(
      result.errors.every((e) => e.code === "E_PATH_ESCAPE"),
      `Expected only E_PATH_ESCAPE errors, got: ${result.errors.map((e) => e.code).join(", ")}`
    );
  });
});

// ---------------------------------------------------------------------------
// Duplicate receipt_id detection (PK-A06)
// ---------------------------------------------------------------------------

describe("Duplicate receipt_id detection (PK-A06)", () => {
  // Helper: build a minimal valid-shape pack with custom JSONL content
  async function makePackWithJsonl(
    receipts: Record<string, unknown>[]
  ): Promise<string> {
    const { mkdtemp, writeFile } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const dir = await mkdtemp(join(tmpdir(), "assay-test-"));

    const jsonlContent = receipts.map((r) => JSON.stringify(r)).join("\n") + "\n";
    const jsonlBytes = Buffer.from(jsonlContent);
    const jsonlHash = createHash("sha256").update(jsonlBytes).digest("hex");

    await writeFile(join(dir, "receipt_pack.jsonl"), jsonlContent);

    const manifest = {
      files: [
        { path: "receipt_pack.jsonl", sha256: jsonlHash, bytes: jsonlBytes.length },
      ],
      expected_files: ["receipt_pack.jsonl", "pack_manifest.json"],
      receipt_count_expected: receipts.length,
      attestation: {},
    };
    await writeFile(
      join(dir, "pack_manifest.json"),
      JSON.stringify(manifest, null, 2)
    );
    return dir;
  }

  it("rejects pack with duplicate receipt_ids", async () => {
    const dir = await makePackWithJsonl([
      { receipt_id: "dup-001", type: "test", timestamp: "2026-01-01T00:00:00Z" },
      { receipt_id: "dup-001", type: "test", timestamp: "2026-01-01T00:00:01Z" },
    ]);
    const result = await verifyPackManifest(dir);
    const dupErrors = result.errors.filter((e) => e.code === "E_DUPLICATE_ID");
    assert.ok(
      dupErrors.length >= 1,
      `Expected E_DUPLICATE_ID, got: ${result.errors.map((e) => e.code).join(", ")}`
    );
  });

  it("detects E_DUPLICATE_ID independently in a valid-shaped pack", async () => {
    // E_DUPLICATE_ID must be present and independently detectable,
    // even if other errors (missing signature, etc.) also appear
    const dir = await makePackWithJsonl([
      { receipt_id: "dup-002", type: "test", timestamp: "2026-01-01T00:00:00Z" },
      { receipt_id: "dup-002", type: "test", timestamp: "2026-01-01T00:00:01Z" },
    ]);
    const result = await verifyPackManifest(dir);
    assert.equal(result.passed, false);
    // E_DUPLICATE_ID must be present
    assert.ok(result.errors.some((e) => e.code === "E_DUPLICATE_ID"));
    // There may be other errors (missing signature, etc.) but E_DUPLICATE_ID
    // must be independently detectable
  });
});

// ---------------------------------------------------------------------------
// Malformed manifest shape (structural validation)
// ---------------------------------------------------------------------------

describe("Malformed manifest shape", () => {
  async function makeTempPack(manifest: unknown): Promise<string> {
    const { mkdtemp, writeFile } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const dir = await mkdtemp(join(tmpdir(), "assay-test-"));
    await writeFile(
      join(dir, "pack_manifest.json"),
      JSON.stringify(manifest)
    );
    return dir;
  }

  it("handles files as non-array gracefully", async () => {
    const dir = await makeTempPack({
      files: "not-an-array",
      expected_files: [],
    });
    const result = await verifyPackManifest(dir);
    // Should not crash — should fail gracefully
    assert.equal(result.passed, false);
  });

  it("handles expected_files as non-array gracefully", async () => {
    const dir = await makeTempPack({
      files: [],
      expected_files: { not: "an array" },
    });
    const result = await verifyPackManifest(dir);
    assert.equal(result.passed, false);
  });

  it("handles completely empty manifest", async () => {
    const dir = await makeTempPack({});
    const result = await verifyPackManifest(dir);
    // Empty manifest = no files verified, no signature, should fail
    // but should not crash
    assert.equal(typeof result.passed, "boolean");
  });
});
