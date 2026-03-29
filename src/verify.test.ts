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
import * as ed from "@noble/ed25519";
import { canonicalize, canonicalizeToString } from "./jcs.js";
import { verifyPackManifest, verifyPack } from "./verify.js";
import type { PackContents } from "./verify.js";

ed.etc.sha512Sync = (...m: Uint8Array[]) => {
  const h = createHash("sha512");
  for (const msg of m) h.update(msg);
  return h.digest();
};

// Path to the Assay conformance corpus (relative to repo root)
const ASSAY_VECTORS = join(
  process.env.ASSAY_VECTORS_DIR ??
    join(process.env.HOME!, "assay/tests/contracts/vectors")
);
const SCHEMA_DEPTH_VECTORS = join(ASSAY_VECTORS, "pack-schema-depth");
const GOLDEN_PACK_DIR = join(ASSAY_VECTORS, "pack", "golden_minimal");

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
// Structural invariant: verify-core.ts has no Node imports
// ---------------------------------------------------------------------------

describe("verify-core.ts runtime neutrality", async () => {
  const source = await readFile(
    join(import.meta.dirname!, "..", "src", "verify-core.ts"),
    "utf-8"
  );

  it("has zero Node built-in imports (node: prefix)", () => {
    const nodeImports = source.match(/from\s+["']node:/g) || [];
    assert.equal(nodeImports.length, 0,
      `Must have zero node: imports, found: ${nodeImports.join(", ")}`);
  });

  it("has zero bare Node module imports (fs, path, crypto)", () => {
    const bareNodeImports = source.match(/from\s+["'](fs|path|crypto|os|child_process|http|https|net|stream|util)["']/g) || [];
    assert.equal(bareNodeImports.length, 0,
      `Must have zero bare Node imports, found: ${bareNodeImports.join(", ")}`);
  });

  it("has no Node global references (Buffer, process, __dirname)", () => {
    // Check for common Node globals that indicate runtime coupling.
    // Allow mentions in comments/strings by checking for usage patterns.
    const lines = source.split("\n").filter(l => !l.trim().startsWith("//") && !l.trim().startsWith("*"));
    const codeOnly = lines.join("\n");
    const globals = ["Buffer", "process\\.", "__dirname", "__filename", "require\\("];
    for (const g of globals) {
      const matches = codeOnly.match(new RegExp(`\\b${g}`, "g")) || [];
      assert.equal(matches.length, 0,
        `verify-core.ts must not use Node global '${g}', found ${matches.length} occurrences`);
    }
  });
});

// ---------------------------------------------------------------------------
// Fixture-driven conformance runner: core / wrapper / bundle parity
// ---------------------------------------------------------------------------

/** Conformance fixture: one specimen, one expected outcome. */
interface ConformanceFixture {
  name: string;
  expectPassed: boolean;
  expectCode: string | null;
  expectCodesAnyOf?: string[];     // if set, any of these codes is acceptable
  expectFailStage: string | null;
  faultClass: string | null;
  description: string;
}

// Load fixture expectations from the shared spec file (lives in the Assay corpus).
// This is the same file that Python or any future implementation would consume.
const fixturesFile = join(ASSAY_VECTORS, "pack/conformance-fixtures.json");
const fixturesData = JSON.parse(await readFile(fixturesFile, "utf-8"));
const CONFORMANCE_FIXTURES: ConformanceFixture[] = fixturesData.fixtures;

/** Load a pack directory into PackContents for the core API. */
async function loadPack(dir: string): Promise<PackContents> {
  const manifestJson = await readFile(join(dir, "pack_manifest.json"), "utf-8");
  const manifest = JSON.parse(manifestJson);
  const fileNames = ["receipt_pack.jsonl", "verify_report.json", "verify_transcript.md",
                     "pack_manifest.json", "pack_signature.sig"];
  const files = new Map<string, Uint8Array>();
  for (const name of fileNames) {
    try {
      files.set(name, new Uint8Array(await readFile(join(dir, name))));
    } catch { /* missing — verifyPack will handle */ }
  }
  return { manifest, files };
}

/** Assert a VerifyResult matches fixture expectations. */
function assertFixture(
  result: { passed: boolean; errors: Array<{code: string}>; stages: Array<{stage: string; status: string}> },
  fixture: ConformanceFixture,
  surface: string,
) {
  assert.equal(result.passed, fixture.expectPassed,
    `[${surface}/${fixture.name}] expected passed=${fixture.expectPassed}`);

  const acceptCodes = fixture.expectCodesAnyOf ?? (fixture.expectCode ? [fixture.expectCode] : []);
  if (acceptCodes.length > 0) {
    assert.ok(result.errors.some(e => acceptCodes.includes(e.code)),
      `[${surface}/${fixture.name}] expected one of [${acceptCodes.join(", ")}], got: ${result.errors.map(e => e.code).join(", ")}`);
  }

  if (fixture.expectFailStage) {
    const stage = result.stages.find(s => s.stage === fixture.expectFailStage);
    if (stage) {
      assert.equal(stage.status, "fail",
        `[${surface}/${fixture.name}] stage ${fixture.expectFailStage} should be fail`);
    }
    // Stage may not exist if verifier short-circuits (e.g., path_traversal aborts early).
    // That's valid — the fixture says "this stage should fail IF present."
  }
}

/** Assert two VerifyResults are equivalent across surfaces. */
function assertResultsParity(
  a: { passed: boolean; errors: Array<{code: string}>; stages: Array<{stage: string; status: string}>; receiptCount: number; headHash: string | null },
  b: typeof a,
  label: string,
) {
  assert.equal(a.passed, b.passed, `${label}: passed`);
  assert.equal(a.receiptCount, b.receiptCount, `${label}: receiptCount`);
  assert.equal(a.headHash, b.headHash, `${label}: headHash`);
  assert.equal(a.errors.length, b.errors.length, `${label}: error count`);
  assert.equal(a.stages.length, b.stages.length, `${label}: stage count`);
  for (let i = 0; i < a.stages.length; i++) {
    assert.equal(a.stages[i]!.stage, b.stages[i]!.stage, `${label}: stage ${i} name`);
    assert.equal(a.stages[i]!.status, b.stages[i]!.status, `${label}: stage ${i} status`);
  }
  for (let i = 0; i < a.errors.length; i++) {
    assert.equal(a.errors[i]!.code, b.errors[i]!.code, `${label}: error ${i} code`);
  }
}

// ---------------------------------------------------------------------------
// Schema-validation depth parity
// ---------------------------------------------------------------------------

type ParityCategory = "exact_parity" | "equivalent_structural_parity" | "mismatch";

const CANONICAL_SCHEMA_BOUNDARY = {
  stage: "validate_schema",
  code: "E_MANIFEST_TAMPER",
} as const;

const ACCEPTED_PARITY_CATEGORIES = new Set<ParityCategory>([
  "exact_parity",
  "equivalent_structural_parity",
]);

function firstFailStage(result: { stages: Array<{ stage: string; status: string }> }): string | null {
  return result.stages.find((s) => s.status === "fail")?.stage ?? null;
}

function classifySchemaDepthParity(result: {
  passed: boolean;
  errors: Array<{ code: string }>;
  stages: Array<{ stage: string; status: string }>;
}): ParityCategory {
  if (result.passed) {
    return "mismatch";
  }

  const failStage = firstFailStage(result);
  const hasCanonicalCode = result.errors.some((e) => e.code === CANONICAL_SCHEMA_BOUNDARY.code);
  if (failStage === CANONICAL_SCHEMA_BOUNDARY.stage && hasCanonicalCode) {
    return "exact_parity";
  }

  // A later failure for a different reason does not count as parity.
  if (failStage === "validate_schema" || failStage === "validate_shape") {
    return hasCanonicalCode ? "equivalent_structural_parity" : "mismatch";
  }

  return "mismatch";
}

async function buildSchemaDepthPack(specimenName: string): Promise<PackContents> {
  const manifestJson = await readFile(
    join(SCHEMA_DEPTH_VECTORS, specimenName, "pack_manifest.json"),
    "utf-8"
  );
  const manifest = JSON.parse(manifestJson);

  const files = new Map<string, Uint8Array>();
  for (const name of ["receipt_pack.jsonl", "verify_report.json", "verify_transcript.md"]) {
    files.set(name, new Uint8Array(await readFile(join(GOLDEN_PACK_DIR, name))));
  }

  return signManifestWithFiles(manifest, files, false);
}

async function loadGoldenPackTemplate(): Promise<{
  manifest: Record<string, unknown>;
  files: Map<string, Uint8Array>;
}> {
  const manifestJson = await readFile(join(GOLDEN_PACK_DIR, "pack_manifest.json"), "utf-8");
  const manifest = JSON.parse(manifestJson);
  const files = new Map<string, Uint8Array>();
  for (const name of ["receipt_pack.jsonl", "verify_report.json", "verify_transcript.md"]) {
    files.set(name, new Uint8Array(await readFile(join(GOLDEN_PACK_DIR, name))));
  }
  return { manifest, files };
}

function clonePackFiles(files: ReadonlyMap<string, Uint8Array>): Map<string, Uint8Array> {
  const cloned = new Map<string, Uint8Array>();
  for (const [name, bytes] of files.entries()) {
    cloned.set(name, new Uint8Array(bytes));
  }
  return cloned;
}

function refreshManifestFileEntries(
  manifest: Record<string, unknown>,
  files: ReadonlyMap<string, Uint8Array>,
): void {
  const manifestFiles = Array.isArray(manifest.files) ? manifest.files : [];
  for (const entry of manifestFiles) {
    if (!entry || typeof entry !== "object") continue;
    const fileEntry = entry as Record<string, unknown>;
    const path = fileEntry.path;
    if (typeof path !== "string") continue;
    const bytes = files.get(path);
    if (!bytes) continue;
    fileEntry.sha256 = createHash("sha256").update(bytes).digest("hex");
    fileEntry.bytes = bytes.length;
  }
}

function computeReceiptHeadHash(receipts: Record<string, unknown>[]): string {
  if (receipts.length === 0) {
    return createHash("sha256").update("empty").digest("hex");
  }

  let headHash: string | null = null;
  for (const receipt of receipts) {
    const canonical = canonicalize(receipt);
    headHash = createHash("sha256").update(canonical).digest("hex");
  }

  return headHash!;
}

async function signManifestWithFiles(
  manifestInput: Record<string, unknown>,
  filesInput: Map<string, Uint8Array>,
  refreshEntries = true,
): Promise<PackContents> {
  const manifest = structuredClone(manifestInput) as Record<string, unknown>;
  const files = clonePackFiles(filesInput);

  if (refreshEntries) {
    refreshManifestFileEntries(manifest, files);
  }

  const signerSeed = createHash("sha256").update("schema-depth-signer").digest();
  const pubkey = await ed.getPublicKeyAsync(signerSeed);
  const attestation = manifest.attestation as Record<string, unknown>;
  const attCanonical = canonicalize(attestation);
  const attHash = createHash("sha256").update(attCanonical).digest("hex");

  const unsigned: Record<string, unknown> = {
    ...manifest,
    attestation_sha256: attHash,
    signer_id: "schema-depth-signer",
    signer_pubkey: Buffer.from(pubkey).toString("base64"),
    signer_pubkey_sha256: createHash("sha256").update(pubkey).digest("hex"),
    pack_root_sha256: attHash,
  };
  delete unsigned.signature;

  const canonicalUnsigned = canonicalize(unsigned);
  const signature = await ed.signAsync(canonicalUnsigned, signerSeed);
  const finalManifest: Record<string, unknown> = {
    ...unsigned,
    signature: Buffer.from(signature).toString("base64"),
  };

  files.set(
    "pack_manifest.json",
    new TextEncoder().encode(JSON.stringify(finalManifest, null, 2))
  );
  files.set("pack_signature.sig", signature);

  return { manifest: finalManifest, files };
}

async function buildSchemaValidGoldenPack(
  mutator?: (manifest: Record<string, unknown>, files: Map<string, Uint8Array>) => void
): Promise<PackContents> {
  const { manifest, files } = await loadGoldenPackTemplate();
  if (mutator) {
    mutator(manifest, files);
  }
  return signManifestWithFiles(manifest, files);
}

describe("Schema-validation depth parity", async () => {
  const fixturesFile = join(SCHEMA_DEPTH_VECTORS, "schema-depth-fixtures.json");
  const fixturesData = JSON.parse(await readFile(fixturesFile, "utf-8"));
  const fixtures: Array<{ name: string; description: string; mutation_class: string }> = fixturesData.fixtures;

  for (const fixture of fixtures) {
    it(`${fixture.name}: canonical schema boundary`, async () => {
      const pack = await buildSchemaDepthPack(fixture.name);
      const result = verifyPack(pack);
      const parityCategory = classifySchemaDepthParity(result);
      const failStage = firstFailStage(result);

      assert.ok(
        ACCEPTED_PARITY_CATEGORIES.has(parityCategory),
        `[schema-depth/${fixture.name}] parity=${parityCategory}, stage=${failStage}, errors=${result.errors.map((e) => e.code).join(", ")}`
      );
      assert.equal(
        result.passed,
        false,
        `[schema-depth/${fixture.name}] malformed specimen must fail`
      );
      assert.equal(
        failStage,
        CANONICAL_SCHEMA_BOUNDARY.stage,
        `[schema-depth/${fixture.name}] expected structural rejection at ${CANONICAL_SCHEMA_BOUNDARY.stage}, got ${failStage ?? "pass"}`
      );
      assert.ok(
        result.errors.some((e) => e.code === CANONICAL_SCHEMA_BOUNDARY.code),
        `[schema-depth/${fixture.name}] expected ${CANONICAL_SCHEMA_BOUNDARY.code}, got ${result.errors.map((e) => e.code).join(", ")}`
      );
    });
  }
});

// --- Core conformance ---

describe("Conformance: core verifyPack()", async () => {
  for (const fixture of CONFORMANCE_FIXTURES) {
    it(`${fixture.name}: ${fixture.expectPassed ? "PASS" : "FAIL " + fixture.expectCode}`, async () => {
      const pack = await loadPack(join(ASSAY_VECTORS, "pack", fixture.name));
      const result = verifyPack(pack);
      assertFixture(result, fixture, "core");
    });
  }
});

// --- Core/Node wrapper parity ---

describe("Conformance: core == Node wrapper parity", async () => {
  for (const fixture of CONFORMANCE_FIXTURES) {
    it(`${fixture.name}: parity`, async () => {
      const packDir = join(ASSAY_VECTORS, "pack", fixture.name);
      const pack = await loadPack(packDir);
      const coreResult = verifyPack(pack);
      const nodeResult = await verifyPackManifest(packDir);
      assertResultsParity(coreResult, nodeResult, fixture.name);
    });
  }
});

// --- Browser bundle conformance ---

describe("Conformance: browser bundle", async () => {
  // @ts-expect-error — browser bundle has no .d.ts
  const bundle = await import("../browser/assay-verify.js");

  it("exports verifyPack and canonicalize", () => {
    assert.equal(typeof bundle.verifyPack, "function");
    assert.equal(typeof bundle.canonicalize, "function");
  });

  for (const fixture of CONFORMANCE_FIXTURES) {
    it(`${fixture.name}: ${fixture.expectPassed ? "PASS" : "FAIL " + fixture.expectCode}`, async () => {
      const pack = await loadPack(join(ASSAY_VECTORS, "pack", fixture.name));
      const result = bundle.verifyPack(pack);
      assertFixture(result, fixture, "bundle");
    });
  }
});

// ---------------------------------------------------------------------------
// verifyPack() — runtime-neutral core, in-memory only
// ---------------------------------------------------------------------------

describe("verifyPack() in-memory core", async () => {
  // Load golden specimen into memory to test the runtime-neutral path
  const packDir = join(ASSAY_VECTORS, "pack/golden_minimal");
  const manifestJson = await readFile(join(packDir, "pack_manifest.json"), "utf-8");
  const manifest = JSON.parse(manifestJson);

  const fileNames = [
    "receipt_pack.jsonl",
    "verify_report.json",
    "verify_transcript.md",
    "pack_manifest.json",
    "pack_signature.sig",
  ];
  const files = new Map<string, Uint8Array>();
  for (const name of fileNames) {
    files.set(name, new Uint8Array(await readFile(join(packDir, name))));
  }
  const pack: PackContents = { manifest, files };

  it("passes with in-memory pack contents (no filesystem)", () => {
    const result = verifyPack(pack);
    assert.equal(result.passed, true, `Errors: ${JSON.stringify(result.errors)}`);
    assert.equal(result.errors.length, 0);
  });

  it("is synchronous (returns VerifyResult, not Promise)", () => {
    const result = verifyPack(pack);
    // verifyPack is sync — result is not a Promise
    assert.equal(typeof result.passed, "boolean");
    assert.ok(Array.isArray(result.stages));
  });

  it("emits stage receipts from in-memory path", () => {
    const result = verifyPack(pack);
    assert.ok(result.stages.length >= 7);
    for (const s of result.stages) {
      assert.equal(s.status, "ok", `Stage ${s.stage} should be ok`);
    }
  });

  it("detects tampered content from in-memory data", () => {
    // Modify one byte in the JSONL to simulate tamper
    const tamperedJsonl = new Uint8Array(files.get("receipt_pack.jsonl")!);
    tamperedJsonl[0] = tamperedJsonl[0]! ^ 0xff;
    const tamperedFiles = new Map(files);
    tamperedFiles.set("receipt_pack.jsonl", tamperedJsonl);

    const result = verifyPack({ manifest, files: tamperedFiles });
    assert.equal(result.passed, false);
    assert.ok(
      result.errors.some((e) => e.code === "E_MANIFEST_TAMPER"),
      "Should detect file hash tamper"
    );
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

  it("emits stage receipts for all verification phases", async () => {
    const result = await verifyPackManifest(packDir);
    assert.ok(result.stages.length >= 7, `Expected >= 7 stages, got ${result.stages.length}`);

    const stageNames = result.stages.map((s) => s.stage);
    assert.ok(stageNames.includes("validate_schema"), "Missing validate_schema stage");
    assert.ok(stageNames.includes("validate_shape"), "Missing validate_shape stage");
    assert.ok(stageNames.includes("validate_paths"), "Missing validate_paths stage");
    assert.ok(stageNames.includes("validate_file_hashes"), "Missing validate_file_hashes stage");
    assert.ok(stageNames.includes("validate_receipts"), "Missing validate_receipts stage");
    assert.ok(stageNames.includes("validate_attestation"), "Missing validate_attestation stage");
    assert.ok(stageNames.includes("verify_signature"), "Missing verify_signature stage");
    assert.ok(stageNames.includes("check_d12_invariant"), "Missing check_d12_invariant stage");

    // All stages should be ok for golden specimen
    for (const s of result.stages) {
      assert.equal(s.status, "ok", `Stage ${s.stage} should be ok, got ${s.status}`);
    }
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
// Adversarial specimen suite: one fault per pack
// ---------------------------------------------------------------------------

describe("Adversarial: tampered signature", async () => {
  const packDir = join(ASSAY_VECTORS, "pack/tampered_signature");

  it("verification fails", async () => {
    const result = await verifyPackManifest(packDir);
    assert.equal(result.passed, false);
  });

  it("reports E_PACK_SIG_INVALID", async () => {
    const result = await verifyPackManifest(packDir);
    assert.ok(
      result.errors.some((e) => e.code === "E_PACK_SIG_INVALID"),
      `Expected E_PACK_SIG_INVALID, got: ${result.errors.map((e) => e.code).join(", ")}`
    );
  });

  it("verify_signature stage is fail", async () => {
    const result = await verifyPackManifest(packDir);
    const sigStage = result.stages.find((s) => s.stage === "verify_signature");
    assert.ok(sigStage, "Missing verify_signature stage");
    assert.equal(sigStage!.status, "fail");
  });
});

describe("Malformed signature material", () => {
  it("fails closed when signature is not valid base64", async () => {
    const pack = await buildSchemaValidGoldenPack();
    (pack.manifest as Record<string, unknown>).signature = "%%%";

    const result = verifyPack(pack);

    assert.equal(result.passed, false);
    assert.ok(
      result.errors.some((e) => e.code === "E_PACK_SIG_INVALID" && e.field === "signature"),
      `Expected malformed signature to fail cleanly, got: ${JSON.stringify(result.errors)}`
    );
  });

  it("fails closed when signer_pubkey is not valid base64", async () => {
    const pack = await buildSchemaValidGoldenPack();
    (pack.manifest as Record<string, unknown>).signer_pubkey = "%%%";

    const result = verifyPack(pack);

    assert.equal(result.passed, false);
    assert.ok(
      result.errors.some(
        (e) => e.code === "E_PACK_SIG_INVALID" && e.field === "signer_pubkey"
      ),
      `Expected malformed signer_pubkey to fail cleanly, got: ${JSON.stringify(result.errors)}`
    );
  });
});

describe("Adversarial: missing kernel file", async () => {
  const packDir = join(ASSAY_VECTORS, "pack/missing_kernel_file");

  it("verification fails", async () => {
    const result = await verifyPackManifest(packDir);
    assert.equal(result.passed, false);
  });

  it("reports E_MANIFEST_TAMPER for missing file", async () => {
    const result = await verifyPackManifest(packDir);
    const missing = result.errors.filter(
      (e) => e.code === "E_MANIFEST_TAMPER" && e.field === "verify_report.json"
    );
    assert.ok(
      missing.length >= 1,
      `Expected E_MANIFEST_TAMPER on verify_report.json, got: ${JSON.stringify(result.errors)}`
    );
  });
});

describe("Adversarial: D12 invariant break", async () => {
  const packDir = join(ASSAY_VECTORS, "pack/d12_invariant_break");

  it("verification fails", async () => {
    const result = await verifyPackManifest(packDir);
    assert.equal(result.passed, false);
  });

  it("reports E_MANIFEST_TAMPER for D12", async () => {
    const result = await verifyPackManifest(packDir);
    const d12 = result.errors.filter(
      (e) => e.code === "E_MANIFEST_TAMPER" && e.field === "pack_root_sha256"
    );
    assert.ok(
      d12.length >= 1,
      `Expected E_MANIFEST_TAMPER on pack_root_sha256, got: ${JSON.stringify(result.errors)}`
    );
  });

  it("check_d12_invariant stage is fail", async () => {
    const result = await verifyPackManifest(packDir);
    const d12Stage = result.stages.find((s) => s.stage === "check_d12_invariant");
    assert.ok(d12Stage, "Missing check_d12_invariant stage");
    assert.equal(d12Stage!.status, "fail");
  });
});

describe("Adversarial: path traversal in manifest", async () => {
  const packDir = join(ASSAY_VECTORS, "pack/path_traversal");

  it("verification fails", async () => {
    const result = await verifyPackManifest(packDir);
    assert.equal(result.passed, false);
  });

  it("reports E_PATH_ESCAPE", async () => {
    const result = await verifyPackManifest(packDir);
    assert.ok(
      result.errors.some((e) => e.code === "E_PATH_ESCAPE"),
      `Expected E_PATH_ESCAPE, got: ${result.errors.map((e) => e.code).join(", ")}`
    );
  });
});

describe("Adversarial: duplicate receipt_id", async () => {
  const packDir = join(ASSAY_VECTORS, "pack/duplicate_receipt_id");

  it("verification fails", async () => {
    const result = await verifyPackManifest(packDir);
    assert.equal(result.passed, false);
  });

  it("reports duplicate detection (E_DUPLICATE_ID or E_MANIFEST_TAMPER)", async () => {
    // The TS verifier detects duplicates directly (E_DUPLICATE_ID).
    // The Python reference surfaces it as receipt_integrity mismatch.
    // Both are valid conforming behaviors per the spec.
    const result = await verifyPackManifest(packDir);
    const valid = result.errors.some(
      (e) => e.code === "E_DUPLICATE_ID" || e.code === "E_MANIFEST_TAMPER"
    );
    assert.ok(
      valid,
      `Expected E_DUPLICATE_ID or E_MANIFEST_TAMPER, got: ${result.errors.map((e) => e.code).join(", ")}`
    );
  });
});

// ---------------------------------------------------------------------------
// Path containment (security invariant)
// ---------------------------------------------------------------------------

describe("Path containment", () => {
  it("rejects path traversal in files", async () => {
    const pack = await buildSchemaValidGoldenPack((manifest) => {
      const files = manifest.files as Array<Record<string, unknown>>;
      files[0]!.path = "../../../etc/passwd";
    });
    const result = verifyPack(pack);
    assert.equal(result.passed, false);
    assert.ok(
      result.errors.some((e) => e.code === "E_PATH_ESCAPE"),
      "Must reject path traversal"
    );
  });

  it("rejects path traversal in expected_files", async () => {
    const pack = await buildSchemaValidGoldenPack((manifest) => {
      const expectedFiles = manifest.expected_files as string[];
      expectedFiles[0] = "../outside.txt";
    });
    const result = verifyPack(pack);
    assert.equal(result.passed, false);
    assert.ok(
      result.errors.some((e) => e.code === "E_PATH_ESCAPE"),
      "Must reject traversal in expected_files"
    );
  });

  it("rejects absolute path in files", async () => {
    const pack = await buildSchemaValidGoldenPack((manifest) => {
      const files = manifest.files as Array<Record<string, unknown>>;
      files[0]!.path = "/etc/passwd";
    });
    const result = verifyPack(pack);
    assert.equal(result.passed, false);
    assert.ok(
      result.errors.some((e) => e.code === "E_PATH_ESCAPE"),
      "Must reject absolute path"
    );
  });

  it("rejects absolute path in expected_files", async () => {
    const pack = await buildSchemaValidGoldenPack((manifest) => {
      const expectedFiles = manifest.expected_files as string[];
      expectedFiles[0] = "/etc/shadow";
    });
    const result = verifyPack(pack);
    assert.equal(result.passed, false);
    assert.ok(
      result.errors.some((e) => e.code === "E_PATH_ESCAPE"),
      "Must reject absolute path in expected_files"
    );
  });

  it("aborts before file reads on path escape", async () => {
    const pack = await buildSchemaValidGoldenPack((manifest) => {
      const files = manifest.files as Array<Record<string, unknown>>;
      files[0]!.path = "../escape";
    });
    const result = verifyPack(pack);
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
  async function makePackWithJsonl(
    receipts: Record<string, unknown>[]
  ): Promise<PackContents> {
    return buildSchemaValidGoldenPack((manifest, files) => {
      const jsonlContent = receipts.map((r) => JSON.stringify(r)).join("\n") + "\n";
      const jsonlBytes = new TextEncoder().encode(jsonlContent);
      files.set("receipt_pack.jsonl", jsonlBytes);

      const manifestFiles = manifest.files as Array<Record<string, unknown>>;
      const receiptEntry = manifestFiles.find((entry) => entry.path === "receipt_pack.jsonl");
      if (!receiptEntry) {
        throw new Error("golden pack template missing receipt_pack.jsonl");
      }
      receiptEntry.sha256 = createHash("sha256").update(jsonlBytes).digest("hex");
      receiptEntry.bytes = jsonlBytes.length;

      manifest.receipt_count_expected = receipts.length;
      const attestation = manifest.attestation as Record<string, unknown>;
      attestation.n_receipts = receipts.length;
      attestation.head_hash = computeReceiptHeadHash(receipts);
    });
  }

  it("rejects pack with duplicate receipt_ids", async () => {
    const pack = await makePackWithJsonl([
      { receipt_id: "dup-001", type: "test", timestamp: "2026-01-01T00:00:00Z" },
      { receipt_id: "dup-001", type: "test", timestamp: "2026-01-01T00:00:01Z" },
    ]);
    const result = verifyPack(pack);
    const dupErrors = result.errors.filter((e) => e.code === "E_DUPLICATE_ID");
    assert.ok(
      dupErrors.length >= 1,
      `Expected E_DUPLICATE_ID, got: ${result.errors.map((e) => e.code).join(", ")}`
    );
  });

  it("detects E_DUPLICATE_ID independently in a valid-shaped pack", async () => {
    // E_DUPLICATE_ID must be present and independently detectable,
    // even if other errors (missing signature, etc.) also appear
    const pack = await makePackWithJsonl([
      { receipt_id: "dup-002", type: "test", timestamp: "2026-01-01T00:00:00Z" },
      { receipt_id: "dup-002", type: "test", timestamp: "2026-01-01T00:00:01Z" },
    ]);
    const result = verifyPack(pack);
    assert.equal(result.passed, false);
    // E_DUPLICATE_ID must be present
    assert.ok(result.errors.some((e) => e.code === "E_DUPLICATE_ID"));
    // There may be other errors (missing signature, etc.) but E_DUPLICATE_ID
    // must be independently detectable
  });
});

// ---------------------------------------------------------------------------
// Fail-closed: signature present but signer_pubkey absent (CVE guard)
// ---------------------------------------------------------------------------

describe("Fail-closed: signature present, signer_pubkey absent", () => {
  it("returns passed=false with validate_schema / E_MANIFEST_TAMPER", async () => {
    const pack = await buildSchemaValidGoldenPack();
    delete (pack.manifest as Record<string, unknown>).signer_pubkey;
    const result = verifyPack(pack);

    assert.equal(result.passed, false,
      `Pack with missing signer_pubkey must fail, got errors: ${JSON.stringify(result.errors)}`);

    const schemaErrors = result.errors.filter(
      (e) => e.code === "E_MANIFEST_TAMPER" && e.field === "signer_pubkey"
    );
    assert.ok(
      schemaErrors.length >= 1,
      `Expected E_MANIFEST_TAMPER with field=signer_pubkey, got: ${result.errors.map((e) => `${e.code}(${e.field ?? ""})`).join(", ")}`
    );

    const schemaStage = result.stages.find((s) => s.stage === "validate_schema");
    assert.ok(schemaStage, "Missing validate_schema stage");
    assert.equal(schemaStage!.status, "fail",
      "validate_schema stage must be fail when signer_pubkey is absent");
  });
});

// ---------------------------------------------------------------------------
// Empty-pack head_hash parity
// ---------------------------------------------------------------------------

describe("Empty-pack head_hash parity", () => {
  it("uses the Python empty-pack sentinel instead of null", async () => {
    const emptyJsonl = new TextEncoder().encode("");
    const emptyJsonlHash = createHash("sha256").update(emptyJsonl).digest("hex");
    const emptyHeadHash = createHash("sha256").update("empty").digest("hex");

    const pack = await buildSchemaValidGoldenPack((manifest, files) => {
      files.set("receipt_pack.jsonl", emptyJsonl);

      const manifestFiles = manifest.files as Array<Record<string, unknown>>;
      const receiptEntry = manifestFiles.find((entry) => entry.path === "receipt_pack.jsonl");
      if (!receiptEntry) {
        throw new Error("golden pack template missing receipt_pack.jsonl");
      }
      receiptEntry.sha256 = emptyJsonlHash;
      receiptEntry.bytes = 0;

      manifest.receipt_count_expected = 0;
      const attestation = manifest.attestation as Record<string, unknown>;
      attestation.n_receipts = 0;
      attestation.head_hash = emptyHeadHash;
    });

    const result = verifyPack(pack);

    assert.equal(result.headHash, emptyHeadHash);
    assert.ok(
      !result.errors.some((e) => e.code === "E_MANIFEST_TAMPER" && e.field === "head_hash"),
      `Empty pack should not fail head_hash parity, got errors: ${JSON.stringify(result.errors)}`
    );
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
