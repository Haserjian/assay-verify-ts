export const ATTESTATION_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://assay.local/schemas/attestation.schema.json",
  title: "Proof Pack Attestation",
  type: "object",
  additionalProperties: false,
  required: [
    "pack_format_version",
    "fingerprint_version",
    "pack_id",
    "run_id",
    "suite_id",
    "suite_hash",
    "verifier_version",
    "canon_version",
    "canon_impl",
    "canon_impl_version",
    "policy_hash",
    "claim_set_id",
    "claim_set_hash",
    "receipt_integrity",
    "claim_check",
    "assurance_level",
    "proof_tier",
    "mode",
    "head_hash",
    "head_hash_algorithm",
    "time_authority",
    "n_receipts",
    "timestamp_start",
    "timestamp_end",
  ],
  properties: {
    pack_format_version: {
      type: "string",
      pattern: "^[0-9]+\\.[0-9]+\\.[0-9]+$",
    },
    fingerprint_version: {
      type: "integer",
      minimum: 1,
    },
    pack_id: { type: "string", minLength: 1 },
    run_id: { type: "string", minLength: 1 },
    suite_id: { type: "string", minLength: 1 },
    suite_hash: {
      type: "string",
      pattern: "^[a-f0-9]{64}$",
    },
    verifier_version: {
      type: "string",
      pattern: "^[A-Za-z0-9._-]+$",
    },
    canon_version: {
      type: "string",
      pattern: "^[A-Za-z0-9._-]+$",
    },
    canon_impl: { type: "string" },
    canon_impl_version: { type: "string" },
    policy_hash: {
      type: "string",
      pattern: "^[a-f0-9]{64}$",
    },
    claim_set_id: { type: "string", minLength: 1 },
    claim_set_hash: {
      type: "string",
      pattern: "^[a-f0-9]{64}$",
    },
    receipt_integrity: {
      type: "string",
      enum: ["PASS", "FAIL"],
    },
    claim_check: {
      type: "string",
      enum: ["PASS", "FAIL", "N/A"],
    },
    assurance_level: {
      type: "string",
      enum: ["L0", "L1", "L2", "L3"],
    },
    proof_tier: {
      type: "string",
      enum: ["hash-only", "signed-pack", "signed-receipts"],
    },
    mode: {
      type: "string",
      enum: ["shadow", "enforced", "breakglass"],
    },
    head_hash: {
      type: "string",
      pattern: "^[a-f0-9]{64}$",
    },
    head_hash_algorithm: {
      type: "string",
    },
    time_authority: {
      type: "string",
    },
    n_receipts: {
      type: "integer",
      minimum: 0,
    },
    timestamp_start: {
      type: "string",
      format: "date-time",
    },
    timestamp_end: {
      type: "string",
      format: "date-time",
    },
    discrepancy_fingerprint: {
      type: ["string", "null"],
      pattern: "^[a-f0-9]{64}$",
    },
    valid_until: {
      type: ["string", "null"],
      format: "date-time",
    },
    superseded_by: {
      type: ["string", "null"],
      minLength: 1,
    },
    ci_binding: {
      type: ["object", "null"],
      additionalProperties: false,
      required: ["provider", "commit_sha"],
      properties: {
        provider: {
          type: "string",
          enum: ["github_actions", "gitlab_ci", "circleci", "jenkins", "local"],
        },
        repo: { type: "string" },
        ref: { type: "string" },
        commit_sha: {
          type: "string",
          pattern: "^[a-f0-9]{40}$",
        },
        run_id: { type: "string", minLength: 1 },
        run_attempt: { type: "string", minLength: 1 },
        workflow_ref: { type: "string" },
        actor: { type: "string" },
      },
    },
  },
} as const;

export const JURISDICTION_RECEIPT_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://assay.local/schemas/jurisdiction_receipt.schema.json",
  title: "Guardian Jurisdiction Receipt",
  description:
    "Portable public contract for Guardian jurisdiction_loss receipts. The verifier validates receipt shape and authority permissions only.",
  type: "object",
  additionalProperties: false,
  required: [
    "receipt_type",
    "algorithm_version",
    "hypothesis_id",
    "previous_status",
    "previous_proof_tier",
    "routing_decision",
    "failure_shape",
    "intervention_elasticities",
    "thresholds",
    "selected_intervention",
    "selected_elasticity",
    "candidate_elasticities",
    "probe_receipt_refs",
    "decision_rule",
    "preserved_residual_signal",
    "counterexamples",
    "new_permissions",
  ],
  properties: {
    receipt_type: {
      const: "jurisdiction_loss",
    },
    algorithm_version: {
      const: "epistemic-jurisdiction-v0.1",
    },
    hypothesis_id: {
      type: "string",
      minLength: 1,
    },
    previous_status: {
      type: "string",
      enum: ["active", "restricted", "factorized", "ghost", "quarantined", "retired"],
    },
    previous_proof_tier: {
      type: "string",
      minLength: 1,
    },
    routing_decision: {
      type: "string",
      enum: ["refine", "factorize", "replace_frame", "archive_hard", "quarantine"],
    },
    failure_shape: {
      type: "object",
      additionalProperties: false,
      required: [
        "constraint_power",
        "generalization_stability",
        "zoo_index",
        "self_explanation_pressure",
        "explanation_debt",
        "model_complexity",
        "temporal_coherence",
      ],
      properties: {
        constraint_power: { type: "number" },
        generalization_stability: { type: "number" },
        zoo_index: { type: "number" },
        self_explanation_pressure: { type: "number" },
        explanation_debt: { type: "number" },
        model_complexity: { type: "number" },
        temporal_coherence: { type: "number" },
      },
    },
    intervention_elasticities: {
      type: "object",
      additionalProperties: false,
      required: ["parameter", "factorization", "representation"],
      properties: {
        parameter: { type: "number" },
        factorization: { type: "number" },
        representation: { type: "number" },
      },
    },
    thresholds: {
      type: "object",
      additionalProperties: false,
      required: ["min_elasticity", "self_sealing_threshold"],
      properties: {
        min_elasticity: { type: "number" },
        self_sealing_threshold: { type: "number" },
      },
    },
    selected_intervention: {
      type: "string",
      enum: ["refine", "factorize", "replace_frame", "archive_hard", "quarantine"],
    },
    selected_elasticity: {
      type: ["number", "null"],
    },
    candidate_elasticities: {
      type: "object",
      additionalProperties: false,
      required: ["refine", "factorize", "replace_frame"],
      properties: {
        refine: { type: "number" },
        factorize: { type: "number" },
        replace_frame: { type: "number" },
      },
    },
    tie_breaker: {
      type: ["string", "null"],
    },
    probe_receipt_refs: {
      type: "array",
      items: {
        type: "string",
        minLength: 1,
      },
    },
    decision_rule: {
      type: "string",
      minLength: 1,
    },
    preserved_residual_signal: {
      type: "string",
    },
    counterexamples: {
      type: "array",
      items: {
        type: "object",
      },
    },
    new_permissions: {
      type: "object",
      additionalProperties: false,
      required: [
        "can_govern",
        "can_suggest",
        "can_gather_evidence",
        "requires_followup_receipts",
        "requires_child_receipts",
        "requires_new_receipts_for_reactivation",
        "authority_scope",
      ],
      properties: {
        can_govern: { type: "boolean" },
        can_suggest: { type: "boolean" },
        can_gather_evidence: { type: "boolean" },
        requires_followup_receipts: { type: "boolean" },
        requires_child_receipts: { type: "boolean" },
        requires_new_receipts_for_reactivation: { type: "boolean" },
        authority_scope: {
          type: "string",
          minLength: 1,
        },
      },
    },
  },
  allOf: [
    {
      if: {
        properties: { routing_decision: { const: "refine" } },
        required: ["routing_decision"],
      },
      then: {
        properties: {
          selected_intervention: { const: "refine" },
          selected_elasticity: { type: "number" },
        },
      },
    },
    {
      if: {
        properties: { routing_decision: { const: "factorize" } },
        required: ["routing_decision"],
      },
      then: {
        properties: {
          selected_intervention: { const: "factorize" },
          selected_elasticity: { type: "number" },
          new_permissions: {
            properties: {
              can_govern: { const: false },
              requires_child_receipts: { const: true },
            },
          },
        },
      },
    },
    {
      if: {
        properties: { routing_decision: { const: "replace_frame" } },
        required: ["routing_decision"],
      },
      then: {
        properties: {
          selected_intervention: { const: "replace_frame" },
          selected_elasticity: { type: "number" },
        },
      },
    },
    {
      if: {
        properties: { routing_decision: { const: "archive_hard" } },
        required: ["routing_decision"],
      },
      then: {
        properties: {
          selected_intervention: { const: "archive_hard" },
          selected_elasticity: { type: ["number", "null"] },
          new_permissions: {
            properties: {
              can_govern: { const: false },
              can_suggest: { const: true },
              can_gather_evidence: { const: false },
              requires_new_receipts_for_reactivation: { const: true },
            },
          },
        },
      },
    },
    {
      if: {
        properties: { routing_decision: { const: "quarantine" } },
        required: ["routing_decision"],
      },
      then: {
        properties: {
          selected_intervention: { const: "quarantine" },
          selected_elasticity: { type: ["number", "null"] },
          new_permissions: {
            properties: {
              can_govern: { const: false },
              can_suggest: { const: false },
              can_gather_evidence: { const: true },
              requires_new_receipts_for_reactivation: { const: true },
            },
          },
        },
      },
    },
  ],
} as const;

export const PACK_MANIFEST_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://assay.local/schemas/pack_manifest.schema.json",
  title: "Proof Pack Manifest (Signed)",
  type: "object",
  additionalProperties: false,
  required: [
    "pack_id",
    "pack_version",
    "manifest_version",
    "hash_alg",
    "attestation",
    "attestation_sha256",
    "suite_hash",
    "claim_set_id",
    "claim_set_hash",
    "receipt_count_expected",
    "files",
    "expected_files",
    "signer_id",
    "signer_pubkey",
    "signer_pubkey_sha256",
    "signature_alg",
    "signature_scope",
    "signature",
    "pack_root_sha256",
  ],
  properties: {
    pack_id: { type: "string", minLength: 1 },
    pack_version: {
      type: "string",
      pattern: "^[A-Za-z0-9._-]+$",
    },
    manifest_version: {
      type: "string",
      pattern: "^[A-Za-z0-9._-]+$",
    },
    hash_alg: {
      type: "string",
      enum: ["sha256"],
    },
    attestation: {
      $ref: "attestation.schema.json",
    },
    attestation_sha256: {
      type: "string",
      pattern: "^[a-f0-9]{64}$",
    },
    suite_hash: {
      type: "string",
      pattern: "^[a-f0-9]{64}$",
    },
    claim_set_id: { type: "string", minLength: 1 },
    claim_set_hash: {
      type: "string",
      pattern: "^[a-f0-9]{64}$",
    },
    redaction_policy_sha256: {
      type: "string",
      pattern: "^[a-f0-9]{64}$",
    },
    receipt_count_expected: {
      type: "integer",
      minimum: 0,
    },
    files: {
      type: "array",
      minItems: 3,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["path", "sha256", "bytes"],
        properties: {
          path: { type: "string", minLength: 1 },
          sha256: {
            type: "string",
            pattern: "^[a-f0-9]{64}$",
          },
          bytes: {
            type: "integer",
            minimum: 0,
          },
        },
      },
    },
    expected_files: {
      type: "array",
      minItems: 5,
      items: {
        type: "string",
        minLength: 1,
      },
    },
    signer_id: { type: "string", minLength: 1 },
    signer_pubkey: {
      type: "string",
    },
    signer_pubkey_sha256: {
      type: "string",
      pattern: "^[a-f0-9]{64}$",
    },
    signature_alg: {
      type: "string",
      enum: ["ed25519"],
    },
    signature_scope: {
      type: "string",
      enum: [
        "JCS(pack_manifest_excluding_signature_and_pack_root_sha256)",
        "JCS(pack_manifest_without_signature)",
      ],
    },
    signature: {
      type: "string",
      minLength: 1,
    },
    pack_root_sha256: {
      type: "string",
      pattern: "^[a-f0-9]{64}$",
    },
  },
} as const;
