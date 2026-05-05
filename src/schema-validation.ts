import * as Ajv2020Module from "ajv/dist/2020.js";
import * as addFormatsModule from "ajv-formats";
import type { ErrorObject, ValidateFunction } from "ajv/dist/2020.js";
import {
  ATTESTATION_SCHEMA,
  JURISDICTION_RECEIPT_SCHEMA,
  PACK_MANIFEST_SCHEMA,
} from "./schema-definitions.js";

export interface SchemaValidationError {
  field?: string;
  message: string;
}

const Ajv2020 = Ajv2020Module.default as unknown as new (opts?: unknown) => {
  addSchema: (schema: unknown) => unknown;
  compile: (schema: unknown) => ValidateFunction;
  getSchema: (key: string) => ValidateFunction | undefined;
};

const ajv = new Ajv2020({
  allErrors: true,
  strict: false,
  allowUnionTypes: true,
});

const addFormats = ((addFormatsModule as unknown as {
  default?: (ajv: unknown) => void;
})?.default ?? (addFormatsModule as unknown as (ajv: unknown) => void));

addFormats(ajv);

ajv.addSchema(ATTESTATION_SCHEMA);

const validateManifestFn = ajv.compile(PACK_MANIFEST_SCHEMA);
const validateJurisdictionReceiptFn = ajv.compile(JURISDICTION_RECEIPT_SCHEMA);
const validateAttestationFn = ajv.getSchema(ATTESTATION_SCHEMA.$id);

if (!validateAttestationFn) {
  throw new Error("Failed to initialize attestation schema validator");
}

function instancePathToField(instancePath: string): string | undefined {
  if (!instancePath) return undefined;
  return instancePath
    .split("/")
    .slice(1)
    .map((part) => part.replace(/~1/g, "/").replace(/~0/g, "~"))
    .join(".");
}

function errorField(error: ErrorObject): string | undefined {
  const base = instancePathToField(error.instancePath);

  if (error.keyword === "required") {
    const missing = (error.params as { missingProperty?: string }).missingProperty;
    return missing ? (base ? `${base}.${missing}` : missing) : base;
  }

  if (error.keyword === "additionalProperties") {
    const extra = (error.params as { additionalProperty?: string }).additionalProperty;
    return extra ? (base ? `${base}.${extra}` : extra) : base;
  }

  return base;
}

function collectValidationErrors(
  validator: ValidateFunction,
  value: unknown
): SchemaValidationError[] {
  if (validator(value)) {
    return [];
  }

  return (validator.errors ?? []).map((error: ErrorObject) => ({
    field: errorField(error),
    message: error.message ?? "schema validation failed",
  }));
}

export function validateManifestSchema(manifest: unknown): SchemaValidationError[] {
  return collectValidationErrors(validateManifestFn, manifest);
}

export function validateJurisdictionReceiptSchema(receipt: unknown): SchemaValidationError[] {
  return collectValidationErrors(validateJurisdictionReceiptFn, receipt);
}

export function validateAttestationSchema(attestation: unknown): SchemaValidationError[] {
  return collectValidationErrors(validateAttestationFn!, attestation);
}
