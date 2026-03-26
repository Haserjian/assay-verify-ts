/**
 * Assay JCS Profile v1 — Layer 1 canonicalization.
 *
 * Based on RFC 8785 with one documented deviation: scientific notation
 * uses uppercase E without explicit + sign (1E21 not 1e+21).
 * See CANONICALIZATION_PROFILE.md for the full deviation list.
 *
 * Pure canonicalization: JSON value in, canonical UTF-8 bytes out.
 * No signature stripping, no receipt projection, no normalization.
 *
 * Contract reference: docs/contracts/PACK_CONTRACT.md §3
 */

/**
 * Canonicalize a JSON-compatible value to Assay JCS Profile v1 bytes.
 */
export function canonicalize(value: unknown): Uint8Array {
  const str = serializeValue(value);
  return new TextEncoder().encode(str);
}

/**
 * Canonicalize to string (for debugging / display).
 */
export function canonicalizeToString(value: unknown): string {
  return serializeValue(value);
}

function serializeValue(value: unknown): string {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";

  if (typeof value === "string") {
    return JSON.stringify(value);
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("Non-finite numbers are not permitted in canonical JSON");
    }
    // Assay JCS Profile v1: uses Python-originated exponent formatting
    // (uppercase E, no explicit + sign: "1E21" not "1e+21").
    // This deviates from RFC 8785's ECMAScript-native form.
    // See CANONICALIZATION_PROFILE.md for the full deviation list.
    //
    // JavaScript's JSON.stringify produces RFC-native form (1e+21).
    // We transform to match Assay's corpus/Python reference behavior.
    const s = JSON.stringify(value);
    if (s.includes("e")) {
      return s.replace(/e\+?(-?)/, (_, sign) => "E" + sign);
    }
    return s;
  }

  if (Array.isArray(value)) {
    return "[" + value.map(serializeValue).join(",") + "]";
  }

  if (typeof value === "object" && value !== null) {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj);

    // RFC 8785: sort by UTF-16 code units (which is JavaScript's native
    // string comparison order — this is why JCS chose this sort order).
    keys.sort((a, b) => {
      if (a < b) return -1;
      if (a > b) return 1;
      return 0;
    });

    if (keys.length === 0) return "{}";

    const pairs = keys.map(
      (key) => JSON.stringify(key) + ":" + serializeValue(obj[key])
    );
    return "{" + pairs.join(",") + "}";
  }

  throw new TypeError(`Unsupported type for JCS: ${typeof value}`);
}
