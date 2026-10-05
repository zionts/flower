import { canonicalJson } from "./json.ts";
import type { ScanPageOptions } from "./core.ts";

/** Internal wire reference: source pages use the existing range host operation. */
export interface SourcePageReference {
  readonly kind: "sourcePage";
  readonly collection: string;
  readonly options: ScanPageOptions;
}

export function sourcePageReference(collection: string, value: ScanPageOptions): SourcePageReference {
  if (typeof collection !== "string" || !collection) throw new TypeError("Scan page collection must be a nonempty string");
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) {
    throw new TypeError("Scan page options must be a plain object");
  }
  // Inspect descriptors before reading anything: getters must never run, and
  // the reference sent to the bridge must not omit symbols or hidden options.
  const input: Record<string, unknown> = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    const property = Object.getOwnPropertyDescriptor(value, key)!;
    if (typeof key !== "string" || !property.enumerable || !("value" in property)) {
      throw new TypeError("Scan page options cannot contain symbols, hidden properties, or accessors");
    }
    if (key !== "limit" && key !== "after") throw new TypeError(`Scan page options do not accept ${JSON.stringify(key)}`);
    input[key] = property.value;
  }
  if (!Number.isSafeInteger(input.limit) || (input.limit as number) < 1) {
    throw new TypeError("Scan page limit must be a positive safe integer");
  }
  const options: { limit: number; after?: string } = { limit: input.limit as number };
  if (Object.hasOwn(input, "after")) {
    if (typeof input.after !== "string") throw new TypeError("Scan page cursor must be a string");
    options.after = input.after;
  }
  return Object.freeze({ kind: "sourcePage", collection, options: Object.freeze(options) });
}

/** The raw (possibly JSON-encoded) stored key, never the decoded SDK key. */
export function sourcePageCursor(collection: string, key: string): string {
  return canonicalJson({
    version: 1,
    scope: canonicalJson(["sourcePage", collection]),
    last: "source:" + canonicalJson([collection, key]),
  });
}
