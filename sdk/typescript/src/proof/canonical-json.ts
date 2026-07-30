import { createHash } from "node:crypto";
import type { Sha256Digest } from "../kernel/supply-chain-contracts.js";

export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (typeof value === "object" && value !== null) {
    const entries = Object.entries(value).sort(([left], [right]) =>
      left.localeCompare(right),
    );
    const fields = entries.map(
      ([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`,
    );
    return `{${fields.join(",")}}`;
  }
  return JSON.stringify(value);
}

export function sha256(value: string | Uint8Array): Sha256Digest {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
