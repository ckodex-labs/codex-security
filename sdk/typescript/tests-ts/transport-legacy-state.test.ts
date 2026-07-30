import { describe, expect, test } from "bun:test";
import {
  fromLegacyWorkbenchScan,
  toLegacyWorkbenchPatch,
} from "../src/transport/legacy-workbench-state.js";

describe("legacy workbench state adapter", () => {
  test("preserves cancellation intent across the legacy failed-state encoding", () => {
    const kernel = fromLegacyWorkbenchScan({
      status: "failed",
      completed_at: null,
      canceled_at: "2026-01-01T00:00:00Z",
      error: null,
    });
    expect(kernel).toEqual({
      status: "failed",
      canceledAt: "2026-01-01T00:00:00Z",
    });
    expect(toLegacyWorkbenchPatch(kernel)).toEqual({
      status: "failed",
      completed_at: null,
      canceled_at: "2026-01-01T00:00:00Z",
      error: null,
    });
  });
});
