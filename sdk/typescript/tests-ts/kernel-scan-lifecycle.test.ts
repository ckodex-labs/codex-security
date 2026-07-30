import { describe, expect, test } from "bun:test";
import { transitionScan } from "../src/kernel/scan-lifecycle.js";

describe("scan lifecycle kernel", () => {
  test("keeps completion idempotent so retries cannot rewrite evidence time", () => {
    const complete = {
      status: "complete",
      completedAt: "2026-01-01T00:00:00Z",
    } as const;
    expect(
      transitionScan(complete, {
        kind: "complete",
        at: "2026-02-01T00:00:00Z",
      }),
    ).toEqual({ ok: true, changed: false, state: complete });
  });

  test("rejects terminal-state reversal because sealed results are immutable", () => {
    expect(
      transitionScan(
        { status: "complete", completedAt: "2026-01-01T00:00:00Z" },
        { kind: "fail", at: "2026-01-02T00:00:00Z", message: "late error" },
      ),
    ).toEqual({
      ok: false,
      reason: "cannot fail a scan in complete state",
    });
  });

  test("maps cancellation to the legacy failed state while retaining intent", () => {
    expect(
      transitionScan(
        { status: "running" },
        { kind: "cancel", at: "2026-01-01T00:00:00Z" },
      ),
    ).toEqual({
      ok: true,
      changed: true,
      state: {
        status: "failed",
        canceledAt: "2026-01-01T00:00:00Z",
      },
      event: {
        kind: "scan_canceled",
        at: "2026-01-01T00:00:00Z",
      },
    });
  });
});
