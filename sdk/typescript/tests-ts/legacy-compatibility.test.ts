import { describe, expect, test } from "bun:test";
import { ScanCostTracker, estimateScanCost, formatUsd } from "../src/cost.js";
import {
  ScanCostTracker as TransportScanCostTracker,
  estimateScanCost as transportEstimateScanCost,
  formatUsd as transportFormatUsd,
} from "../src/transport/cost.js";
import { resolveTrustedExecutable } from "../src/trusted-executable.js";
import { resolveTrustedExecutable as transportResolveTrustedExecutable } from "../src/transport/trusted-executable.js";
import { workerStatusFromEvent } from "../src/worker-progress.js";
import { workerStatusFromEvent as kernelWorkerStatusFromEvent } from "../src/kernel/worker-progress.js";

describe("legacy TypeScript compatibility facades", () => {
  test("preserves cost symbol identity through the legacy module", () => {
    expect(ScanCostTracker).toBe(TransportScanCostTracker);
    expect(estimateScanCost).toBe(transportEstimateScanCost);
    expect(formatUsd).toBe(transportFormatUsd);
  });

  test("preserves executable and worker symbol identity", () => {
    expect(resolveTrustedExecutable).toBe(transportResolveTrustedExecutable);
    expect(workerStatusFromEvent).toBe(kernelWorkerStatusFromEvent);
  });
});
