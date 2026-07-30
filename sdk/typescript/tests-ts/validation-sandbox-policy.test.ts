import { describe, expect, test } from "bun:test";
import type { SandboxSpec } from "../src/kernel/contracts.js";
import { validateSandboxSpec } from "../src/validation/sandbox-policy.js";

function isolatedSandbox(): SandboxSpec {
  return {
    imageRef:
      "registry.example/scanner@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    runAsUser: 65532,
    privileged: false,
    linuxCapabilities: [],
    dockerSocketMounted: false,
    ambientCredentials: false,
    network: { mode: "deny" },
    mounts: [
      {
        role: "source",
        source: "source",
        target: "/workspace",
        access: "read_only",
      },
      {
        role: "output",
        source: "output",
        target: "/output",
        access: "read_write",
      },
      {
        role: "state",
        source: "state",
        target: "/state",
        access: "read_write",
      },
    ],
    limits: {
      cpuMillis: 2_000,
      memoryBytes: 1_073_741_824,
      processCount: 64,
      wallClockMillis: 300_000,
      maxOutputBytes: 16_777_216,
    },
  };
}

describe("sandbox policy gate", () => {
  test("admits a digest-pinned, non-root, network-denied execution boundary", () => {
    expect(
      validateSandboxSpec(isolatedSandbox(), {
        policyId: "sandbox-policy/v1",
        requireNetworkDeny: true,
        allowedDestinations: [],
      }).verdict,
    ).toBe("allow");
  });

  test("denies privilege, mutable source, ambient credentials, and open egress together", () => {
    const unsafe: SandboxSpec = {
      ...isolatedSandbox(),
      runAsUser: 0,
      privileged: true,
      linuxCapabilities: ["SYS_ADMIN"],
      dockerSocketMounted: true,
      ambientCredentials: true,
      network: { mode: "allowlist", destinations: ["*"] },
      mounts: isolatedSandbox().mounts.map((mount) =>
        mount.role === "source" ? { ...mount, access: "read_write" } : mount,
      ),
    };
    const decision = validateSandboxSpec(unsafe, {
      policyId: "sandbox-policy/v1",
      requireNetworkDeny: true,
      allowedDestinations: [],
    });
    expect(decision.verdict).toBe("deny");
    expect(decision.reasons).toContain("sandbox requests privileged execution");
    expect(decision.reasons).toContain("source is not mounted read-only");
    expect(decision.reasons).toContain("sandbox network is not denied");
  });

  test("requires one canonical and isolated mount per role", () => {
    const base = isolatedSandbox();
    const decision = validateSandboxSpec(
      {
        ...base,
        mounts: [
          ...base.mounts,
          {
            role: "source",
            source: "duplicate",
            target: "/workspace/nested",
            access: "read_only",
          },
        ],
      },
      {
        policyId: "sandbox-policy/v1",
        requireNetworkDeny: true,
        allowedDestinations: [],
      },
    );
    expect(decision.verdict).toBe("deny");
    expect(decision.reasons).toContain(
      "sandbox requires exactly one source mount",
    );
    expect(decision.reasons).toContain("sandbox mount targets overlap");
  });

  test("rejects malformed image digests, UIDs, limits, and allowlists", () => {
    const base = isolatedSandbox();
    const decision = validateSandboxSpec(
      {
        ...base,
        imageRef: "scanner@sha256:short",
        runAsUser: -1,
        network: {
          mode: "allowlist",
          destinations: ["api.example.test", "api.example.test"],
        },
        limits: { ...base.limits, maxOutputBytes: Number.POSITIVE_INFINITY },
      },
      {
        policyId: "sandbox-policy/v1",
        requireNetworkDeny: false,
        allowedDestinations: ["api.example.test"],
      },
    );
    expect(decision.verdict).toBe("deny");
    expect(decision.reasons).toContain("sandbox image is not digest-pinned");
    expect(decision.reasons).toContain("sandbox requests root execution");
    expect(decision.reasons).toContain(
      "sandbox resource limits are not positive",
    );
    expect(decision.reasons).toContain("network allowlist contains duplicates");
  });

  test("rejects option-like images and unenforceable CPU quotas", () => {
    const base = isolatedSandbox();
    const decision = validateSandboxSpec(
      {
        ...base,
        imageRef: `--privileged@sha256:${"a".repeat(64)}`,
        limits: { ...base.limits, cpuMillis: 1 },
      },
      {
        policyId: "sandbox-policy/v1",
        requireNetworkDeny: true,
        allowedDestinations: [],
      },
    );
    expect(decision.verdict).toBe("deny");
    expect(decision.reasons).toContain("sandbox image is not digest-pinned");
    expect(decision.reasons).toContain(
      "sandbox CPU limit is below the Docker enforcement minimum",
    );
  });
});
