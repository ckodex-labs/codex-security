import type {
  GateDecision,
  SandboxMountRole,
  SandboxSpec,
} from "../kernel/contracts.js";

export interface SandboxPolicy {
  policyId: string;
  requireNetworkDeny: boolean;
  allowedDestinations: readonly string[];
}

function hasValidMountAccess(
  spec: SandboxSpec,
  role: SandboxMountRole,
  access: "read_only" | "read_write",
): boolean {
  const mounts = spec.mounts.filter((mount) => mount.role === role);
  return mounts.length === 1 && mounts[0]?.access === access;
}

function canonicalTarget(target: string): string | undefined {
  if (
    !target.startsWith("/") ||
    target.includes("\0") ||
    target.includes(",")
  ) {
    return undefined;
  }
  const segments = target.split("/");
  if (
    segments.some(
      (segment, index) =>
        (index > 0 && segment === "") || segment === "." || segment === "..",
    )
  ) {
    return undefined;
  }
  return target.length > 1 && target.endsWith("/")
    ? target.slice(0, -1)
    : target;
}

function targetsOverlap(left: string, right: string): boolean {
  return (
    left === right ||
    left.startsWith(`${right}/`) ||
    right.startsWith(`${left}/`)
  );
}

interface SandboxDenials {
  reasons: string[];
  remediation: string[];
}

function deny(
  denials: SandboxDenials,
  reason: string,
  remediation: string,
): void {
  denials.reasons.push(reason);
  denials.remediation.push(remediation);
}

function validateIsolation(spec: SandboxSpec, denials: SandboxDenials): void {
  if (
    !/^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*@sha256:[a-f0-9]{64}$/.test(
      spec.imageRef,
    )
  ) {
    deny(
      denials,
      "sandbox image is not digest-pinned",
      "pin the image by sha256 digest",
    );
  }
  if (!Number.isSafeInteger(spec.runAsUser) || spec.runAsUser <= 0) {
    deny(
      denials,
      "sandbox requests root execution",
      "use a non-root numeric user",
    );
  }
  if (spec.privileged) {
    deny(
      denials,
      "sandbox requests privileged execution",
      "disable privileged mode",
    );
  }
  if (spec.linuxCapabilities.length > 0) {
    deny(
      denials,
      "sandbox requests Linux capabilities",
      "drop all Linux capabilities",
    );
  }
  if (spec.dockerSocketMounted) {
    deny(
      denials,
      "sandbox requests the container runtime socket",
      "remove the socket",
    );
  }
  if (spec.ambientCredentials) {
    deny(
      denials,
      "sandbox requests ambient credentials",
      "use scoped explicit leases",
    );
  }
}

function validateMountRoles(spec: SandboxSpec, denials: SandboxDenials): void {
  const roleCounts = new Map<SandboxMountRole, number>();
  for (const mount of spec.mounts) {
    roleCounts.set(mount.role, (roleCounts.get(mount.role) ?? 0) + 1);
    if (mount.source.trim() === "" || mount.source.includes("\0")) {
      deny(
        denials,
        `${mount.role} mount source is invalid`,
        "provide a non-empty mount source without NUL bytes",
      );
    }
  }
  for (const role of ["source", "output", "state"] as const) {
    if (roleCounts.get(role) !== 1) {
      deny(
        denials,
        `sandbox requires exactly one ${role} mount`,
        `provide exactly one ${role} mount`,
      );
    }
  }
}

function validateMountAccess(spec: SandboxSpec, denials: SandboxDenials): void {
  if (!hasValidMountAccess(spec, "source", "read_only")) {
    deny(
      denials,
      "source is not mounted read-only",
      "mount source as read-only",
    );
  }
  for (const role of ["output", "state"] as const) {
    if (!hasValidMountAccess(spec, role, "read_write")) {
      deny(
        denials,
        `${role} is not mounted read-write`,
        `provide a dedicated read-write ${role} mount`,
      );
    }
  }
}

function validateMountTargets(
  spec: SandboxSpec,
  denials: SandboxDenials,
): void {
  const targets = spec.mounts.map((mount) => canonicalTarget(mount.target));
  const canonical = targets.filter(
    (target): target is string => target !== undefined,
  );
  if (canonical.length !== targets.length) {
    deny(
      denials,
      "sandbox mount target is not a canonical absolute path",
      "use normalized absolute container mount paths",
    );
    return;
  }
  const overlaps = canonical.some((target, index) =>
    canonical.slice(index + 1).some((other) => targetsOverlap(target, other)),
  );
  if (overlaps) {
    deny(
      denials,
      "sandbox mount targets overlap",
      "assign a unique target to every mount",
    );
  }
}

function validateLimits(spec: SandboxSpec, denials: SandboxDenials): void {
  if (
    Object.values(spec.limits).some(
      (value) => !Number.isSafeInteger(value) || value <= 0,
    )
  ) {
    deny(
      denials,
      "sandbox resource limits are not positive",
      "set every resource limit",
    );
  }
  if (
    Number.isSafeInteger(spec.limits.cpuMillis) &&
    spec.limits.cpuMillis > 0 &&
    spec.limits.cpuMillis < 10
  ) {
    deny(
      denials,
      "sandbox CPU limit is below the Docker enforcement minimum",
      "set cpuMillis to at least 10",
    );
  }
}

function validateDestinations(
  destinations: readonly string[],
  policy: SandboxPolicy,
  denials: SandboxDenials,
): void {
  if (destinations.length === 0) {
    deny(
      denials,
      "network allowlist is empty",
      "deny network or add approved destinations",
    );
  }
  if (new Set(destinations).size !== destinations.length) {
    deny(
      denials,
      "network allowlist contains duplicates",
      "list each exact approved destination once",
    );
  }
  for (const destination of destinations) {
    const invalid =
      destination === "*" ||
      destination.trim() !== destination ||
      destination.includes("\0") ||
      /[*?[\]]/.test(destination) ||
      !policy.allowedDestinations.includes(destination);
    if (invalid) {
      deny(
        denials,
        `network destination ${destination} is not approved`,
        "remove it or add an exact destination to policy",
      );
    }
  }
}

function validateNetwork(
  spec: SandboxSpec,
  policy: SandboxPolicy,
  denials: SandboxDenials,
): void {
  if (policy.requireNetworkDeny && spec.network.mode !== "deny") {
    deny(denials, "sandbox network is not denied", "set network mode to deny");
    return;
  }
  if (spec.network.mode === "allowlist") {
    validateDestinations(spec.network.destinations, policy, denials);
  }
}

export function validateSandboxSpec(
  spec: SandboxSpec,
  policy: SandboxPolicy,
): GateDecision {
  const denials: SandboxDenials = { reasons: [], remediation: [] };
  validateIsolation(spec, denials);
  validateMountRoles(spec, denials);
  validateMountAccess(spec, denials);
  validateMountTargets(spec, denials);
  validateLimits(spec, denials);
  validateNetwork(spec, policy, denials);
  if (denials.reasons.length > 0) {
    return {
      verdict: "deny",
      policyId: policy.policyId,
      reasons: denials.reasons,
      remediation: denials.remediation,
    };
  }
  return {
    verdict: "allow",
    policyId: policy.policyId,
    reasons: ["sandbox specification satisfies the active isolation policy"],
  };
}
