import type {
  GateDecision,
  ModelCapabilities,
  ModelCapability,
  ModelTransport,
} from "../kernel/contracts.js";

export interface ModelCapabilityPolicy {
  policyId: string;
  allowedTransports: readonly ModelTransport[];
  requiredCapabilities: readonly ModelCapability[];
  requirePrivateEndpoint: boolean;
  requireTlsForRemote: boolean;
  requireDerivedEndpointSecurity: boolean;
}

export function validateModelCapabilities(
  capabilities: ModelCapabilities,
  policy: ModelCapabilityPolicy,
): GateDecision {
  const reasons: string[] = [];
  const remediation: string[] = [];
  validateIdentity(capabilities, reasons, remediation);
  validateFeatures(capabilities, policy, reasons, remediation);
  validateEndpoint(capabilities, policy, reasons, remediation);
  return decision(policy.policyId, reasons, remediation);
}

function validateIdentity(
  capabilities: ModelCapabilities,
  reasons: string[],
  remediation: string[],
): void {
  if (capabilities.providerId.trim() === "") {
    reasons.push("provider identity is empty");
    remediation.push("configure a stable provider identifier");
  }
  if (capabilities.modelId.trim() === "") {
    reasons.push("model identity is empty");
    remediation.push("configure a stable model identifier");
  }
}

function validateFeatures(
  capabilities: ModelCapabilities,
  policy: ModelCapabilityPolicy,
  reasons: string[],
  remediation: string[],
): void {
  if (!policy.allowedTransports.includes(capabilities.transport)) {
    reasons.push(`transport ${capabilities.transport} is not allowed`);
    remediation.push("select a transport allowed by the active policy");
  }
  for (const required of policy.requiredCapabilities) {
    if (!capabilities.features.has(required)) {
      reasons.push(`required capability ${required} is unavailable`);
      remediation.push(`use a model adapter that implements ${required}`);
    }
  }
}

function validateEndpoint(
  capabilities: ModelCapabilities,
  policy: ModelCapabilityPolicy,
  reasons: string[],
  remediation: string[],
): void {
  const isLocal =
    capabilities.transport === "local_process" ||
    capabilities.transport === "local_http";
  if (
    policy.requireDerivedEndpointSecurity &&
    capabilities.endpointSecurity.source !== "derived"
  ) {
    reasons.push("endpoint security is provider-declared rather than derived");
    remediation.push("derive endpoint security from the validated connection");
  }
  if (
    policy.requirePrivateEndpoint &&
    !isLocal &&
    !capabilities.endpointSecurity.privateNetwork
  ) {
    reasons.push("remote model endpoint is not private");
    remediation.push("route the endpoint through an approved private network");
  }
  if (
    policy.requireTlsForRemote &&
    !isLocal &&
    !capabilities.endpointSecurity.tls
  ) {
    reasons.push("remote model endpoint does not declare TLS");
    remediation.push("enable authenticated TLS for the remote endpoint");
  }
  if (
    capabilities.transport === "local_http" &&
    !capabilities.endpointSecurity.loopbackOnly
  ) {
    reasons.push("local model endpoint is not loopback-bound");
    remediation.push("bind the local model adapter to a loopback interface");
  }
}

function decision(
  policyId: string,
  reasons: string[],
  remediation: string[],
): GateDecision {
  if (reasons.length > 0) {
    return {
      verdict: "deny",
      policyId,
      reasons,
      remediation,
    };
  }
  return {
    verdict: "allow",
    policyId,
    reasons: ["provider capabilities satisfy the active model policy"],
  };
}
