import type { ModelExecutionPort } from "../../kernel/ports.js";

interface ProviderDescriptorBase {
  adapterId: string;
}

export interface CodexNativeProviderDescriptor extends ProviderDescriptorBase {
  kind: "codex_native";
}

export interface LocalProcessProviderDescriptor extends ProviderDescriptorBase {
  kind: "local_process";
}

export interface LocalHttpProviderDescriptor extends ProviderDescriptorBase {
  kind: "local_http";
}

export interface PrivateHttpProviderDescriptor extends ProviderDescriptorBase {
  kind: "private_http";
}

export interface PrivateGrpcProviderDescriptor extends ProviderDescriptorBase {
  kind: "private_grpc";
}

export interface HostedApiProviderDescriptor extends ProviderDescriptorBase {
  kind: "hosted_api";
}

export type ModelProviderDescriptor =
  | CodexNativeProviderDescriptor
  | LocalProcessProviderDescriptor
  | LocalHttpProviderDescriptor
  | PrivateHttpProviderDescriptor
  | PrivateGrpcProviderDescriptor
  | HostedApiProviderDescriptor;

export type ProviderAdapterKind = ModelProviderDescriptor["kind"];

export interface ModelProviderAdapterRegistration {
  kind: ProviderAdapterKind;
  adapterId: string;
  create(descriptor: ModelProviderDescriptor): ModelExecutionPort;
}

export class UnknownModelProviderError extends Error {
  public constructor(
    public readonly kind: string,
    public readonly adapterId: string,
  ) {
    super(`No model adapter is registered for ${kind}:${adapterId}.`);
    this.name = "UnknownModelProviderError";
  }
}

export class InvalidModelProviderDescriptorError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "InvalidModelProviderDescriptorError";
  }
}

export class DuplicateModelProviderRegistrationError extends Error {
  public constructor(
    public readonly kind: ProviderAdapterKind,
    public readonly adapterId: string,
  ) {
    super(`Multiple model adapters are registered for ${kind}:${adapterId}.`);
    this.name = "DuplicateModelProviderRegistrationError";
  }
}

const PROVIDER_KINDS = new Set<ProviderAdapterKind>([
  "codex_native",
  "local_process",
  "local_http",
  "private_http",
  "private_grpc",
  "hosted_api",
]);

export function requireModelProviderDescriptor(
  value: unknown,
): ModelProviderDescriptor {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new InvalidModelProviderDescriptorError(
      "Model provider descriptor must be an object.",
    );
  }
  const descriptor = value as Record<string, unknown>;
  const kind = descriptor["kind"];
  const adapterId = descriptor["adapterId"];
  if (
    typeof kind !== "string" ||
    !PROVIDER_KINDS.has(kind as ProviderAdapterKind)
  ) {
    throw new InvalidModelProviderDescriptorError(
      "Model provider descriptor kind is unsupported.",
    );
  }
  if (
    typeof adapterId !== "string" ||
    adapterId.trim() === "" ||
    adapterId !== adapterId.trim() ||
    adapterId.length > 256 ||
    /[\u0000-\u001f\u007f]/u.test(adapterId)
  ) {
    throw new InvalidModelProviderDescriptorError(
      "Model provider descriptor adapterId must be a bounded canonical string.",
    );
  }
  const unexpected = Object.keys(descriptor).filter(
    (key) => key !== "kind" && key !== "adapterId",
  );
  if (unexpected.length > 0) {
    throw new InvalidModelProviderDescriptorError(
      `Model provider descriptor contains unsupported fields: ${unexpected.join(", ")}.`,
    );
  }
  return { kind: kind as ProviderAdapterKind, adapterId };
}

export function resolveModelProvider(
  descriptor: ModelProviderDescriptor,
  registrations: readonly ModelProviderAdapterRegistration[],
): ModelExecutionPort {
  const matching = registrations.filter(
    (candidate) =>
      candidate.kind === descriptor.kind &&
      candidate.adapterId === descriptor.adapterId,
  );
  if (matching.length === 0) {
    throw new UnknownModelProviderError(descriptor.kind, descriptor.adapterId);
  }
  if (matching.length > 1) {
    throw new DuplicateModelProviderRegistrationError(
      descriptor.kind,
      descriptor.adapterId,
    );
  }
  const registration = matching[0];
  if (registration === undefined) {
    throw new UnknownModelProviderError(descriptor.kind, descriptor.adapterId);
  }
  return registration.create(descriptor);
}
