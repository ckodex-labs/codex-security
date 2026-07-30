import type {
  ModelCapability,
  ScanModelProvider,
} from "../../kernel/contracts.js";
import type { SandboxedModelProcessRunnerPort } from "../../kernel/ports.js";
import {
  LocalProcessModelAdapter,
  type LocalProcessModelAdapterConfig,
} from "../model/local-process.js";
import type {
  ModelProviderAdapterRegistration,
  ModelProviderDescriptor,
} from "./provider-selection.js";

export type ProductionLocalProcessConfiguration =
  | {
      mode: "codex_loopback_bridge";
      id: string;
      model: string;
      bridgeBaseUrl: string;
      credentialEnv?: string;
    }
  | {
      mode: "direct_model_port";
      adapterId: string;
      modelId: string;
      executable: string;
      arguments?: readonly string[];
      environment?: Readonly<Record<string, string>>;
      features: ReadonlySet<ModelCapability>;
      runner: SandboxedModelProcessRunnerPort;
    };

export type ProductionLocalProcessRuntime =
  | { mode: "codex_loopback_bridge"; scanProvider: ScanModelProvider }
  | {
      mode: "direct_model_port";
      descriptor: ModelProviderDescriptor;
      registration: ModelProviderAdapterRegistration;
    };

export function createProductionLocalProcessRuntime(
  configuration: ProductionLocalProcessConfiguration,
): ProductionLocalProcessRuntime {
  if (configuration.mode === "codex_loopback_bridge") {
    return {
      mode: configuration.mode,
      scanProvider: {
        kind: "local_process",
        id: configuration.id,
        model: configuration.model,
        bridgeBaseUrl: configuration.bridgeBaseUrl,
        ...(configuration.credentialEnv === undefined
          ? {}
          : { credentialEnv: configuration.credentialEnv }),
      },
    };
  }
  const adapterConfig: LocalProcessModelAdapterConfig = {
    providerId: configuration.adapterId,
    modelId: configuration.modelId,
    executable: configuration.executable,
    arguments: configuration.arguments,
    environment: configuration.environment,
    features: configuration.features,
  };
  return {
    mode: configuration.mode,
    descriptor: { kind: "local_process", adapterId: configuration.adapterId },
    registration: {
      kind: "local_process",
      adapterId: configuration.adapterId,
      create: () =>
        new LocalProcessModelAdapter(adapterConfig, configuration.runner),
    },
  };
}
