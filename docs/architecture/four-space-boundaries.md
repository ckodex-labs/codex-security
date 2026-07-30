# Four-space boundaries

This is the enforceable dependency map for the incremental architecture migration.

```text
                     outbound ports
┌────────────────────────────────────────────────────┐
│ kernel                                             │
│ domain contracts · scan lifecycle · port contracts│
└───────────────┬───────────────────┬────────────────┘
                │                   │
       ┌────────▼────────┐  ┌───────▼────────┐
       │ validation      │  │ proof          │
       │ policy gates    │  │ host receipts  │
       └────────┬────────┘  └───────┬────────┘
                │                   │
                └─────────┬─────────┘
                          │ inward dependencies
                 ┌────────▼─────────┐
                 │ transport       │
                 │ CLI/API/DB/model│
                 │ sandbox adapters│
                 └──────────────────┘
```

## Dependency rules

| Space      | May import                                 | Must not own                                      |
| ---------- | ------------------------------------------ | ------------------------------------------------- |
| Kernel     | Kernel                                     | Node APIs, persistence, transports, provider SDKs |
| Validation | Kernel, validation                         | Provider calls, persistence, evidence signing     |
| Proof      | Kernel, proof, approved host cryptography  | Policy decisions, provider execution              |
| Transport  | All inward spaces and adapter dependencies | Domain invariants                                 |

`sdk/typescript/scripts/check-architecture.mjs` checks these rules for the new space directories. Existing flat modules remain outside the enforced set until migrated; this limitation is intentional and visible.

## Port coverage

| Concern              | Kernel port/contract                               | Adapter status                                                                                                              |
| -------------------- | -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Local model          | `ModelExecutionPort` + `local_http/local_process`  | `local_http` and bounded NDJSON `local_process` adapters implemented; process execution requires an injected sandbox runner |
| Private remote model | `ModelExecutionPort` + `private_http/private_grpc` | Literal/private-DNS HTTP and protobuf gRPC adapters implemented with pinned TLS identity                                    |
| Hosted model         | `ModelExecutionPort` + `hosted_api`                | Existing Codex-native runtime retained; not migrated behind `ModelExecutionPort`                                            |
| Sandbox              | `SandboxExecutionPort` + `SandboxSpec`             | Policy and Docker CLI adapter implemented; live Docker acceptance remains environment-gated                                 |
| Scan state           | `ScanStateRepositoryPort`                          | Legacy mapping implemented; database adapter pending                                                                        |
| Evidence             | `EvidenceRecorderPort` + decision evidence         | Append-only workbench adapter and BPL gate implemented; production binding pending; sealed scan-v1 finalizer unchanged      |

The provider capability gate covers streaming, structured output, tool calling, cancellation, and usage accounting. Adapter activation is denied if the selected policy requires a capability the provider cannot supply.

The production scan path deliberately retains Codex `runStreamed` so agent and
tool continuation semantics are preserved. The package-root composed execution
API is available for bounded adapter consumers; it is not a replacement scan
engine. Private DNS resolution is single-shot and the request lookup is pinned
to the admitted private address while TLS retains the original DNS identity.
Process and gRPC selections fail closed unless the caller supplies a literal
loopback Responses bridge, preserving the Codex tool-continuation loop.
Production provider selection still needs to bind its host-created
ActionEnvelope and receipts to the durable workbench adapter.

## Dagger boundary

Dagger is the portable verification entrypoint. Its functions call the package's architecture, type, test, format, build, and package checks. These commands remain the source of verification behavior so CI configuration does not become a second implementation.
