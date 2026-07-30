# ADR-0001: Four-space hexagonal architecture

- Status: Accepted for incremental migration
- Date: 2026-07-29
- Decision scope: architecture runway and bounded Responses-provider activation

## Context

The TypeScript SDK and Python workbench currently combine orchestration, persistence, model execution, transport mapping, and evidence finalization in large modules. That shape makes provider substitution and isolation policy difficult to verify independently.

The required target separates four responsibilities:

1. Kernel: pure domain state and port contracts.
2. Validation: deterministic policy and promotion decisions.
3. Presentation/transport: CLI, API, persistence, and provider adapters.
4. Proof: host-generated evidence and verification.

The repository must also support future local-model and private remote-model adapters without allowing a model provider to control policy, sandboxing, or proof.

## Decision

Adopt hexagonal ports and adapters inside the four spaces.

- Kernel owns domain types, state transitions, and port interfaces. It imports no platform or provider code.
- Validation depends only on kernel contracts and fails closed.
- Proof depends on kernel contracts and the minimal host cryptography required to construct evidence.
- Transport may depend inward and contains concrete provider, process, HTTP, gRPC, CLI, database, and compatibility adapters.
- Dagger invokes repository verification commands; verification logic remains in repository scripts and tests.

The first slice added the dependency rules, pure scan lifecycle, model and sandbox ports, capability gates, a decision receipt, and a legacy workbench state mapper. A subsequent activation slice exposed the model composition contracts at the package root and added local and private Responses-provider projection to the existing Codex runtime. It does not replace the existing `runStreamed` agent and tool loop.

## Security consequences

- Model identity and declared capabilities are inputs to host validation, not proof of approval.
- Local providers must be loopback-bound.
- Private remote providers must meet explicit private-network and TLS policy.
- Sandbox execution is denied for root, privilege, Linux capabilities, runtime sockets, ambient credentials, mutable source, unbounded resources, or unauthorized egress.
- Output and state use dedicated writable mounts; source remains read-only.
- Decision evidence is created outside provider adapters.

## Compatibility and migration

The existing `running | complete | failed` storage representation remains authoritative during migration. Cancellation continues to use `failed` plus `canceled_at`. The compatibility adapter maps that representation without changing persisted records.

The active scan compatibility path projects literal loopback or authenticated
literal private endpoints into Codex configuration. The lower-level composed
Responses adapter is separately available to bounded consumers and emits its
host admission receipt before network execution. `local_process`,
`private_grpc`, and private DNS with pinned-address TLS are implemented as
bounded adapters. Non-HTTP transports require an explicit loopback Responses
bridge for production scan projection, so the existing Codex agent/tool loop is
not replaced. Durable back-propagation lineage remains a separate concern. The
canonical v1 scan evidence finalizer is unchanged; adding provider decision
evidence to that sealed set requires an explicit contract version.

## Verification

- `pnpm --dir sdk/typescript run architecture`
- `pnpm --dir sdk/typescript run types`
- `pnpm --dir sdk/typescript run test`
- `dagger call all --source=.`
