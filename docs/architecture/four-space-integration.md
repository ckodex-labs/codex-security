# Four-space runtime integration

Status: application and composition seam implemented. Production API activation
uses Codex-native custom-provider projection so the existing agent, plugin,
tool, lifecycle, and evidence-finalization loop is preserved.

## Execution path

```text
explicit provider descriptor
  → exact adapter registration
  → adapter capabilities
  → validation gate
  → host-generated decision evidence
  → observer
  → provider event stream
```

The provider descriptor contains only `kind` and `adapterId`. Endpoint security
and model capabilities come from the selected adapter and are evaluated by the
validation space. Unknown kinds, unknown adapter identifiers, extra descriptor
fields, and denied capabilities fail before `ModelExecutionPort.execute`.

The kernel application service owns ordering but not infrastructure:

1. Obtain adapter capabilities.
2. Request an injected admission decision.
3. Create, persist, and observe the host decision evidence.
4. Stop on denial.
5. Execute the admitted provider and forward strictly increasing event
   sequences.

Provider events have no evidence or admission variant. Consequently, model
output cannot author the gate decision or its receipt.

Request-level capabilities are combined with policy-level requirements; a
composition policy cannot weaken the execution request. Exact duplicate adapter
registrations are rejected as ambiguous. Except for the transport-neutral
`codex_native` compatibility adapter, the observed transport must match the
descriptor kind. An admitted stream must end in a `completed` or `canceled`
event, and nonterminal executions are canceled during cleanup.

## Production compatibility path

`CodexSecurityConfig.modelProvider` and the matching CLI provider flags project
an admitted local or private endpoint into Codex's `model_provider` and
`model_providers` configuration. That path intentionally does not replace
`runStreamed` with the one-shot generic adapter: doing so would discard the
Codex agent/tool continuation protocol.

The production projection enforces:

- local endpoints are HTTP literal loopback addresses;
- private HTTP endpoints projected directly into Codex are authenticated HTTPS
  literal RFC 1918 or unique-local addresses;
- process and gRPC transports require an explicit literal-loopback Responses
  bridge and are never silently projected as HTTP;
- provider identifiers use the reserved `ckodex-` namespace;
- only the Responses wire protocol is selected;
- automatic request and stream retries are disabled;
- provider credentials are referenced by environment-variable name, excluded
  from tool shells, and removed from plugin/workbench subprocess environments.

Package-root consumers can use `PinnedTlsHttpConnector` for a private DNS
endpoint. It resolves once, requires the configured private address to be in the
answer, pins the request lookup to that address, retains the DNS name for
SNI/hostname verification, and records the peer certificate fingerprint.

The Python workbench remains the sole authority for:

- scan registration and stored lifecycle state;
- canonical v1 manifest, findings, and coverage finalization;
- sealing and manifest-digest persistence;
- append-only governance evidence keyed to stable scan identity;
- completion, failure, and cancellation transitions.

Provider adapters must write only the unsealed canonical inputs expected by that
workbench. Activation must preserve the existing sequence:

```text
register scan → execute provider → complete or fail through workbench
```

No model decision evidence is added to the sealed v1 artifact set until that
contract is explicitly versioned.

## Remaining activation prerequisites

- Live acceptance against operator-selected local model servers and private
  deployments. Repository-controlled process, TLS, and mTLS gRPC fixtures are
  covered; those fixtures are not external deployment acceptance.
- A mapping for thread, reconnect, worker-progress, and portable cost events.
- Production binding of provider-selection receipts to the durable governance
  adapter. The adapter and promotion-critical BPL persistence gate are
  implemented; the sealed v1 artifact set remains unchanged.
