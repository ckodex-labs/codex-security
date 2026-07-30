# Codex Security

`@openai/codex-security` is a CLI and SDK for finding, validating, and fixing security vulnerabilities in your code.

**This repository is a fork of [OpenAI's codex-security](https://github.com/openai/codex-security) with a fundamental architecture rewrite.**

> Note: for best results, we recommend that your account is verified for [Trusted Access](https://chatgpt.com/cyber).

## Attribution

This project is derived from the original `@openai/codex-security` repository by OpenAI, licensed under the Apache License 2.0. See [NOTICES.md](NOTICES.md) for full attribution details.

We are fundamentally rewriting the entire architecture:
- The backend scan engine and SDK are implemented in **Rust** (`sdk/rust/`)
- CLI tooling and build infrastructure use **Go** (`dagger/`)
- The four-space hexagonal architecture (ADR-0001) is adopted for the rewrite
- All backend work uses Rust or Go, not Python or TypeScript

## Quick start

The Rust CLI is the primary interface for this fork. Install Rust and Cargo, then build and run the scanner directly:

```bash
cargo run --package codex-security-sdk -- scan .
cargo run --package codex-security-sdk -- scan . --model gpt-5.6-terra --effort high
```

For CI, set `OPENAI_API_KEY` or `CODEX_API_KEY` instead of signing in. Environment API keys are
passed directly to the current scan and are never stored in Codex's credential
home or system keyring.

Local sign-in honors Codex's configured credential backend, including a system
keyring required by a managed device. Codex Security keeps login and scan
credentials in the same private, persistent state directory.

If both a ChatGPT sign-in and an API key are available, interactive scans ask
which credential to use. CI and other noninteractive scans keep the existing
API-key precedence. Select a credential explicitly when needed:

```bash
cargo run --package codex-security-sdk -- scan . --auth chatgpt
cargo run --package codex-security-sdk -- scan . --auth api-key
```

To make your ChatGPT sign-in the automatic default, unset any configured API
keys:

```bash
unset OPENAI_API_KEY CODEX_API_KEY
```

Scan history is stored in the Codex Security workbench state directory. If that
directory cannot be written, set `CODEX_SECURITY_STATE_DIR` to a writable
directory outside the repository.

## Rust SDK

The Rust SDK (`sdk/rust/`) is the replacement backend. It provides
the same scan capabilities with improved performance, memory safety, and isolation.

```rust
use codex_security_sdk::CodexSecurityClient;
use codex_security_sdk::SdkConfig;

let config = SdkConfig::from_env()?;
let client = CodexSecurityClient::new(config)?;
let result = client.run(".").await?;
```

For complete command help, runtime defaults, native multi-agent worker limits,
environment variables, deep-scan configuration, and SDK options, see the
[Rust SDK README](sdk/rust/README.md) and the
[official CLI reference](https://learn.chatgpt.com/docs/security/cli/reference).

## Architecture

This fork adopts the four-space hexagonal architecture described in [ADR-0001](docs/adr/0001-four-space-hexagonal-architecture.md):

- **Kernel**: pure domain state and port contracts
- **Validation**: deterministic policy and promotion decisions
- **Transport**: CLI, API, persistence, and provider adapters
- **Proof**: host-generated evidence and verification