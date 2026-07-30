# Codex Security

`@openai/codex-security` is a CLI and TypeScript SDK for finding, validating, and fixing security vulnerabilities in your code.

**This repository is a fork of [OpenAI's codex-security](https://github.com/openai/codex-security) with a fundamental architecture rewrite.**

> Note: for best results, we recommend that your account is verified for [Trusted Access](https://chatgpt.com/cyber).

## Attribution

This project is derived from the original `@openai/codex-security` repository by OpenAI, licensed under the Apache License 2.0. See [NOTICES.md](NOTICES.md) for full attribution details.

We are fundamentally rewriting the entire architecture:
- The backend scan engine and SDK are being replaced with a **Rust** implementation (`sdk/rust/`)
- CLI tooling and build infrastructure use **Go** (`dagger/`)
- The four-space hexagonal architecture (ADR-0001) is adopted for the rewrite
- All backend work uses Rust or Go, not Python or TypeScript

## Quick start

Requires Node.js 22.13.0 or later in the 22.x release line, Node.js 24.x, or
Node.js 26.x; Python 3.10 or later; and access to Codex Security.

```bash
npm install @openai/codex-security
npx @openai/codex-security login
npx @openai/codex-security scan .
npx @openai/codex-security scan . --model gpt-5.6-terra --effort high
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
npx @openai/codex-security scan . --auth chatgpt
npx @openai/codex-security scan . --auth api-key
```

To make your ChatGPT sign-in the automatic default, unset any configured API
keys:

```bash
unset OPENAI_API_KEY CODEX_API_KEY
```

Scan history is stored in the Codex Security workbench state directory. If that
directory cannot be written, set `CODEX_SECURITY_STATE_DIR` to a writable
directory outside the repository.

## TypeScript SDK

The TypeScript SDK (`sdk/typescript/`) remains available during the migration to the Rust backend.

```ts
import { CodexSecurity } from "@openai/codex-security";

const security = new CodexSecurity();
const result = await security.run(".");

console.log(result.reportPath);
await security.close();
```

## Rust SDK (Rewrite Target)

The Rust SDK (`sdk/rust/`) is being developed as the replacement backend. It provides
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
[TypeScript package README](sdk/typescript/README.md) and the
[official CLI reference](https://learn.chatgpt.com/docs/security/cli/reference).
