# Attribution and Third-Party Notices

## Codex Security

This repository is a fork of the [OpenAI Codex Security](https://github.com/openai/codex-security) project.

Original Project: `@openai/codex-security` by OpenAI  
Original Repository: https://github.com/openai/codex-security  
Original License: Apache License 2.0  
Original Copyright: Copyright 2025 OpenAI

This fork fundamentally rewrites the entire architecture of the original project.
While based on the original work, this version replaces the TypeScript SDK and Python
workbench with a Rust-based backend and Go-based tooling, adopting a four-space
hexagonal architecture with strict separation of domain logic, validation, transport,
and proof concerns.

All original Apache 2.0 license terms apply to the original code components retained
in this repository. The rewritten components are provided under the same Apache 2.0
license.

## Dependencies

See the individual component LICENSE files and `sdk/typescript/package.json` for
third-party dependency attributions.
