# MCPDoctor

**Security and configuration analyzer for Model Context Protocol servers and tools.**

> **Status:** early development. No stable release has been published.

MCPDoctor is a local Rust CLI for reviewing MCP configuration files and surfacing security-relevant signals before those configurations are trusted by an AI client.

## Current development preview

The first implementation will deliberately start with explainable local checks such as:

- plaintext HTTP endpoints
- shell-capable server commands
- possible inline credential fields
- broad filesystem access indicators

Results are heuristic findings, not proof that a configuration is malicious or safe.

## Planned v0.1

```text
mcpdoctor scan <CONFIG>
```

The v0.1 goal is local config inspection with clear rule identifiers, severity, explanations, and script-friendly exit behavior. MCPDoctor will not send configuration data to a remote service.

## Build

Requires Rust 1.74 or newer.

```bash
cargo build
cargo test
```

## Security

See [SECURITY.md](SECURITY.md).

## License

MIT © BLC Core Studio
