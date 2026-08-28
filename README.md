# MCPDoctor

**Local security and configuration analyzer for Model Context Protocol configuration files.**

> **Status:** development preview. No stable release has been published.

MCPDoctor is a local Rust CLI for reviewing MCP configuration files and surfacing security-relevant signals before those configurations are trusted by an AI client.

## Current preview

```bash
mcpdoctor scan <CONFIG>
```

The current deterministic checks flag:

- `MCP001` — plaintext HTTP endpoints
- `MCP002` — shell-capable server commands such as Bash, PowerShell, or `/bin/sh`
- `MCP003` — possible inline token/API-key fields
- `MCP004` — possible filesystem-root access indicators

A clean scan prints `PASS`. Findings are reported as warnings and return a non-zero exit status. Read or usage errors are reported separately.

These checks are conservative heuristics. A finding is not proof that a configuration is malicious, and a clean result is not proof that an MCP server or configuration is safe. MCPDoctor performs the current checks locally and does not upload configuration data.

## Build

Requires Rust 1.74 or newer.

```bash
cargo build --locked
cargo test --locked
```

## Security

See [SECURITY.md](SECURITY.md) for reporting guidance and limitations.

## License

MIT © BLC Core Studio
