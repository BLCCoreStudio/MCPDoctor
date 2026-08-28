# MCPDoctor

**Local diagnostics, security review, and configuration-drift checks for Model Context Protocol setups.**

> **Status:** development preview. No stable release has been published.

MCPDoctor is a local Rust CLI for answering a practical question: **why does this MCP configuration look risky or fail before the client even launches it?**

The current development line combines:

- deterministic security/configuration checks
- safe local diagnostics for the configured server command
- executable discovery through the current `PATH`
- local configuration baselines and drift detection

MCPDoctor does not automatically launch arbitrary MCP server commands in `doctor` mode. That keeps diagnostics predictable while executable probing and protocol handshakes are developed behind explicit opt-in behavior.

## Scan a configuration

```bash
mcpdoctor scan <CONFIG>
```

Current deterministic checks include:

- `MCP001` — plaintext HTTP endpoints
- `MCP002` — shell-capable server commands such as Bash, PowerShell, or `/bin/sh`
- `MCP003` — possible inline token/API-key fields
- `MCP004` — possible filesystem-root access indicators

Findings are review signals, not proof that a configuration or server is malicious.

## Run safe diagnostics

```bash
mcpdoctor doctor <CONFIG>
```

The current doctor report checks:

- whether the configuration is readable
- current MCPDoctor security/configuration rules
- whether a JSON `command` string can be detected
- whether that executable can be resolved in the current `PATH`
- whether additional review is required

Example shape:

```text
CONFIG      ✓ readable: mcp.json
SECURITY    ✓ no current rule matched
COMMAND     ✓ detected: node
EXECUTABLE  ✓ /usr/bin/node
NETWORK     · no server process was launched
HANDSHAKE   · not performed in safe doctor mode
RESULT      PASS
```

The explicit `NETWORK` and `HANDSHAKE` lines make current capability boundaries visible rather than implying checks that did not happen.

## Configuration drift baselines

Create a local baseline:

```bash
mcpdoctor baseline init ~/.config/example/mcp.json ./mcp.baseline
```

Check for later changes:

```bash
mcpdoctor baseline check ~/.config/example/mcp.json ./mcp.baseline
```

Accept the current file as the new baseline:

```bash
mcpdoctor baseline update ~/.config/example/mcp.json ./mcp.baseline
```

Baseline updates are written through a temporary file and rename. The current drift check compares bytes and reports the approximate first changed line/byte.

## Relationship to MCPWatch

`MCPWatch` remains a focused companion repository that documents the earlier baseline-monitoring experiment. Its core drift direction is now integrated into MCPDoctor, which is the primary product target for MCP diagnostics and configuration health.

## Exit behavior

- `0` — requested check passed
- `2` — usage/read/setup failure
- `3` — review signal, missing executable, or configuration drift detected

## Build

Requires Rust 1.74 or newer.

```bash
cargo build --locked
cargo test --locked
```

## Security model and limitations

- `doctor` currently does not execute the configured server.
- String extraction intentionally supports a conservative subset of common JSON configuration shapes; it is not a replacement for full MCP schema validation.
- A clean local scan does not prove that an MCP server is trustworthy or safe at runtime.
- Baseline equality proves only that the compared files are byte-identical.
- Protocol initialization, `tools/list`, latency checks, and explicit opt-in server probing are planned future diagnostics and will not be claimed until implemented and testable.

See [SECURITY.md](SECURITY.md) for reporting guidance and limitations.

## License

MIT © BLC Core Studio
