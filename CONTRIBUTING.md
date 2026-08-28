# Contributing

Focused rule improvements, false-positive reductions, tests, documentation fixes, and portability work are welcome.

Before opening a pull request:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

Keep security-rule changes explainable and covered by tests. Vulnerabilities should follow `SECURITY.md`.
