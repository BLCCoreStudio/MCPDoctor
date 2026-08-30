#!/usr/bin/env bash
set -euo pipefail

config="${MCPDOCTOR_INPUT_CONFIG:-}"
mode="${MCPDOCTOR_INPUT_MODE:-scan}"

if [[ -z "$config" ]]; then
  echo "ERROR: config input is required" >&2
  exit 2
fi

case "$mode" in
  scan|doctor) ;;
  *)
    echo "ERROR: mode must be 'scan' or 'doctor'" >&2
    exit 2
    ;;
esac

manifest="$GITHUB_ACTION_PATH/Cargo.toml"
cargo build --release --locked --manifest-path "$manifest"
binary="$GITHUB_ACTION_PATH/target/release/mcpdoctor"
test -x "$binary"

"$binary" "$mode" "$config"
