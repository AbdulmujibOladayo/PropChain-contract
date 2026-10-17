#!/usr/bin/env bash
# PropChain ReentrancyGuard deployment script.
#
# ReentrancyGuard is embedded in the contracts that use it (it is not a
# standalone contract), so deploying it means building and instantiating the
# PropertyRegistry contract that carries the guard.
#
# Usage:
#   SURI="//Alice" ./scripts/deploy_reentrancy_guard.sh
#   URL=wss://rpc.example.org SURI="//Alice" ./scripts/deploy_reentrancy_guard.sh
set -euo pipefail

URL="${URL:-ws://127.0.0.1:9944}"
SURI="${SURI:?Set SURI to the deployer secret URI}"
MANIFEST="contracts/lib/Cargo.toml"

command -v cargo-contract >/dev/null 2>&1 || {
  echo "cargo-contract is required: cargo install cargo-contract" >&2
  exit 1
}

echo "Building contract..."
cargo contract build --manifest-path "$MANIFEST" --release

BUNDLE="target/ink/propchain_contracts.contract"

echo "Instantiating on $URL..."
cargo contract instantiate "$BUNDLE" --constructor new --url "$URL" --suri "$SURI" --skip-confirm
