#!/bin/bash

# Deploy the PropChain TransparentProxy (#1278).
#
# The proxy constructor takes the initial implementation and the admin
# account, so both must be supplied at deploy time.
#
# Usage:
#   ./deploy_proxy.sh <implementation_address> <admin_address> [node_url] [suri]
#
# Example (local dev node):
#   ./deploy_proxy.sh 5GrwvaEF... 5FHneW46... ws://localhost:9944 //Alice

set -euo pipefail

IMPLEMENTATION_ADDRESS=$1
ADMIN_ADDRESS=$2
NODE_URL=${3:-ws://localhost:9944}
SURI=${4:-//Alice}

if [ -z "${IMPLEMENTATION_ADDRESS:-}" ] || [ -z "${ADMIN_ADDRESS:-}" ]; then
    echo "Usage: ./deploy_proxy.sh <implementation_address> <admin_address> [node_url] [suri]"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_DIR="$SCRIPT_DIR/../contracts/proxy"

echo "Building propchain-proxy..."
cargo contract build --release --manifest-path "$PROXY_DIR/Cargo.toml"

echo "Instantiating proxy..."
cargo contract instantiate \
    --manifest-path "$PROXY_DIR/Cargo.toml" \
    --constructor new \
    --args "$IMPLEMENTATION_ADDRESS" "$ADMIN_ADDRESS" \
    --suri "$SURI" \
    --url "$NODE_URL" \
    --execute

echo "Proxy deployed with implementation $IMPLEMENTATION_ADDRESS and admin $ADMIN_ADDRESS."
echo "Use ./upgrade.sh <proxy_address> <new_logic_wasm_path> to stage future upgrades."
