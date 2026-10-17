#!/usr/bin/env bash

# PropChain AccessControl Deployment Script (issue #1262)
#
# Deploys the AccessControl trait/contract module to a Substrate-based
# network. AccessControl is part of the `propchain-traits` crate and is
# embedded in contracts that depend on it. This script handles building,
# uploading, instantiating, and post-deployment configuration (bootstrap,
# role grants, permission grants) for the AccessControl component.
#
# Usage:
#   ./scripts/deploy_access_control.sh --network local
#   ./scripts/deploy_access_control.sh --network westend --suri "//Alice"
#   NETWORK=westend SURI="//Alice" ./scripts/deploy_access_control.sh

set -euo pipefail

# ── Colour helpers ─────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

# ── Configuration ───────────────────────────────────────────────────────────
NETWORK="${NETWORK:-local}"
SURI="${SURI:-//Alice}"
WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE_TTL_BLOCKS="${CACHE_TTL_BLOCKS:-100}"

# Network RPC endpoints
declare -A NETWORKS=(
    ["local"]="ws://localhost:9944"
    ["westend"]="wss://westend-rpc.polkadot.io"
    ["rococo"]="wss://rococo-rpc.polkadot.io"
    ["polkadot"]="wss://rpc.polkadot.io"
)

# Default accounts for different networks
declare -A DEFAULT_ACCOUNTS=(
    ["local"]="//Alice"
    ["westend"]=""
    ["rococo"]=""
    ["polkadot"]=""
)

# ── Validation ─────────────────────────────────────────────────────────────
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

validate_network() {
    if [[ -z "${NETWORKS[$NETWORK]:-}" ]]; then
        log_error "Unknown network: $NETWORK"
        log_info "Available networks: ${!NETWORKS[*]}"
        exit 1
    fi
}

check_prerequisites() {
    log_info "Checking prerequisites..."

    if ! command_exists cargo-contract; then
        log_error "cargo-contract not found. Install with: cargo install cargo-contract --locked"
        exit 1
    fi

    if ! command_exists jq; then
        log_error "jq not found. Install with: apt-get install jq or brew install jq"
        exit 1
    fi

    if [ "$NETWORK" != "local" ] && [ -z "${SURI:-}" ]; then
        log_error "SURI (mnemonic) not set for network: $NETWORK"
        log_info "Set it with: export SURI='your mnemonic phrase'"
        exit 1
    fi

    log_success "Prerequisites check passed"
}

# ── Build ──────────────────────────────────────────────────────────────────
build_traits() {
    log_info "Building propchain-traits crate..."

    cd "$WORKSPACE_ROOT"
    if ! cargo build -p propchain-traits --release 2>&1; then
        log_error "Failed to build propchain-traits"
        exit 1
    fi

    log_success "propchain-traits built successfully"
}

# ── Deploy ─────────────────────────────────────────────────────────────────
#
# AccessControl lives inside the `propchain-traits` crate. In a production
# setup it is embedded in a contract (e.g. `propchain-contracts`) that
# re-exports its storage. This script deploys whichever contract hosts
# AccessControl storage. If a host contract is not specified via
# --host-contract, it defaults to `propchain-contracts` (the lib crate).
deploy_access_control() {
    local host_contract="${HOST_CONTRACT:-propchain-contracts}"
    local contract_dir="$WORKSPACE_ROOT/contracts/lib"

    if [ ! -d "$contract_dir" ]; then
        log_error "Host contract directory not found: $contract_dir"
        log_info "Set HOST_CONTRACT to the directory name under contracts/"
        return 1
    fi

    log_info "Deploying AccessControl (hosted in $host_contract) to $NETWORK..."

    cd "$contract_dir"

    # Upload code
    log_info "Uploading contract code..."
    local upload_result
    upload_result=$(cargo contract upload \
        --url "${NETWORKS[$NETWORK]}" \
        --suri "${SURI:-${DEFAULT_ACCOUNTS[$NETWORK]}}" \
        --output-json 2>&1) || {
        log_error "Failed to upload contract code"
        echo "$upload_result"
        return 1
    }

    local code_hash
    code_hash=$(echo "$upload_result" | jq -r '.codeHash // empty')
    if [ -z "$code_hash" ]; then
        log_error "Failed to extract code hash from upload result"
        echo "$upload_result"
        return 1
    fi
    log_info "Code uploaded. Hash: $code_hash"

    # Instantiate — the AccessControl constructor accepts `cache_ttl_blocks`
    log_info "Instantiating AccessControl with cache_ttl_blocks=$CACHE_TTL_BLOCKS..."
    local instantiate_result
    instantiate_result=$(cargo contract instantiate \
        --constructor new \
        --args "$CACHE_TTL_BLOCKS" \
        --url "${NETWORKS[$NETWORK]}" \
        --suri "${SURI:-${DEFAULT_ACCOUNTS[$NETWORK]}}" \
        --code-hash "$code_hash" \
        --salt "$(date +%s)" \
        --output-json 2>&1) || {
        log_error "Failed to instantiate contract"
        echo "$instantiate_result"
        return 1
    }

    local contract_address
    contract_address=$(echo "$instantiate_result" | jq -r '.contract // empty')
    if [ -z "$contract_address" ]; then
        log_error "Failed to extract contract address"
        echo "$instantiate_result"
        return 1
    fi
    log_success "AccessControl deployed at: $contract_address"

    # Save deployment record
    local deployment_file="$WORKSPACE_ROOT/deployments/$NETWORK/access_control.json"
    mkdir -p "$(dirname "$deployment_file")"
    cat > "$deployment_file" << EOF
{
    "network": "$NETWORK",
    "contract": "access_control",
    "host_contract": "$host_contract",
    "address": "$contract_address",
    "codeHash": "$code_hash",
    "cache_ttl_blocks": $CACHE_TTL_BLOCKS,
    "deployedAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "deployedBy": "${SURI:-${DEFAULT_ACCOUNTS[$NETWORK]}}"
}
EOF
    log_info "Deployment record saved to: $deployment_file"

    # Post-deployment: bootstrap the admin
    log_info "Bootstrapping admin account..."
    log_info "Call bootstrap(admin=<deployer>, block_number=<current>, timestamp=<now>)"
    log_info "Use cargo contract call --contract $contract_address --message bootstrap ..."

    echo "$contract_address"
}

# ── Post-deployment configuration ───────────────────────────────────────────
#
# After instantiation the AccessControl storage is empty. The deploying
# account must call `bootstrap` to grant itself SuperAdmin + Admin roles.
# This function prints the commands for manual execution (the on-chain
# call requires a signed extrinsic).
post_deploy_bootstrap() {
    local contract_address="$1"

    echo ""
    log_info "=== Post-deployment steps ==="
    echo ""
    echo "AccessControl is live but has no roles assigned."
    echo "Run the following to bootstrap the admin:"
    echo ""
    echo "  cargo contract call \\"
    echo "    --contract $contract_address \\"
    echo "    --message bootstrap \\"
    echo "    --url ${NETWORKS[$NETWORK]} \\"
    echo "    --suri \"\${SURI:-${DEFAULT_ACCOUNTS[$NETWORK]}}\""
    echo ""
    echo "Then grant roles to other accounts:"
    echo ""
    echo "  cargo contract call \\"
    echo "    --contract $contract_address \\"
    echo "    --message grant_role \\"
    echo "    --args <target_account> <role_id> <block_number> <timestamp> \\"
    echo "    --url ${NETWORKS[$NETWORK]} \\"
    echo "    --suri \"\${SURI:-${DEFAULT_ACCOUNTS[$NETWORK]}}\""
    echo ""
    echo "Available roles (0-9):"
    echo "  0=SuperAdmin  1=Admin  2=OracleAdmin  3=ComplianceAdmin"
    echo "  4=FeeAdmin     5=BridgeOperator  6=Verifier  7=PauseGuardian"
    echo "  8=Manager      9=EscrowAdmin"
}

# ── Verify ─────────────────────────────────────────────────────────────────
verify_deployment() {
    local contract_address="$1"

    log_info "Verifying AccessControl at $contract_address..."

    cd "$WORKSPACE_ROOT/contracts/lib"

    if cargo contract info \
        --contract "$contract_address" \
        --url "${NETWORKS[$NETWORK]}" \
        --output-json 2>/dev/null | jq .; then
        log_success "Contract is live and accessible"
    else
        log_error "Contract verification failed"
        return 1
    fi
}

# ── Main ───────────────────────────────────────────────────────────────────
main() {
    local verify=false
    local skip_build=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --network)
                NETWORK="$2"
                shift 2
                ;;
            --suri)
                SURI="$2"
                shift 2
                ;;
            --host-contract)
                HOST_CONTRACT="$2"
                shift 2
                ;;
            --cache-ttl)
                CACHE_TTL_BLOCKS="$2"
                shift 2
                ;;
            --verify)
                verify=true
                shift
                ;;
            --skip-build)
                skip_build=true
                shift
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Deploy the AccessControl component to a Substrate network."
                echo ""
                echo "Options:"
                echo "  --network NETWORK     Target network (local, westend, rococo, polkadot)"
                echo "  --suri SURI           Account mnemonic (default: //Alice for local)"
                echo "  --host-contract NAME  Host contract directory (default: propchain-contracts)"
                echo "  --cache-ttl N         Permission cache TTL in blocks (default: 100)"
                echo "  --verify              Verify deployment after deploying"
                echo "  --skip-build          Skip the build step"
                echo "  --help                Show this help message"
                echo ""
                echo "Environment variables:"
                echo "  NETWORK               Target network (default: local)"
                echo "  SURI                  Account mnemonic"
                echo "  HOST_CONTRACT         Host contract name"
                echo "  CACHE_TTL_BLOCKS      Cache TTL in blocks (default: 100)"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    log_info "=== AccessControl Deployment ==="

    validate_network
    check_prerequisites

    if [ "$skip_build" = false ]; then
        build_traits
    fi

    local contract_address
    contract_address=$(deploy_access_control)

    if [ "$verify" = true ]; then
        verify_deployment "$contract_address" || true
    fi

    post_deploy_bootstrap "$contract_address"

    log_success "AccessControl deployment complete!"
}

main "$@"
