# ReentrancyGuard: overflow, storage gap and deployment

ReentrancyGuard in this repository is the `ReentrancyGuard` struct (a single `locked: bool`), its `ReentrancyError::ReentrantCall` error and the `non_reentrant!` macro in `contracts/traits/src/reentrancy_guard.rs` (mirrored in `contracts/lib/src/reentrancy_guard.rs`). `PropertyRegistry` holds one as its `reentrancy_guard` field.

## Integer overflow (#1292)

The guard holds a single `bool`; it has no counter or arithmetic, so it cannot overflow. `enter` returns `ReentrancyError::ReentrantCall` when already locked and never increments a depth.

## Storage gap (#1293)

Solidity storage gaps reserve slots in upgradeable base contracts. In ink! the guard is a field of the contract struct and its layout is derived from the struct (`StorageLayout`); upgrades go through the proxy contract (`contracts/proxy`), not through inherited slots. If the guard ever needs more state, add it as a new field and migrate through the proxy's upgrade path.

## Deployment (#1294)

`scripts/deploy_reentrancy_guard.sh` builds the registry contract that embeds the guard and instantiates it with `cargo contract`.

## Static analysis in CI (#1295)

`.github/workflows/reentrancy-guard-analysis.yml` runs Clippy with warnings denied and the guard tests whenever guard code changes (Slither only analyses Solidity).
