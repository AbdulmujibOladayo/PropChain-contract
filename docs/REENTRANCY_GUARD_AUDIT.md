# ReentrancyGuard: access control audit and primitives

ReentrancyGuard in this repository is the `ReentrancyGuard` struct (a single `locked: bool`), its `ReentrancyError::ReentrantCall` error and the `non_reentrant!` macro in `contracts/traits/src/reentrancy_guard.rs` (mirrored in `contracts/lib/src/reentrancy_guard.rs`). `PropertyRegistry` holds one as its `reentrancy_guard` field.

## Access control audit (#1290)

The guard has no privileged operations: `enter`, `exit` and `is_locked` are plain methods on a struct owned by the embedding contract, so only that contract's own code can reach them. There is no admin, owner or role on the guard, and no message exposes it directly. `exit` must run after every successful `enter`; the `non_reentrant!` macro guarantees this for the wrapped block.

## OpenZeppelin primitives (#1288)

The implementation already mirrors OpenZeppelin's `ReentrancyGuard` (a mutex flag with `nonReentrant` semantics via `non_reentrant!`). No external library is needed in ink!.

## Tests (#1289, #1291)

`contracts/traits/tests/reentrancy_guard_integration.rs` drives the guard from a vault-like contract, including a self re-entrant call, and checks the invariants that the guard is unlocked after every completed call and that a failed `enter` never unlocks it.
