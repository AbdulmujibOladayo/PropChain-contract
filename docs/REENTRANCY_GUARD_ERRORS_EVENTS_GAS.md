# ReentrancyGuard: errors, events, validation and gas

ReentrancyGuard in this repository is the `ReentrancyGuard` struct (a single `locked: bool`), its `ReentrancyError::ReentrantCall` error and the `non_reentrant!` macro in `contracts/traits/src/reentrancy_guard.rs` (mirrored in `contracts/lib/src/reentrancy_guard.rs`). `PropertyRegistry` holds one as its `reentrancy_guard` field.

## Custom errors (#1287)

The guard already returns a typed `ReentrancyError::ReentrantCall` (SCALE-encodable) instead of a string. Contracts convert it into their own `Error` with `?` inside `non_reentrant!`.

## Input validation (#1286)

`enter`, `exit` and `is_locked` take no arguments, so there is no input to validate. The only state check is `locked`, evaluated before the flag is set.

## Events (#1285)

The guard deliberately emits no events: it is embedded in the hot path of value-moving messages, and a rejected re-entrant call surfaces as the caller's error. Contracts that need an audit trail log it themselves (the registry writes audit entries).

## Gas / resource use (#1284)

One `bool` of storage; `enter` is one read and one write, `exit` one write, `is_locked` one read. No allocation, no loops.

## Tests

`contracts/traits/tests/reentrancy_guard_errors.rs` covers the error value, idempotent `exit` and the default state.
