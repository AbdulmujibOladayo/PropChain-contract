# ReentrancyGuard: documentation and reentrancy review

ReentrancyGuard in this repository is the `ReentrancyGuard` struct (a single `locked: bool`), its `ReentrancyError::ReentrantCall` error and the `non_reentrant!` macro in `contracts/traits/src/reentrancy_guard.rs` (mirrored in `contracts/lib/src/reentrancy_guard.rs`). `PropertyRegistry` holds one as its `reentrancy_guard` field.

## Documentation (#1282)

| Item | Behaviour |
|------|-----------|
| `ReentrancyGuard::new()` | Creates an unlocked guard |
| `enter()` | `Ok(())` and locks; `Err(ReentrancyError::ReentrantCall)` if already locked |
| `exit()` | Unlocks. Safe to call when already unlocked |
| `is_locked()` | Reads the flag without changing it |
| `non_reentrant!(self, { ... })` | Enters, runs the block, always exits, returns the block's result |

## Review (#1283)

The guard is a plain mutex flag, which is the standard protection against a callee calling back into a message while the first call is still mid-update. Review notes:

- `non_reentrant!` runs the body in a closure and calls `exit()` after it, so early `return`/`?` inside the block still unlock. A panic aborts the whole message, which reverts storage in ink!, so the flag is not left set.
- Protected messages should perform checks first, update state, then make external calls (checks-effects-interactions); the guard is a second line of defence, not a replacement.
- Read-only messages do not need the guard.

## Tests (#1280, #1281)

`contracts/traits/tests/reentrancy_guard_unit_fuzz.rs` has unit tests and a deterministic randomized sequence test checked against a boolean model.
