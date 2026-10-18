# PropertyRegistry testing plan

> Status: this document records the agreed approach and a checklist for `PropertyRegistry`. It was written without changing contract code; code changes should follow the checklist in small, reviewable PRs.

## Issue #1328: Unit tests for PropertyRegistry

Cover each public message with at least one happy-path and one failure-path test:

- Constructor sets the expected initial state (owner/admin, counters, defaults).
- Every state-changing message emits the expected event and updates storage exactly once.
- Every restricted message rejects a non-authorized caller with the expected `Error` variant.
- Boundary values: zero, one, maximum, and just-over-maximum inputs.
- Repeated calls (idempotency) and calls in the wrong state return an error instead of panicking.

Place tests in the contract's `#[cfg(test)]` module using `ink::env::test` for callers and block timestamps.


## Issue #1329: Fuzz tests for PropertyRegistry

Use `proptest` (already common in the workspace) with these properties:

- No message panics for any generated input; failures are returned as `Result::Err`.
- Total supply / counters never decrease unless a burn/removal message is called.
- Applying a message and then its inverse returns the contract to the original observable state.
- Arbitrary sequences of up to 50 messages keep the invariants listed in the invariants document.

Seed failing cases into a regression test so they stay covered.

