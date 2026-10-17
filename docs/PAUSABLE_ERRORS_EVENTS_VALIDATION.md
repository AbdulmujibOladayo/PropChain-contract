# Pausable: errors, events, validation and gas

Pausable in this repository is the pause logic of the `PropertyRegistry` ink! contract (`contracts/lib/src/lib.rs`): `pause_contract`, `emergency_pause`, `request_resume`, `approve_resume`, `ensure_not_paused` and `get_pause_state`. There is no separate Solidity `Pausable` contract.

## Custom errors (#1303)

Pause failures are typed variants of the contract `Error` enum, not strings: `ContractPaused`, `AlreadyPaused`, `NotPaused`, `NotAuthorizedToPause`, `ValueOutOfBounds`.

## Input validation (#1302)

`pause_contract` validates the reason length against `MAX_REASON_LENGTH` (2,000) and the optional duration against `MIN_PAUSE_DURATION` (60 s) .. `MAX_PAUSE_DURATION` (2,592,000 s), returning `Error::ValueOutOfBounds` for durations outside the range. Validation runs before any state is written.

## Events (#1301)

Pausing emits `ContractPaused { by, reason, timestamp, auto_resume_at }` and writes a `SecurityEventType::ContractPaused` audit entry. Resuming emits the corresponding resume event.

## Gas / resource use (#1300)

The paused check (`ensure_not_paused`) is a single flag read on the hot path. Resume approvals are kept in a small vector that is cleared on every new pause, so storage does not grow across pause cycles.

## Tests

`contracts/lib/tests/pausable_validation.rs` covers the duration bounds, reason length and authorization errors.
