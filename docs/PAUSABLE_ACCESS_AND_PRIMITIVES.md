# Pausable: access control and primitives

Pausable in this repository is the pause logic of the `PropertyRegistry` ink! contract (`contracts/lib/src/lib.rs`): `pause_contract`, `emergency_pause`, `request_resume`, `approve_resume`, `ensure_not_paused` and `get_pause_state`. There is no separate Solidity `Pausable` contract.

## Access control audit (#1306)

- `pause_contract` and `emergency_pause` accept the contract admin, an account holding the `PauseGuardian` role, or an account in the legacy `pause_guardians` mapping. Anyone else gets `Error::NotAuthorizedToPause` and a `SecurityEventType::UnauthorizedAccess` audit event.
- Pausing an already paused contract returns `Error::AlreadyPaused` without changing state.
- Resuming needs `request_resume` followed by enough distinct `approve_resume` calls; `set_pause_guardian` is admin-only.

## OpenZeppelin primitives (#1304)

OpenZeppelin `Pausable` is a Solidity library. The ink! equivalent already implemented here is the `paused` flag in `PauseInfo` plus `ensure_not_paused()` (the `whenNotPaused` modifier) and the RBAC `Role::PauseGuardian`. No external primitive is required.

## Tests (#1305, #1307)

`contracts/lib/tests/pausable_integration.rs` covers the pause-and-resume flow, the invariant that a second pause leaves state untouched, and the invariant that non-privileged callers can never pause.
