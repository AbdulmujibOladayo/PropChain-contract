# Access Control Audit & Documentation

> Issue #1258 — Audit access control in `AccessControl`

## Overview

The `AccessControl` storage item (`contracts/traits/src/access_control.rs`) provides
role-based access control (RBAC) for all PropChain contracts. It manages three
concerns:

1. **Role assignments** — which accounts hold which roles
2. **Permission grants** — which roles/accounts are allowed which actions on which resources
3. **Key rotation** — secure transfer of an account's roles to a new account

All security-relevant state changes are recorded in an immutable, sequential
audit log.

## Role Hierarchy

```
SuperAdmin
  └── Admin
        ├── OracleAdmin
        ├── ComplianceAdmin
        ├── FeeAdmin
        ├── BridgeOperator
        ├── Verifier
        ├── PauseGuardian
        ├── Manager
        └── EscrowAdmin
```

`SuperAdmin` is the root role. `Admin` is the operational admin. All other roles
inherit from `Admin`, meaning a `SuperAdmin` holder is implicitly an `Admin`,
`OracleAdmin`, `Verifier`, etc. This is implemented via `ancestor_roles()`:
when checking `has_role(account, OracleAdmin)`, the system also checks whether
`account` holds `Admin` or `SuperAdmin`.

### Role Descriptions

| Role              | Scope                                          |
|-------------------|------------------------------------------------|
| `SuperAdmin`      | Full control, including role management       |
| `Admin`           | Grant/revoke roles and permissions             |
| `OracleAdmin`     | Configure oracle sources and parameters         |
| `ComplianceAdmin` | Manage compliance registry and sanctions       |
| `FeeAdmin`        | Set and adjust fee parameters                   |
| `BridgeOperator`  | Initiate and manage cross-chain bridges         |
| `Verifier`        | Verify property metadata and documents          |
| `PauseGuardian`   | Pause/unpause contracts in emergencies          |
| `Manager`         | Manage property listings and metadata           |
| `EscrowAdmin`     | Override and resolve escrow disputes            |

## Permission Model

Permissions are `(Resource, Action)` pairs. A permission can be granted to:

1. **A role** — applies to every account holding that role (or any ancestor role)
2. **An account directly** — applies only to that specific account

### Resources

| Resource          | Description                            |
|-------------------|----------------------------------------|
| `Global`          | All resources                          |
| `PropertyRegistry`| Property registration and lookup       |
| `Oracle`          | Oracle price feeds                     |
| `Bridge`          | Cross-chain bridge operations           |
| `Escrow`          | Escrow lifecycle                        |
| `Compliance`      | Compliance and sanctions               |
| `Metadata`        | IPFS metadata storage                   |
| `Insurance`       | Insurance policies                      |
| `Analytics`       | Analytics and reporting                 |
| `Fees`            | Fee configuration                       |
| `Property(u64)`   | A specific property by ID               |
| `Token(u64)`      | A specific token by ID                  |

### Actions

| Action         | Description                              |
|----------------|------------------------------------------|
| `ManageRoles`  | Grant or revoke roles                    |
| `Configure`    | Change configuration parameters           |
| `Update`       | Update data (metadata, valuations, etc.) |
| `Transfer`     | Transfer ownership                        |
| `Pause`        | Pause or resume a contract                |
| `Verify`       | Verify or approve                         |
| `Mint`         | Mint tokens                              |
| `Burn`         | Burn tokens                              |

### Permission Resolution Order

1. Check account-level permission (`account_permissions` mapping)
2. Check role-level permission for every role the account holds

If either check returns `true`, the account has the permission.

## Permission Cache

`has_permission_cached` provides a cached lookup using an **epoch-based
invalidation** model:

- The cache key is `(AccountId, Permission, cache_epoch)`.
- When any permission or role changes, `invalidate_cache()` increments
  `cache_epoch`, making all previous cache entries unreachable.
- Within a single epoch, cached values are reused without recomputation.

This is a simple, correct model: every mutation invalidates the entire cache,
and stale entries can never be served because the epoch is part of the key.

The `cache_ttl_blocks` and `current_block` parameters are accepted by
`has_permission_cached` for API compatibility but are not used in the current
implementation — the epoch-based model is stronger and simpler than TTL-based
invalidation.

## Key Rotation

Key rotation allows an account to transfer all of its roles to a new account,
which is critical for key compromise recovery and account migration.

### Lifecycle

```
1. request_key_rotation(old, new, block, timestamp)
   → Creates a pending KeyRotationRequest
   → Cooldown period begins (KEY_ROTATION_COOLDOWN_BLOCKS = 14,400 blocks ≈ 24h)

2. confirm_key_rotation(old, caller, block, timestamp)
   → Caller must be the new account
   → Block must be >= effective_at (cooldown elapsed)
   → Block must be <= effective_at + KEY_ROTATION_EXPIRY_BLOCKS (43,200 blocks ≈ 3 days)
   → All roles transferred from old to new account
   → Pending rotation removed

3. cancel_key_rotation(old, caller, block, timestamp)
   → Can be called by either old or new account at any time
   → Removes the pending rotation without transferring roles
```

### Security Properties

- Only the account itself can initiate its own rotation
- Only the designated new account can confirm (prevents hijacking)
- Duplicate rotation requests while one is pending are rejected
- After confirmation, the old account has zero roles
- The per-account `rotation_nonce` prevents replay attacks

## Audit Trail

Every security-relevant operation writes a `PermissionAuditEntry` to the
`audit_log` mapping, keyed by a monotonically increasing `audit_count`.

### Audit Actions

| Action                          | When emitted                        |
|---------------------------------|-------------------------------------|
| `RoleGranted`                   | `grant_role` succeeds               |
| `RoleRevoked`                   | `revoke_role` succeeds              |
| `PermissionGrantedToRole`       | `grant_permission_to_role` succeeds |
| `PermissionRevokedFromRole`     | `revoke_permission_from_role` (future) |
| `PermissionGrantedToAccount`    | Direct account permission grant     |
| `PermissionRevokedFromAccount`  | Direct account permission revoke    |
| `KeyRotationRequested`          | `request_key_rotation` succeeds     |
| `KeyRotationCompleted`          | `confirm_key_rotation` succeeds     |
| `KeyRotationCancelled`         | `cancel_key_rotation` succeeds      |

### Audit Entry Fields

| Field          | Type              | Description                        |
|----------------|-------------------|------------------------------------|
| `id`           | `u64`             | Sequential ID (1-based)            |
| `actor`        | `AccountId`       | Who performed the action            |
| `target`       | `AccountId`       | Who was affected                    |
| `action`       | `AuditAction`    | What was done                       |
| `role`         | `Option<Role>`   | Role involved (if any)              |
| `permission`   | `Option<Permission>` | Permission involved (if any)    |
| `block_number` | `u32`            | Block number when action occurred   |
| `timestamp`    | `u64`            | Timestamp when action occurred      |

## Integer Overflow Protection (Issue #1260)

All arithmetic in `AccessControl` uses `checked_add` with explicit error
handling. The following counters are protected:

| Counter        | Location              | Overflow behavior           |
|----------------|-----------------------|-----------------------------|
| `audit_count`  | `write_audit`         | Returns `ArithmeticOverflow`|
| `cache_epoch`  | `invalidate_cache`    | Returns `ArithmeticOverflow`|
| `rotation_nonce` | `request_key_rotation` | Returns `ArithmeticOverflow`|

The `ArithmeticOverflow` error variant was added to `AccessControlError` to
ensure no counter silently wraps. In practice, reaching `u64::MAX` would
require ~584 billion years of operations at 1 per second, but the guard
ensures correctness by construction.

Block-number arithmetic (`effective_at`, `expiry`) uses `saturating_add`
because these are inherently bounded by the block number space (`u32`), and
saturation at `u32::MAX` simply means "never expires" / "always eligible",
which is a safe degradation.

## Error Reference

| Error                    | When returned                                  |
|--------------------------|------------------------------------------------|
| `Unauthorized`           | Caller lacks the required role                  |
| `KeyRotationCooldown`    | Confirmation attempted before cooldown elapses  |
| `KeyRotationExpired`     | Confirmation attempted after expiry window       |
| `NoPendingRotation`      | No rotation exists for the account              |
| `RotationUnauthorized`   | Caller is not the old or new account            |
| `ArithmeticOverflow`     | A counter has reached `u64::MAX`               |

## Integration Notes

Contracts embed `AccessControl` as a storage field and call its methods
directly. The contract is responsible for:

1. Calling `bootstrap()` during construction to set the initial admin
2. Using `ensure_has_role()` or `has_permission_cached()` to guard privileged
   operations
3. Passing the current block number and timestamp for audit records

Example usage:

```rust
// In your contract's storage struct
access_control: AccessControl,

// In constructor
let mut ac = AccessControl::new(64); // 64-block cache TTL
ac.bootstrap(caller, block_number, timestamp);

// In a privileged message
self.access_control.ensure_has_role(caller, Role::Admin)?;
```

## Test Coverage

- **Invariant tests**: `contracts/traits/tests/access_control_invariants.rs`
  (12 tests covering audit-count accuracy, role hierarchy, cache
  consistency, invalidation, non-admin rejection, key rotation lifecycle,
  overflow guards, and audit entry integrity)

- **Integration tests**: `contracts/traits/tests/access_control_integration.rs`
  (end-to-end flow tests covering bootstrap → grant → check → revoke,
  key rotation full lifecycle, and permission caching behavior)
