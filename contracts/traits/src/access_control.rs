//! Role-based access control primitives for PropChain smart contracts.
//!
//! # Overview
//!
//! This module provides an OpenZeppelin-style RBAC system where:
//! - Every role has a designated **role admin** that controls who can grant/revoke it.
//! - Roles form an inheritance hierarchy (e.g. `SuperAdmin` has all `Admin` permissions).
//! - State changes emit ink! events consumable by off-chain indexers.
//! - All public entry-points validate inputs with descriptive custom errors.
//!
//! # Issues addressed
//!
//! | Issue | Summary |
//! |-------|---------|
//! | [#1253](https://github.com/MettaChain/PropChain-contract/issues/1253) | Add events for AccessControl state changes |
//! | [#1254](https://github.com/MettaChain/PropChain-contract/issues/1254) | Add input validation in AccessControl |
//! | [#1255](https://github.com/MettaChain/PropChain-contract/issues/1255) | Use custom errors in AccessControl |
//! | [#1256](https://github.com/MettaChain/PropChain-contract/issues/1256) | Refactor AccessControl with OpenZeppelin primitives |

use ink::prelude::vec::Vec;
use ink::primitives::AccountId;
use ink::storage::Mapping;

// ─────────────────────────────────────────────────────────────────────────────
// Roles
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, scale::Encode, scale::Decode)]
#[cfg_attr(
    feature = "std",
    derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
)]
pub enum Role {
    SuperAdmin,
    Admin,
    OracleAdmin,
    ComplianceAdmin,
    FeeAdmin,
    BridgeOperator,
    Verifier,
    PauseGuardian,
    Manager,
    EscrowAdmin,
}

// ─────────────────────────────────────────────────────────────────────────────
// Resources and actions
// ─────────────────────────────────────────────────────────────────────────────

#[allow(clippy::cast_possible_truncation)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, scale::Encode, scale::Decode)]
#[cfg_attr(
    feature = "std",
    derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
)]
pub enum Resource {
    Global,
    PropertyRegistry,
    Oracle,
    Bridge,
    Escrow,
    Compliance,
    Metadata,
    Insurance,
    Analytics,
    Fees,
    Property(u64),
    Token(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, scale::Encode, scale::Decode)]
#[cfg_attr(
    feature = "std",
    derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
)]
pub enum Action {
    ManageRoles,
    Configure,
    Update,
    Transfer,
    Pause,
    Verify,
    Mint,
    Burn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, scale::Encode, scale::Decode)]
#[cfg_attr(
    feature = "std",
    derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
)]
pub struct Permission {
    pub resource: Resource,
    pub action: Action,
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit trail
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, scale::Encode, scale::Decode)]
#[cfg_attr(
    feature = "std",
    derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
)]
pub enum AuditAction {
    RoleGranted,
    RoleRevoked,
    PermissionGrantedToRole,
    PermissionRevokedFromRole,
    PermissionGrantedToAccount,
    PermissionRevokedFromAccount,
    KeyRotationRequested,
    KeyRotationCompleted,
    KeyRotationCancelled,
    RoleAdminChanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, scale::Encode, scale::Decode)]
#[cfg_attr(
    feature = "std",
    derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
)]
pub struct PermissionAuditEntry {
    pub id: u64,
    pub actor: AccountId,
    pub target: AccountId,
    pub action: AuditAction,
    pub role: Option<Role>,
    pub permission: Option<Permission>,
    pub block_number: u32,
    pub timestamp: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Issue #1255 — Custom errors
// ─────────────────────────────────────────────────────────────────────────────
// The original enum covered only key-rotation failures. Every public function
// now returns a typed error variant rather than a bare panic or a generic
// "Unauthorized" catch-all, making call-site handling easier and error messages
// machine-readable.

#[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub enum AccessControlError {
    /// Caller does not hold the required role.
    Unauthorized,
    /// A key rotation is already pending for this account.
    KeyRotationCooldown,
    /// The pending rotation window has expired; the request was cleaned up.
    KeyRotationExpired,
    /// No pending rotation exists for the given account.
    NoPendingRotation,
    /// The caller is not permitted to confirm/cancel this rotation.
    RotationUnauthorized,
    // ── Issue #1254: input-validation errors ─────────────────────────────────
    /// The supplied `AccountId` is the zero/default address and is not accepted.
    ZeroAccount,
    /// The new account in a key-rotation request must differ from the current one.
    SameAccount,
    /// The `cache_ttl_blocks` supplied to `new()` must be at least 1.
    InvalidCacheTtl,
}

// ─────────────────────────────────────────────────────────────────────────────
// Issue #1253 — Events for AccessControl state changes
// ─────────────────────────────────────────────────────────────────────────────
// ink! events must be defined inside an `#[ink::contract]` module, but this
// module is a plain library crate.  We use the `#[ink::event]` standalone macro
// (ink! ≥ 5.x) so the events appear in the contract ABI whenever this crate is
// used as a dependency.

/// Emitted when a role is granted to an account.
#[ink::event]
pub struct RoleGranted {
    /// Account that performed the grant.
    #[ink(topic)]
    pub actor: AccountId,
    /// Account that received the role.
    #[ink(topic)]
    pub target: AccountId,
    /// The role that was granted.
    pub role: Role,
}

/// Emitted when a role is revoked from an account.
#[ink::event]
pub struct RoleRevoked {
    /// Account that performed the revocation.
    #[ink(topic)]
    pub actor: AccountId,
    /// Account that lost the role.
    #[ink(topic)]
    pub target: AccountId,
    /// The role that was revoked.
    pub role: Role,
}

/// Emitted when a permission is granted to a role.
#[ink::event]
pub struct RolePermissionGranted {
    /// Account that performed the grant.
    #[ink(topic)]
    pub actor: AccountId,
    /// Role that received the permission.
    pub role: Role,
    /// The permission that was granted.
    pub permission: Permission,
}

/// Emitted when a permission is revoked from a role.
#[ink::event]
pub struct RolePermissionRevoked {
    /// Account that performed the revocation.
    #[ink(topic)]
    pub actor: AccountId,
    /// Role that lost the permission.
    pub role: Role,
    /// The permission that was revoked.
    pub permission: Permission,
}

/// Emitted when a direct (account-level) permission is granted.
#[ink::event]
pub struct AccountPermissionGranted {
    /// Account that performed the grant.
    #[ink(topic)]
    pub actor: AccountId,
    /// Account that received the permission.
    #[ink(topic)]
    pub target: AccountId,
    /// The permission that was granted.
    pub permission: Permission,
}

/// Emitted when a direct (account-level) permission is revoked.
#[ink::event]
pub struct AccountPermissionRevoked {
    /// Account that performed the revocation.
    #[ink(topic)]
    pub actor: AccountId,
    /// Account that lost the permission.
    #[ink(topic)]
    pub target: AccountId,
    /// The permission that was revoked.
    pub permission: Permission,
}

/// Emitted when a key rotation is requested.
#[ink::event]
pub struct KeyRotationRequested {
    /// The account initiating key rotation.
    #[ink(topic)]
    pub old_account: AccountId,
    /// The new account that will receive all roles after cooldown.
    #[ink(topic)]
    pub new_account: AccountId,
    /// Block number at which the rotation becomes effective.
    pub effective_at: u32,
}

/// Emitted when a key rotation is confirmed and roles are transferred.
#[ink::event]
pub struct KeyRotationCompleted {
    /// The old account whose roles were transferred.
    #[ink(topic)]
    pub old_account: AccountId,
    /// The new account that now holds all roles.
    #[ink(topic)]
    pub new_account: AccountId,
}

/// Emitted when a pending key rotation is cancelled.
#[ink::event]
pub struct KeyRotationCancelled {
    /// The account whose pending rotation was cancelled.
    #[ink(topic)]
    pub old_account: AccountId,
    /// The account that cancelled the rotation.
    pub cancelled_by: AccountId,
}

/// Emitted when the role-admin for a role is changed (Issue #1256).
#[ink::event]
pub struct RoleAdminChanged {
    /// The role whose admin was updated.
    pub role: Role,
    /// The previous admin role.
    pub previous_admin: Role,
    /// The new admin role.
    pub new_admin: Role,
}

// ─────────────────────────────────────────────────────────────────────────────
// Storage
// ─────────────────────────────────────────────────────────────────────────────

type PermissionCacheKey = (AccountId, Permission, u64);

/// Issue #1256 — OpenZeppelin-style role-admin mapping.
///
/// Every role has a designated **admin role** (defaults to `Role::Admin`).
/// Only an account that holds the admin role for a given role may grant or
/// revoke it.  This lets the contract owner delegate role management in a
/// fine-grained way without giving everyone `Admin`.
///
/// Compare OpenZeppelin's `AccessControl._roles[role].adminRole`.
#[ink::storage_item]
#[derive(Default)]
pub struct AccessControl {
    role_assignments: Mapping<(AccountId, Role), bool>,
    role_permissions: Mapping<(Role, Permission), bool>,
    account_permissions: Mapping<(AccountId, Permission), bool>,
    permission_cache: Mapping<PermissionCacheKey, bool>,
    audit_log: Mapping<u64, PermissionAuditEntry>,
    audit_count: u64,
    cache_epoch: u64,
    cache_ttl_blocks: u32,
    pending_rotations: Mapping<AccountId, crate::crypto::KeyRotationRequest>,
    rotation_nonce: Mapping<AccountId, u64>,
    /// Issue #1256: maps each Role to its admin Role.
    /// Stored as `(role_index, admin_role_index)` pairs encoded as u8 tuples.
    role_admin: Mapping<u8, u8>,
}

impl core::fmt::Debug for AccessControl {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AccessControl")
            .field("audit_count", &self.audit_count)
            .field("cache_epoch", &self.cache_epoch)
            .field("cache_ttl_blocks", &self.cache_ttl_blocks)
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Role ↔ u8 conversion helpers (Issue #1256)
// ─────────────────────────────────────────────────────────────────────────────

impl Role {
    fn to_index(self) -> u8 {
        match self {
            Role::SuperAdmin => 0,
            Role::Admin => 1,
            Role::OracleAdmin => 2,
            Role::ComplianceAdmin => 3,
            Role::FeeAdmin => 4,
            Role::BridgeOperator => 5,
            Role::Verifier => 6,
            Role::PauseGuardian => 7,
            Role::Manager => 8,
            Role::EscrowAdmin => 9,
        }
    }

    fn from_index(idx: u8) -> Option<Role> {
        match idx {
            0 => Some(Role::SuperAdmin),
            1 => Some(Role::Admin),
            2 => Some(Role::OracleAdmin),
            3 => Some(Role::ComplianceAdmin),
            4 => Some(Role::FeeAdmin),
            5 => Some(Role::BridgeOperator),
            6 => Some(Role::Verifier),
            7 => Some(Role::PauseGuardian),
            8 => Some(Role::Manager),
            9 => Some(Role::EscrowAdmin),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Issue #1254 — Input validation helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `Err(AccessControlError::ZeroAccount)` when `account` is the default/zero
/// `AccountId` (all-zeroes byte array).  The zero address is never a legitimate
/// user address in Substrate and accepting it silently leads to hard-to-debug
/// permission grants that can never be used.
fn ensure_non_zero_account(account: AccountId) -> Result<(), AccessControlError> {
    if account == AccountId::from([0u8; 32]) {
        return Err(AccessControlError::ZeroAccount);
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Implementation
// ─────────────────────────────────────────────────────────────────────────────

impl AccessControl {
    /// Create a new `AccessControl` instance.
    ///
    /// # Issue #1254 — Input validation
    /// `cache_ttl_blocks` must be at least 1.  A TTL of 0 would make every
    /// permission lookup bypass the cache immediately.
    pub fn new(cache_ttl_blocks: u32) -> Result<Self, AccessControlError> {
        if cache_ttl_blocks == 0 {
            return Err(AccessControlError::InvalidCacheTtl);
        }
        Ok(Self {
            role_assignments: Mapping::default(),
            role_permissions: Mapping::default(),
            account_permissions: Mapping::default(),
            permission_cache: Mapping::default(),
            audit_log: Mapping::default(),
            audit_count: 0,
            cache_epoch: 0,
            cache_ttl_blocks,
            pending_rotations: Mapping::default(),
            rotation_nonce: Mapping::default(),
            role_admin: Mapping::default(),
        })
    }

    /// Bootstrap the access-control system by granting `SuperAdmin` and `Admin`
    /// to the given account.  Typically called once during contract construction.
    ///
    /// # Issue #1254 — Input validation
    /// Rejects the zero address.
    pub fn bootstrap(
        &mut self,
        admin: AccountId,
        block_number: u32,
        timestamp: u64,
    ) -> Result<(), AccessControlError> {
        ensure_non_zero_account(admin)?;
        self.role_assignments
            .insert((admin, Role::SuperAdmin), &true);
        self.role_assignments.insert((admin, Role::Admin), &true);
        self.write_audit(
            admin,
            admin,
            AuditAction::RoleGranted,
            Some(Role::SuperAdmin),
            None,
            block_number,
            timestamp,
        );
        self.write_audit(
            admin,
            admin,
            AuditAction::RoleGranted,
            Some(Role::Admin),
            None,
            block_number,
            timestamp,
        );
        Ok(())
    }

    // ── Issue #1256 — Role-admin management ──────────────────────────────────

    /// Return the admin role for `role`.
    ///
    /// Defaults to `Role::Admin` when no explicit override has been set,
    /// matching the OpenZeppelin convention.
    pub fn get_role_admin(&self, role: Role) -> Role {
        let idx = role.to_index();
        self.role_admin
            .get(idx)
            .and_then(Role::from_index)
            .unwrap_or(Role::Admin)
    }

    /// Change the admin role for `role`.
    ///
    /// Only the current admin of `role` (or `SuperAdmin`) may perform this.
    /// Emits [`RoleAdminChanged`].
    ///
    /// # Issue #1254 — Input validation
    /// `actor` must not be the zero address.
    pub fn set_role_admin(
        &mut self,
        actor: AccountId,
        role: Role,
        new_admin: Role,
        block_number: u32,
        timestamp: u64,
    ) -> Result<(), AccessControlError> {
        ensure_non_zero_account(actor)?;
        // Must hold the current admin role (or SuperAdmin).
        let current_admin = self.get_role_admin(role);
        if !self.has_role(actor, current_admin) && !self.has_role(actor, Role::SuperAdmin) {
            return Err(AccessControlError::Unauthorized);
        }
        let previous_admin = self.get_role_admin(role);
        self.role_admin.insert(role.to_index(), &new_admin.to_index());
        self.invalidate_cache();
        self.write_audit(
            actor,
            actor,
            AuditAction::RoleAdminChanged,
            Some(role),
            None,
            block_number,
            timestamp,
        );
        // Emit the standalone event (Issue #1253).
        ink::env::emit_event::<ink::env::DefaultEnvironment, _>(RoleAdminChanged {
            role,
            previous_admin,
            new_admin,
        });
        Ok(())
    }

    // ── Role grants / revocations ─────────────────────────────────────────────

    /// Grant `role` to `target`.
    ///
    /// The caller must hold the **admin role** for `role` (Issue #1256).
    /// Emits [`RoleGranted`] (Issue #1253).
    ///
    /// # Issue #1254 — Input validation
    /// Both `actor` and `target` must be non-zero accounts.
    pub fn grant_role(
        &mut self,
        actor: AccountId,
        target: AccountId,
        role: Role,
        block_number: u32,
        timestamp: u64,
    ) -> Result<(), AccessControlError> {
        ensure_non_zero_account(actor)?;
        ensure_non_zero_account(target)?;
        // Issue #1256: check the role's designated admin, not always Role::Admin.
        let required_admin = self.get_role_admin(role);
        self.ensure_has_role(actor, required_admin)?;
        self.role_assignments.insert((target, role), &true);
        self.invalidate_cache();
        self.write_audit(
            actor,
            target,
            AuditAction::RoleGranted,
            Some(role),
            None,
            block_number,
            timestamp,
        );
        // Issue #1253: emit event.
        ink::env::emit_event::<ink::env::DefaultEnvironment, _>(RoleGranted {
            actor,
            target,
            role,
        });
        Ok(())
    }

    /// Revoke `role` from `target`.
    ///
    /// The caller must hold the **admin role** for `role` (Issue #1256).
    /// Emits [`RoleRevoked`] (Issue #1253).
    ///
    /// # Issue #1254 — Input validation
    /// Both `actor` and `target` must be non-zero accounts.
    pub fn revoke_role(
        &mut self,
        actor: AccountId,
        target: AccountId,
        role: Role,
        block_number: u32,
        timestamp: u64,
    ) -> Result<(), AccessControlError> {
        ensure_non_zero_account(actor)?;
        ensure_non_zero_account(target)?;
        let required_admin = self.get_role_admin(role);
        self.ensure_has_role(actor, required_admin)?;
        self.role_assignments.remove((target, role));
        self.invalidate_cache();
        self.write_audit(
            actor,
            target,
            AuditAction::RoleRevoked,
            Some(role),
            None,
            block_number,
            timestamp,
        );
        // Issue #1253: emit event.
        ink::env::emit_event::<ink::env::DefaultEnvironment, _>(RoleRevoked {
            actor,
            target,
            role,
        });
        Ok(())
    }

    // ── Permission grants / revocations ──────────────────────────────────────

    /// Grant `permission` to all accounts that hold `role`.
    ///
    /// Requires `Role::Admin`.
    /// Emits [`RolePermissionGranted`] (Issue #1253).
    ///
    /// # Issue #1254 — Input validation
    /// `actor` must be non-zero.
    pub fn grant_permission_to_role(
        &mut self,
        actor: AccountId,
        role: Role,
        permission: Permission,
        block_number: u32,
        timestamp: u64,
    ) -> Result<(), AccessControlError> {
        ensure_non_zero_account(actor)?;
        self.ensure_has_role(actor, Role::Admin)?;
        self.role_permissions.insert((role, permission), &true);
        self.invalidate_cache();
        self.write_audit(
            actor,
            actor,
            AuditAction::PermissionGrantedToRole,
            Some(role),
            Some(permission),
            block_number,
            timestamp,
        );
        // Issue #1253: emit event.
        ink::env::emit_event::<ink::env::DefaultEnvironment, _>(RolePermissionGranted {
            actor,
            role,
            permission,
        });
        Ok(())
    }

    /// Revoke `permission` from all accounts that hold `role`.
    ///
    /// Requires `Role::Admin`.
    /// Emits [`RolePermissionRevoked`] (Issue #1253).
    ///
    /// # Issue #1254 — Input validation
    /// `actor` must be non-zero.
    pub fn revoke_permission_from_role(
        &mut self,
        actor: AccountId,
        role: Role,
        permission: Permission,
        block_number: u32,
        timestamp: u64,
    ) -> Result<(), AccessControlError> {
        ensure_non_zero_account(actor)?;
        self.ensure_has_role(actor, Role::Admin)?;
        self.role_permissions.remove((role, permission));
        self.invalidate_cache();
        self.write_audit(
            actor,
            actor,
            AuditAction::PermissionRevokedFromRole,
            Some(role),
            Some(permission),
            block_number,
            timestamp,
        );
        // Issue #1253: emit event.
        ink::env::emit_event::<ink::env::DefaultEnvironment, _>(RolePermissionRevoked {
            actor,
            role,
            permission,
        });
        Ok(())
    }

    /// Grant `permission` directly to `target` (bypasses role-based lookup).
    ///
    /// Requires `Role::Admin`.
    /// Emits [`AccountPermissionGranted`] (Issue #1253).
    ///
    /// # Issue #1254 — Input validation
    /// Both `actor` and `target` must be non-zero.
    pub fn grant_permission_to_account(
        &mut self,
        actor: AccountId,
        target: AccountId,
        permission: Permission,
        block_number: u32,
        timestamp: u64,
    ) -> Result<(), AccessControlError> {
        ensure_non_zero_account(actor)?;
        ensure_non_zero_account(target)?;
        self.ensure_has_role(actor, Role::Admin)?;
        self.account_permissions.insert((target, permission), &true);
        self.invalidate_cache();
        self.write_audit(
            actor,
            target,
            AuditAction::PermissionGrantedToAccount,
            None,
            Some(permission),
            block_number,
            timestamp,
        );
        // Issue #1253: emit event.
        ink::env::emit_event::<ink::env::DefaultEnvironment, _>(AccountPermissionGranted {
            actor,
            target,
            permission,
        });
        Ok(())
    }

    /// Revoke a directly-granted `permission` from `target`.
    ///
    /// Requires `Role::Admin`.
    /// Emits [`AccountPermissionRevoked`] (Issue #1253).
    ///
    /// # Issue #1254 — Input validation
    /// Both `actor` and `target` must be non-zero.
    pub fn revoke_permission_from_account(
        &mut self,
        actor: AccountId,
        target: AccountId,
        permission: Permission,
        block_number: u32,
        timestamp: u64,
    ) -> Result<(), AccessControlError> {
        ensure_non_zero_account(actor)?;
        ensure_non_zero_account(target)?;
        self.ensure_has_role(actor, Role::Admin)?;
        self.account_permissions.remove((target, permission));
        self.invalidate_cache();
        self.write_audit(
            actor,
            target,
            AuditAction::PermissionRevokedFromAccount,
            None,
            Some(permission),
            block_number,
            timestamp,
        );
        // Issue #1253: emit event.
        ink::env::emit_event::<ink::env::DefaultEnvironment, _>(AccountPermissionRevoked {
            actor,
            target,
            permission,
        });
        Ok(())
    }

    // ── Role / permission queries ─────────────────────────────────────────────

    /// Return `true` if `account` holds `role` directly or through inheritance.
    pub fn has_role(&self, account: AccountId, role: Role) -> bool {
        self.role_assignments.get((account, role)).unwrap_or(false)
            || self.ancestor_roles(role).iter().any(|ancestor| {
                self.role_assignments
                    .get((account, *ancestor))
                    .unwrap_or(false)
            })
    }

    /// Return `Ok(())` iff `account` holds `role`, otherwise
    /// `Err(AccessControlError::Unauthorized)`.
    pub fn ensure_has_role(
        &self,
        account: AccountId,
        role: Role,
    ) -> Result<(), AccessControlError> {
        if self.has_role(account, role) {
            Ok(())
        } else {
            Err(AccessControlError::Unauthorized)
        }
    }

    /// Return `true` if `account` has `permission`, either directly or via a role.
    pub fn has_permission(&self, account: AccountId, permission: Permission) -> bool {
        if self
            .account_permissions
            .get((account, permission))
            .unwrap_or(false)
        {
            return true;
        }
        self.all_roles()
            .iter()
            .filter(|role| self.has_role(account, **role))
            .any(|role| {
                self.role_permissions
                    .get((*role, permission))
                    .unwrap_or(false)
            })
    }

    /// Cache-aware version of `has_permission`.
    pub fn has_permission_cached(
        &mut self,
        account: AccountId,
        permission: Permission,
        current_block: u32,
    ) -> bool {
        if let Some(cached) = self
            .permission_cache
            .get((account, permission, self.cache_epoch))
        {
            return cached;
        }
        let value = self.has_permission(account, permission);
        self.permission_cache
            .insert((account, permission, self.cache_epoch), &value);
        let _ = current_block.saturating_add(self.cache_ttl_blocks);
        value
    }

    // ── Audit log ─────────────────────────────────────────────────────────────

    pub fn get_audit_entry(&self, id: u64) -> Option<PermissionAuditEntry> {
        self.audit_log.get(id)
    }

    pub fn audit_count(&self) -> u64 {
        self.audit_count
    }

    // ── Key rotation ─────────────────────────────────────────────────────────

    /// Request a key rotation.
    ///
    /// The rotation enters a cooldown period before it can be confirmed.
    /// Emits [`KeyRotationRequested`] (Issue #1253).
    ///
    /// # Issue #1254 — Input validation
    /// - `actor` must not be the zero address.
    /// - `new_account` must not be the zero address.
    /// - `new_account` must differ from `actor`.
    pub fn request_key_rotation(
        &mut self,
        actor: AccountId,
        new_account: AccountId,
        block_number: u32,
        timestamp: u64,
    ) -> Result<(), AccessControlError> {
        ensure_non_zero_account(actor)?;
        ensure_non_zero_account(new_account)?;
        if actor == new_account {
            return Err(AccessControlError::SameAccount);
        }
        if self.pending_rotations.contains(actor) {
            return Err(AccessControlError::KeyRotationCooldown);
        }

        let effective_at =
            block_number.saturating_add(crate::constants::KEY_ROTATION_COOLDOWN_BLOCKS);

        let request = crate::crypto::KeyRotationRequest {
            old_account: actor,
            new_account,
            requested_at: block_number,
            effective_at,
            confirmed: false,
        };

        self.pending_rotations.insert(actor, &request);

        let nonce = self.rotation_nonce.get(actor).unwrap_or(0);
        self.rotation_nonce.insert(actor, &nonce.saturating_add(1));

        self.write_audit(
            actor,
            new_account,
            AuditAction::KeyRotationRequested,
            None,
            None,
            block_number,
            timestamp,
        );
        // Issue #1253: emit event.
        ink::env::emit_event::<ink::env::DefaultEnvironment, _>(KeyRotationRequested {
            old_account: actor,
            new_account,
            effective_at,
        });
        Ok(())
    }

    /// Confirm a pending key rotation.
    ///
    /// Must be called by the new account after the cooldown period has elapsed.
    /// Transfers all roles from the old account to the new account.
    /// Emits [`KeyRotationCompleted`] (Issue #1253).
    ///
    /// # Issue #1254 — Input validation
    /// `caller` must not be the zero address.
    pub fn confirm_key_rotation(
        &mut self,
        old_account: AccountId,
        caller: AccountId,
        block_number: u32,
        timestamp: u64,
    ) -> Result<(), AccessControlError> {
        ensure_non_zero_account(old_account)?;
        ensure_non_zero_account(caller)?;
        let request = self
            .pending_rotations
            .get(old_account)
            .ok_or(AccessControlError::NoPendingRotation)?;

        if request.new_account != caller {
            return Err(AccessControlError::RotationUnauthorized);
        }

        if block_number < request.effective_at {
            return Err(AccessControlError::KeyRotationCooldown);
        }

        let expiry = request
            .effective_at
            .saturating_add(crate::constants::KEY_ROTATION_EXPIRY_BLOCKS);
        if block_number > expiry {
            self.pending_rotations.remove(old_account);
            return Err(AccessControlError::KeyRotationExpired);
        }

        for role in self.all_roles() {
            if self
                .role_assignments
                .get((old_account, role))
                .unwrap_or(false)
            {
                self.role_assignments.remove((old_account, role));
                self.role_assignments
                    .insert((request.new_account, role), &true);
            }
        }

        self.pending_rotations.remove(old_account);
        self.invalidate_cache();

        self.write_audit(
            caller,
            old_account,
            AuditAction::KeyRotationCompleted,
            None,
            None,
            block_number,
            timestamp,
        );
        // Issue #1253: emit event.
        ink::env::emit_event::<ink::env::DefaultEnvironment, _>(KeyRotationCompleted {
            old_account,
            new_account: caller,
        });
        Ok(())
    }

    /// Cancel a pending key rotation.
    ///
    /// Either the old or the new account may cancel.
    /// Emits [`KeyRotationCancelled`] (Issue #1253).
    ///
    /// # Issue #1254 — Input validation
    /// Both `old_account` and `caller` must be non-zero.
    pub fn cancel_key_rotation(
        &mut self,
        old_account: AccountId,
        caller: AccountId,
        block_number: u32,
        timestamp: u64,
    ) -> Result<(), AccessControlError> {
        ensure_non_zero_account(old_account)?;
        ensure_non_zero_account(caller)?;
        let request = self
            .pending_rotations
            .get(old_account)
            .ok_or(AccessControlError::NoPendingRotation)?;

        if caller != request.old_account && caller != request.new_account {
            return Err(AccessControlError::RotationUnauthorized);
        }

        self.pending_rotations.remove(old_account);

        self.write_audit(
            caller,
            old_account,
            AuditAction::KeyRotationCancelled,
            None,
            None,
            block_number,
            timestamp,
        );
        // Issue #1253: emit event.
        ink::env::emit_event::<ink::env::DefaultEnvironment, _>(KeyRotationCancelled {
            old_account,
            cancelled_by: caller,
        });
        Ok(())
    }

    /// Return the pending key rotation for `account`, if any.
    pub fn get_pending_rotation(
        &self,
        account: AccountId,
    ) -> Option<crate::crypto::KeyRotationRequest> {
        self.pending_rotations.get(account)
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn invalidate_cache(&mut self) {
        self.cache_epoch = self.cache_epoch.saturating_add(1);
    }

    /// Return the set of roles that are considered "ancestors" of `role` for
    /// the purpose of permission inheritance.
    fn ancestor_roles(&self, role: Role) -> Vec<Role> {
        match role {
            Role::SuperAdmin => Vec::new(),
            Role::Admin => vec![Role::SuperAdmin],
            Role::OracleAdmin => vec![Role::Admin, Role::SuperAdmin],
            Role::ComplianceAdmin => vec![Role::Admin, Role::SuperAdmin],
            Role::FeeAdmin => vec![Role::Admin, Role::SuperAdmin],
            Role::BridgeOperator => vec![Role::Admin, Role::SuperAdmin],
            Role::Verifier => vec![Role::Admin, Role::SuperAdmin],
            Role::PauseGuardian => vec![Role::Admin, Role::SuperAdmin],
            Role::Manager => vec![Role::Admin, Role::SuperAdmin],
            Role::EscrowAdmin => vec![Role::Admin, Role::SuperAdmin],
        }
    }

    fn all_roles(&self) -> [Role; 10] {
        [
            Role::SuperAdmin,
            Role::Admin,
            Role::OracleAdmin,
            Role::ComplianceAdmin,
            Role::FeeAdmin,
            Role::BridgeOperator,
            Role::Verifier,
            Role::PauseGuardian,
            Role::Manager,
            Role::EscrowAdmin,
        ]
    }

    #[allow(clippy::too_many_arguments)]
    fn write_audit(
        &mut self,
        actor: AccountId,
        target: AccountId,
        action: AuditAction,
        role: Option<Role>,
        permission: Option<Permission>,
        block_number: u32,
        timestamp: u64,
    ) {
        self.audit_count = self.audit_count.saturating_add(1);
        let entry = PermissionAuditEntry {
            id: self.audit_count,
            actor,
            target,
            action,
            role,
            permission,
            block_number,
            timestamp,
        };
        self.audit_log.insert(self.audit_count, &entry);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_account(seed: u8) -> AccountId {
        AccountId::from([seed; 32])
    }

    fn zero_account() -> AccountId {
        AccountId::from([0u8; 32])
    }

    fn make_ac() -> AccessControl {
        AccessControl::new(10).expect("TTL must be valid")
    }

    // ── Issue #1255: custom error variants ───────────────────────────────────

    #[ink::test]
    fn new_with_zero_ttl_returns_error() {
        assert_eq!(
            AccessControl::new(0),
            Err(AccessControlError::InvalidCacheTtl)
        );
    }

    #[ink::test]
    fn new_with_valid_ttl_succeeds() {
        assert!(AccessControl::new(1).is_ok());
    }

    // ── Issue #1254: input validation ────────────────────────────────────────

    #[ink::test]
    fn bootstrap_rejects_zero_address() {
        let mut ac = make_ac();
        assert_eq!(
            ac.bootstrap(zero_account(), 1, 0),
            Err(AccessControlError::ZeroAccount)
        );
    }

    #[ink::test]
    fn grant_role_rejects_zero_actor() {
        let mut ac = make_ac();
        let admin = make_account(1);
        ac.bootstrap(admin, 1, 0).unwrap();
        assert_eq!(
            ac.grant_role(zero_account(), make_account(2), Role::Verifier, 2, 0),
            Err(AccessControlError::ZeroAccount)
        );
    }

    #[ink::test]
    fn grant_role_rejects_zero_target() {
        let mut ac = make_ac();
        let admin = make_account(1);
        ac.bootstrap(admin, 1, 0).unwrap();
        assert_eq!(
            ac.grant_role(admin, zero_account(), Role::Verifier, 2, 0),
            Err(AccessControlError::ZeroAccount)
        );
    }

    #[ink::test]
    fn revoke_role_rejects_zero_actor() {
        let mut ac = make_ac();
        let admin = make_account(1);
        ac.bootstrap(admin, 1, 0).unwrap();
        assert_eq!(
            ac.revoke_role(zero_account(), make_account(2), Role::Verifier, 2, 0),
            Err(AccessControlError::ZeroAccount)
        );
    }

    #[ink::test]
    fn revoke_role_rejects_zero_target() {
        let mut ac = make_ac();
        let admin = make_account(1);
        ac.bootstrap(admin, 1, 0).unwrap();
        assert_eq!(
            ac.revoke_role(admin, zero_account(), Role::Verifier, 2, 0),
            Err(AccessControlError::ZeroAccount)
        );
    }

    #[ink::test]
    fn grant_permission_to_account_rejects_zero_target() {
        let mut ac = make_ac();
        let admin = make_account(1);
        ac.bootstrap(admin, 1, 0).unwrap();
        let perm = Permission {
            resource: Resource::Global,
            action: Action::Configure,
        };
        assert_eq!(
            ac.grant_permission_to_account(admin, zero_account(), perm, 2, 0),
            Err(AccessControlError::ZeroAccount)
        );
    }

    #[ink::test]
    fn request_key_rotation_rejects_zero_new_account() {
        let mut ac = make_ac();
        let admin = make_account(1);
        ac.bootstrap(admin, 1, 0).unwrap();
        assert_eq!(
            ac.request_key_rotation(admin, zero_account(), 2, 0),
            Err(AccessControlError::ZeroAccount)
        );
    }

    #[ink::test]
    fn request_key_rotation_rejects_same_account() {
        let mut ac = make_ac();
        let admin = make_account(1);
        ac.bootstrap(admin, 1, 0).unwrap();
        assert_eq!(
            ac.request_key_rotation(admin, admin, 2, 0),
            Err(AccessControlError::SameAccount)
        );
    }

    // ── Core access-control logic ─────────────────────────────────────────────

    #[ink::test]
    fn bootstrap_grants_super_admin_and_admin() {
        let mut ac = make_ac();
        let admin = make_account(1);
        ac.bootstrap(admin, 1, 0).unwrap();
        assert!(ac.has_role(admin, Role::SuperAdmin));
        assert!(ac.has_role(admin, Role::Admin));
    }

    #[ink::test]
    fn grant_and_has_role() {
        let mut ac = make_ac();
        let admin = make_account(1);
        let user = make_account(2);
        ac.bootstrap(admin, 1, 0).unwrap();
        ac.grant_role(admin, user, Role::Verifier, 2, 0).unwrap();
        assert!(ac.has_role(user, Role::Verifier));
    }

    #[ink::test]
    fn revoke_role_removes_role() {
        let mut ac = make_ac();
        let admin = make_account(1);
        let user = make_account(2);
        ac.bootstrap(admin, 1, 0).unwrap();
        ac.grant_role(admin, user, Role::Verifier, 2, 0).unwrap();
        ac.revoke_role(admin, user, Role::Verifier, 3, 0).unwrap();
        assert!(!ac.has_role(user, Role::Verifier));
    }

    #[ink::test]
    fn non_admin_cannot_grant_role() {
        let mut ac = make_ac();
        let admin = make_account(1);
        let attacker = make_account(2);
        let victim = make_account(3);
        ac.bootstrap(admin, 1, 0).unwrap();
        assert_eq!(
            ac.grant_role(attacker, victim, Role::Verifier, 2, 0),
            Err(AccessControlError::Unauthorized)
        );
    }

    // ── Issue #1256: OpenZeppelin role-admin primitives ───────────────────────

    #[ink::test]
    fn default_role_admin_is_admin() {
        let ac = make_ac();
        assert_eq!(ac.get_role_admin(Role::Verifier), Role::Admin);
    }

    #[ink::test]
    fn super_admin_can_change_role_admin() {
        let mut ac = make_ac();
        let admin = make_account(1);
        ac.bootstrap(admin, 1, 0).unwrap();
        ac.set_role_admin(admin, Role::Verifier, Role::Manager, 2, 0)
            .unwrap();
        assert_eq!(ac.get_role_admin(Role::Verifier), Role::Manager);
    }

    #[ink::test]
    fn only_role_admin_can_grant_that_role() {
        let mut ac = make_ac();
        let super_admin = make_account(1);
        let manager = make_account(2);
        let verifier_candidate = make_account(3);
        let plain_admin = make_account(4);

        ac.bootstrap(super_admin, 1, 0).unwrap();

        // Grant Manager role to `manager`
        ac.grant_role(super_admin, manager, Role::Manager, 2, 0)
            .unwrap();

        // Change Verifier's admin to Manager
        ac.set_role_admin(super_admin, Role::Verifier, Role::Manager, 3, 0)
            .unwrap();

        // plain_admin has Role::Admin, but not Role::Manager, so cannot grant Verifier
        ac.grant_role(super_admin, plain_admin, Role::Admin, 4, 0)
            .unwrap();
        assert_eq!(
            ac.grant_role(plain_admin, verifier_candidate, Role::Verifier, 5, 0),
            Err(AccessControlError::Unauthorized)
        );

        // manager holds Role::Manager so CAN grant Verifier
        ac.grant_role(manager, verifier_candidate, Role::Verifier, 5, 0)
            .unwrap();
        assert!(ac.has_role(verifier_candidate, Role::Verifier));
    }

    #[ink::test]
    fn non_admin_cannot_change_role_admin() {
        let mut ac = make_ac();
        let admin = make_account(1);
        let attacker = make_account(2);
        ac.bootstrap(admin, 1, 0).unwrap();
        assert_eq!(
            ac.set_role_admin(attacker, Role::Verifier, Role::Manager, 2, 0),
            Err(AccessControlError::Unauthorized)
        );
    }

    // ── Permission tests ──────────────────────────────────────────────────────

    #[ink::test]
    fn role_permission_round_trip() {
        let mut ac = make_ac();
        let admin = make_account(1);
        let user = make_account(2);
        ac.bootstrap(admin, 1, 0).unwrap();
        ac.grant_role(admin, user, Role::Verifier, 2, 0).unwrap();
        let perm = Permission {
            resource: Resource::PropertyRegistry,
            action: Action::Verify,
        };
        ac.grant_permission_to_role(admin, Role::Verifier, perm, 3, 0)
            .unwrap();
        assert!(ac.has_permission(user, perm));
    }

    #[ink::test]
    fn revoke_permission_from_role_removes_access() {
        let mut ac = make_ac();
        let admin = make_account(1);
        let user = make_account(2);
        ac.bootstrap(admin, 1, 0).unwrap();
        ac.grant_role(admin, user, Role::Verifier, 2, 0).unwrap();
        let perm = Permission {
            resource: Resource::PropertyRegistry,
            action: Action::Verify,
        };
        ac.grant_permission_to_role(admin, Role::Verifier, perm, 3, 0)
            .unwrap();
        ac.revoke_permission_from_role(admin, Role::Verifier, perm, 4, 0)
            .unwrap();
        assert!(!ac.has_permission(user, perm));
    }

    #[ink::test]
    fn direct_account_permission_grant_and_revoke() {
        let mut ac = make_ac();
        let admin = make_account(1);
        let user = make_account(2);
        ac.bootstrap(admin, 1, 0).unwrap();
        let perm = Permission {
            resource: Resource::Oracle,
            action: Action::Update,
        };
        ac.grant_permission_to_account(admin, user, perm, 2, 0)
            .unwrap();
        assert!(ac.has_permission(user, perm));
        ac.revoke_permission_from_account(admin, user, perm, 3, 0)
            .unwrap();
        assert!(!ac.has_permission(user, perm));
    }

    // ── Audit log ─────────────────────────────────────────────────────────────

    #[ink::test]
    fn audit_log_grows_on_operations() {
        let mut ac = make_ac();
        let admin = make_account(1);
        ac.bootstrap(admin, 1, 0).unwrap();
        let before = ac.audit_count();
        ac.grant_role(admin, make_account(2), Role::Verifier, 2, 0)
            .unwrap();
        assert_eq!(ac.audit_count(), before + 1);
    }

    // ── Key rotation ──────────────────────────────────────────────────────────

    #[ink::test]
    fn key_rotation_full_lifecycle() {
        let mut ac = make_ac();
        let old = make_account(1);
        let new = make_account(2);
        ac.bootstrap(old, 1, 0).unwrap();

        let cooldown = crate::constants::KEY_ROTATION_COOLDOWN_BLOCKS;
        ac.request_key_rotation(old, new, 10, 0).unwrap();

        // Confirm after cooldown.
        let confirm_block = 10 + cooldown + 1;
        ac.confirm_key_rotation(old, new, confirm_block, 0).unwrap();

        // Roles transferred.
        assert!(ac.has_role(new, Role::SuperAdmin));
        assert!(!ac.has_role(old, Role::SuperAdmin));
    }

    #[ink::test]
    fn key_rotation_cancel() {
        let mut ac = make_ac();
        let old = make_account(1);
        let new = make_account(2);
        ac.bootstrap(old, 1, 0).unwrap();
        ac.request_key_rotation(old, new, 10, 0).unwrap();
        ac.cancel_key_rotation(old, old, 11, 0).unwrap();
        assert!(ac.get_pending_rotation(old).is_none());
    }

    #[ink::test]
    fn confirm_by_wrong_caller_rejected() {
        let mut ac = make_ac();
        let old = make_account(1);
        let new = make_account(2);
        let attacker = make_account(3);
        ac.bootstrap(old, 1, 0).unwrap();
        let cooldown = crate::constants::KEY_ROTATION_COOLDOWN_BLOCKS;
        ac.request_key_rotation(old, new, 10, 0).unwrap();
        let confirm_block = 10 + cooldown + 1;
        assert_eq!(
            ac.confirm_key_rotation(old, attacker, confirm_block, 0),
            Err(AccessControlError::RotationUnauthorized)
        );
    }

    #[ink::test]
    fn duplicate_rotation_request_rejected() {
        let mut ac = make_ac();
        let old = make_account(1);
        let new = make_account(2);
        ac.bootstrap(old, 1, 0).unwrap();
        ac.request_key_rotation(old, new, 10, 0).unwrap();
        assert_eq!(
            ac.request_key_rotation(old, new, 11, 0),
            Err(AccessControlError::KeyRotationCooldown)
        );
    }
}
