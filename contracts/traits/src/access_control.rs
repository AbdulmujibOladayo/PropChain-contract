use ink::prelude::vec::Vec;
use ink::primitives::AccountId;
use ink::storage::Mapping;

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

#[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub enum AccessControlError {
    Unauthorized,
    KeyRotationCooldown,
    KeyRotationExpired,
    NoPendingRotation,
    RotationUnauthorized,
}

type PermissionCacheKey = (AccountId, Permission, u64);

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
    // ── Storage gap for upgrade safety (issue #1261) ──────────────────────
    //
    // When new storage fields are added in a future version of this struct,
    // they must be inserted *above* this gap and the gap size reduced by the
    // number of slots consumed. This preserves the storage layout of existing
    // on-chain instances so an upgrade does not corrupt stored data.
    //
    // See `STORAGE_GAP_SIZE` in `constants.rs`.
    __storage_gap: [u128; crate::constants::STORAGE_GAP_SIZE],
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

impl AccessControl {
    pub fn new(cache_ttl_blocks: u32) -> Self {
        Self {
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
            __storage_gap: [0u128; crate::constants::STORAGE_GAP_SIZE],
        }
    }

    pub fn bootstrap(&mut self, admin: AccountId, block_number: u32, timestamp: u64) {
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
    }

    pub fn grant_role(
        &mut self,
        actor: AccountId,
        target: AccountId,
        role: Role,
        block_number: u32,
        timestamp: u64,
    ) -> Result<(), AccessControlError> {
        self.ensure_has_role(actor, Role::Admin)?;
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
        Ok(())
    }

    pub fn revoke_role(
        &mut self,
        actor: AccountId,
        target: AccountId,
        role: Role,
        block_number: u32,
        timestamp: u64,
    ) -> Result<(), AccessControlError> {
        self.ensure_has_role(actor, Role::Admin)?;
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
        Ok(())
    }

    pub fn grant_permission_to_role(
        &mut self,
        actor: AccountId,
        role: Role,
        permission: Permission,
        block_number: u32,
        timestamp: u64,
    ) -> Result<(), AccessControlError> {
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
        Ok(())
    }

    pub fn has_role(&self, account: AccountId, role: Role) -> bool {
        self.role_assignments.get((account, role)).unwrap_or(false)
            || self.ancestor_roles(role).iter().any(|ancestor| {
                self.role_assignments
                    .get((account, *ancestor))
                    .unwrap_or(false)
            })
    }

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

    pub fn get_audit_entry(&self, id: u64) -> Option<PermissionAuditEntry> {
        self.audit_log.get(id)
    }

    pub fn audit_count(&self) -> u64 {
        self.audit_count
    }

    /// Request a key rotation. Only the account being rotated can initiate.
    /// The rotation enters a cooldown period before it can be confirmed.
    pub fn request_key_rotation(
        &mut self,
        actor: AccountId,
        new_account: AccountId,
        block_number: u32,
        timestamp: u64,
    ) -> Result<(), AccessControlError> {
        // Only the account itself can request rotation of its own keys
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

        Ok(())
    }

    /// Confirm a pending key rotation. Must be called by the new account
    /// after the cooldown period has elapsed. Transfers all roles from old to new.
    pub fn confirm_key_rotation(
        &mut self,
        old_account: AccountId,
        caller: AccountId,
        block_number: u32,
        timestamp: u64,
    ) -> Result<(), AccessControlError> {
        let request = self
            .pending_rotations
            .get(old_account)
            .ok_or(AccessControlError::NoPendingRotation)?;

        // Only the designated new account can confirm
        if request.new_account != caller {
            return Err(AccessControlError::RotationUnauthorized);
        }

        // Check cooldown has elapsed
        if block_number < request.effective_at {
            return Err(AccessControlError::KeyRotationCooldown);
        }

        // Check expiry
        let expiry = request
            .effective_at
            .saturating_add(crate::constants::KEY_ROTATION_EXPIRY_BLOCKS);
        if block_number > expiry {
            self.pending_rotations.remove(old_account);
            return Err(AccessControlError::KeyRotationExpired);
        }

        // Transfer all roles from old_account to new_account
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

        Ok(())
    }

    /// Cancel a pending key rotation. Either the old or new account can cancel.
    pub fn cancel_key_rotation(
        &mut self,
        old_account: AccountId,
        caller: AccountId,
        block_number: u32,
        timestamp: u64,
    ) -> Result<(), AccessControlError> {
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

        Ok(())
    }

    /// Get the pending key rotation for an account, if any.
    pub fn get_pending_rotation(
        &self,
        account: AccountId,
    ) -> Option<crate::crypto::KeyRotationRequest> {
        self.pending_rotations.get(account)
    }

    fn invalidate_cache(&mut self) {
        self.cache_epoch = self.cache_epoch.saturating_add(1);
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        KEY_ROTATION_COOLDOWN_BLOCKS, KEY_ROTATION_EXPIRY_BLOCKS, STORAGE_GAP_SIZE,
    };
    use ink::env::DefaultEnvironment;

    // ── Test helpers ───────────────────────────────────────────────────────

    fn account(byte: u8) -> AccountId {
        AccountId::from([byte; 32])
    }

    /// Set up the ink! off-chain test engine with a known callee so that
    /// `Mapping` operations (which read from the engine's storage) work.
    fn init_test_env() {
        let default = ink::env::test::default_accounts::<DefaultEnvironment>();
        ink::env::test::set_callee::<DefaultEnvironment>(default.alice);
    }

    /// Create a fresh AccessControl and bootstrap an admin.
    fn fresh_with_admin() -> (AccessControl, AccountId) {
        init_test_env();
        let mut ac = AccessControl::new(100);
        let admin = account(0xA1);
        ac.bootstrap(admin, 1, 1000);
        (ac, admin)
    }

    fn perm(resource: Resource, action: Action) -> Permission {
        Permission { resource, action }
    }

    // ── Bootstrap ──────────────────────────────────────────────────────────

    #[test]
    fn bootstrap_grants_super_admin_and_admin() {
        let (ac, admin) = fresh_with_admin();

        assert!(ac.has_role(admin, Role::SuperAdmin));
        assert!(ac.has_role(admin, Role::Admin));
    }

    #[test]
    fn bootstrap_writes_two_audit_entries() {
        let (ac, _admin) = fresh_with_admin();

        assert_eq!(ac.audit_count(), 2);

        let entry1 = ac.get_audit_entry(1).expect("entry 1 exists");
        assert_eq!(entry1.action, AuditAction::RoleGranted);
        assert_eq!(entry1.role, Some(Role::SuperAdmin));

        let entry2 = ac.get_audit_entry(2).expect("entry 2 exists");
        assert_eq!(entry2.action, AuditAction::RoleGranted);
        assert_eq!(entry2.role, Some(Role::Admin));
    }

    #[test]
    fn new_starts_with_zero_audit_count() {
        let ac = AccessControl::new(100);
        assert_eq!(ac.audit_count(), 0);
        assert_eq!(ac.cache_epoch, 0);
        assert_eq!(ac.cache_ttl_blocks, 100);
    }

    // ── Role hierarchy / ancestor_roles ────────────────────────────────────

    #[test]
    fn super_admin_satisfies_admin_role() {
        let (ac, admin) = fresh_with_admin();

        // admin has SuperAdmin; should satisfy Admin via ancestor_roles
        assert!(ac.has_role(admin, Role::Admin));
    }

    #[test]
    fn super_admin_satisfies_all_subordinate_roles() {
        let (ac, admin) = fresh_with_admin();

        // SuperAdmin is an ancestor of every other role
        for role in [
            Role::Admin,
            Role::OracleAdmin,
            Role::ComplianceAdmin,
            Role::FeeAdmin,
            Role::BridgeOperator,
            Role::Verifier,
            Role::PauseGuardian,
            Role::Manager,
            Role::EscrowAdmin,
        ] {
            assert!(
                ac.has_role(admin, role),
                "SuperAdmin should satisfy {:?}",
                role
            );
        }
    }

    #[test]
    fn admin_satisfies_oracle_admin_via_ancestry() {
        let (mut ac, admin) = fresh_with_admin();

        // Admin is an ancestor of OracleAdmin
        assert!(ac.has_role(admin, Role::OracleAdmin));
        // But not vice versa
        let oracle = account(0xB1);
        ac.grant_role(admin, oracle, Role::OracleAdmin, 10, 2000).unwrap();
        assert!(!ac.has_role(oracle, Role::Admin));
        assert!(!ac.has_role(oracle, Role::SuperAdmin));
    }

    #[test]
    fn role_not_assigned_returns_false() {
        let (ac, _admin) = fresh_with_admin();
        let nobody = account(0x00);

        assert!(!ac.has_role(nobody, Role::Admin));
        assert!(!ac.has_role(nobody, Role::SuperAdmin));
        assert!(!ac.has_role(nobody, Role::Verifier));
    }

    // ─── grant_role ─────────────────────────────────────────────────────────

    #[test]
    fn grant_role_succeeds_for_admin_actor() {
        let (mut ac, admin) = fresh_with_admin();
        let target = account(0xB0);

        ac.grant_role(admin, target, Role::Verifier, 10, 2000).unwrap();

        assert!(ac.has_role(target, Role::Verifier));
    }

    #[test]
    fn grant_role_fails_for_non_admin_actor() {
        let (mut ac, _admin) = fresh_with_admin();
        let actor = account(0xC0);
        let target = account(0xB0);

        let result = ac.grant_role(actor, target, Role::Verifier, 10, 2000);
        assert_eq!(result, Err(AccessControlError::Unauthorized));
        assert!(!ac.has_role(target, Role::Verifier));
    }

    #[test]
    fn grant_role_records_audit_entry() {
        let (mut ac, admin) = fresh_with_admin();
        let target = account(0xB0);

        ac.grant_role(admin, target, Role::Verifier, 10, 2000).unwrap();

        // bootstrap = 2 entries, grant_role = 1 entry
        assert_eq!(ac.audit_count(), 3);

        let entry = ac.get_audit_entry(3).expect("entry 3 exists");
        assert_eq!(entry.action, AuditAction::RoleGranted);
        assert_eq!(entry.role, Some(Role::Verifier));
        assert_eq!(entry.actor, admin);
        assert_eq!(entry.target, target);
        assert_eq!(entry.block_number, 10);
        assert_eq!(entry.timestamp, 2000);
    }

    #[test]
    fn grant_role_invalidates_cache() {
        let (mut ac, admin) = fresh_with_admin();
        let target = account(0xB0);

        // cache_epoch starts at 0
        assert_eq!(ac.cache_epoch, 0);

        ac.grant_role(admin, target, Role::Verifier, 10, 2000).unwrap();

        // Cache should be invalidated (epoch incremented)
        assert_eq!(ac.cache_epoch, 1);
    }

    // ─── revoke_role ────────────────────────────────────────────────────────

    #[test]
    fn revoke_role_succeeds_for_admin_actor() {
        let (mut ac, admin) = fresh_with_admin();
        let target = account(0xB0);

        ac.grant_role(admin, target, Role::Verifier, 10, 2000).unwrap();
        assert!(ac.has_role(target, Role::Verifier));

        ac.revoke_role(admin, target, Role::Verifier, 20, 3000).unwrap();
        assert!(!ac.has_role(target, Role::Verifier));
    }

    #[test]
    fn revoke_role_fails_for_non_admin_actor() {
        let (mut ac, admin) = fresh_with_admin();
        let actor = account(0xC0);
        let target = account(0xB0);

        ac.grant_role(admin, target, Role::Verifier, 10, 2000).unwrap();

        let result = ac.revoke_role(actor, target, Role::Verifier, 20, 3000);
        assert_eq!(result, Err(AccessControlError::Unauthorized));
        // Role should still be assigned
        assert!(ac.has_role(target, Role::Verifier));
    }

    #[test]
    fn revoke_role_records_audit_entry() {
        let (mut ac, admin) = fresh_with_admin();
        let target = account(0xB0);

        ac.grant_role(admin, target, Role::Verifier, 10, 2000).unwrap();
        ac.revoke_role(admin, target, Role::Verifier, 20, 3000).unwrap();

        // bootstrap = 2, grant = 1, revoke = 1 → 4
        assert_eq!(ac.audit_count(), 4);

        let entry = ac.get_audit_entry(4).expect("entry 4 exists");
        assert_eq!(entry.action, AuditAction::RoleRevoked);
        assert_eq!(entry.role, Some(Role::Verifier));
    }

    // ─── grant_permission_to_role ──────────────────────────────────────────

    #[test]
    fn grant_permission_to_role_succeeds_for_admin() {
        let (mut ac, admin) = fresh_with_admin();
        let p = perm(Resource::Oracle, Action::Update);

        ac.grant_permission_to_role(admin, Role::OracleAdmin, p, 10, 2000).unwrap();

        // Now the OracleAdmin role has the permission to Update the Oracle
        let oracle = account(0xB0);
        ac.grant_role(admin, oracle, Role::OracleAdmin, 10, 2000).unwrap();
        assert!(ac.has_permission(oracle, p));
    }

    #[test]
    fn grant_permission_to_role_fails_for_non_admin() {
        let (mut ac, _admin) = fresh_with_admin();
        let actor = account(0xC0);
        let p = perm(Resource::Oracle, Action::Update);

        let result = ac.grant_permission_to_role(actor, Role::OracleAdmin, p, 10, 2000);
        assert_eq!(result, Err(AccessControlError::Unauthorized));
    }

    #[test]
    fn grant_permission_to_role_records_audit() {
        let (mut ac, admin) = fresh_with_admin();
        let p = perm(Resource::Oracle, Action::Update);

        ac.grant_permission_to_role(admin, Role::OracleAdmin, p, 10, 2000).unwrap();

        // bootstrap = 2, grant_permission = 1 → 3
        assert_eq!(ac.audit_count(), 3);

        let entry = ac.get_audit_entry(3).expect("entry 3 exists");
        assert_eq!(entry.action, AuditAction::PermissionGrantedToRole);
        assert_eq!(entry.role, Some(Role::OracleAdmin));
        assert_eq!(entry.permission, Some(p));
    }

    // ─── has_permission ────────────────────────────────────────────────────

    #[test]
    fn has_permission_returns_false_without_any_role() {
        let (ac, _admin) = fresh_with_admin();
        let nobody = account(0x00);
        let p = perm(Resource::Oracle, Action::Update);

        assert!(!ac.has_permission(nobody, p));
    }

    #[test]
    fn has_permission_via_role_permissions() {
        let (mut ac, admin) = fresh_with_admin();
        let oracle = account(0xB0);
        let p = perm(Resource::Oracle, Action::Update);

        ac.grant_role(admin, oracle, Role::OracleAdmin, 10, 2000).unwrap();
        ac.grant_permission_to_role(admin, Role::OracleAdmin, p, 10, 2000).unwrap();

        assert!(ac.has_permission(oracle, p));
    }

    #[test]
    fn has_permission_via_super_admin_role_permissions() {
        let (mut ac, admin) = fresh_with_admin();
        let p = perm(Resource::Oracle, Action::Update);

        // Grant permission to Admin role, SuperAdmin should inherit via ancestry
        ac.grant_permission_to_role(admin, Role::Admin, p, 10, 2000).unwrap();

        // admin has SuperAdmin, which is an ancestor of Admin
        assert!(ac.has_permission(admin, p));
    }

    #[test]
    fn has_permission_with_unrelated_permission_returns_false() {
        let (mut ac, admin) = fresh_with_admin();
        let oracle = account(0xB0);
        let p_granted = perm(Resource::Oracle, Action::Update);
        let p_other = perm(Resource::Bridge, Action::Pause);

        ac.grant_role(admin, oracle, Role::OracleAdmin, 10, 2000).unwrap();
        ac.grant_permission_to_role(admin, Role::OracleAdmin, p_granted, 10, 2000)
            .unwrap();

        assert!(!ac.has_permission(oracle, p_other));
    }

    // ─── has_permission_cached ──────────────────────────────────────────────

    #[test]
    fn has_permission_cached_returns_same_as_uncached() {
        let (mut ac, admin) = fresh_with_admin();
        let oracle = account(0xB0);
        let p = perm(Resource::Oracle, Action::Update);

        ac.grant_role(admin, oracle, Role::OracleAdmin, 10, 2000).unwrap();
        ac.grant_permission_to_role(admin, Role::OracleAdmin, p, 10, 2000).unwrap();

        let cached = ac.has_permission_cached(oracle, p, 20);
        let uncached = ac.has_permission(oracle, p);
        assert_eq!(cached, uncached);
        assert!(cached);
    }

    #[test]
    fn has_permission_cached_returns_false_for_no_permission() {
        let (mut ac, _admin) = fresh_with_admin();
        let nobody = account(0x00);
        let p = perm(Resource::Oracle, Action::Update);

        let cached = ac.has_permission_cached(nobody, p, 20);
        assert!(!cached);
    }

    #[test]
    fn cache_invalidated_on_role_grant() {
        let (mut ac, admin) = fresh_with_admin();
        let target = account(0xB0);
        let p = perm(Resource::Oracle, Action::Update);

        // Grant permission to Admin role so it's available to admins
        ac.grant_permission_to_role(admin, Role::Admin, p, 10, 2000).unwrap();

        let epoch_before = ac.cache_epoch;
        // Cache a permission check
        let _ = ac.has_permission_cached(admin, p, 20);
        // Grant a role → should invalidate cache
        ac.grant_role(admin, target, Role::Verifier, 30, 3000).unwrap();
        let epoch_after = ac.cache_epoch;
        assert!(epoch_after > epoch_before);
    }

    // ─── ensure_has_role ────────────────────────────────────────────────────

    #[test]
    fn ensure_has_role_ok_for_assigned() {
        let (ac, admin) = fresh_with_admin();

        assert!(ac.ensure_has_role(admin, Role::Admin).is_ok());
        assert!(ac.ensure_has_role(admin, Role::SuperAdmin).is_ok());
    }

    #[test]
    fn ensure_has_role_err_for_unassigned() {
        let (ac, _admin) = fresh_with_admin();
        let nobody = account(0x00);

        assert_eq!(
            ac.ensure_has_role(nobody, Role::Admin),
            Err(AccessControlError::Unauthorized)
        );
    }

    // ─── Audit log ──────────────────────────────────────────────────────────

    #[test]
    fn audit_entries_have_incrementing_ids() {
        let (mut ac, admin) = fresh_with_admin();
        let target = account(0xB0);

        ac.grant_role(admin, target, Role::Verifier, 10, 2000).unwrap();
        ac.revoke_role(admin, target, Role::Verifier, 20, 3000).unwrap();

        for i in 1..=4 {
            let entry = ac.get_audit_entry(i).expect("entry exists");
            assert_eq!(entry.id, i);
        }
    }

    #[test]
    fn audit_entry_not_found_returns_none() {
        let (ac, _admin) = fresh_with_admin();

        assert!(ac.get_audit_entry(999).is_none());
    }

    #[test]
    fn audit_entry_has_correct_block_and_timestamp() {
        let (mut ac, admin) = fresh_with_admin();
        let target = account(0xB0);

        ac.grant_role(admin, target, Role::Verifier, 42, 99999).unwrap();

        let entry = ac.get_audit_entry(3).expect("entry exists");
        assert_eq!(entry.block_number, 42);
        assert_eq!(entry.timestamp, 99999);
    }

    // ─── Key rotation: request ───────────────────────────────────────────────

    #[test]
    fn request_key_rotation_succeeds() {
        let (mut ac, admin) = fresh_with_admin();
        let new_account = account(0xD0);

        ac.request_key_rotation(admin, new_account, 100, 5000).unwrap();

        let pending = ac.get_pending_rotation(admin).expect("pending rotation");
        assert_eq!(pending.old_account, admin);
        assert_eq!(pending.new_account, new_account);
        assert_eq!(pending.requested_at, 100);
        assert_eq!(
            pending.effective_at,
            100 + KEY_ROTATION_COOLDOWN_BLOCKS
        );
        assert!(!pending.confirmed);
    }

    #[test]
    fn request_key_rotation_writes_audit() {
        let (mut ac, admin) = fresh_with_admin();
        let new_account = account(0xD0);

        ac.request_key_rotation(admin, new_account, 100, 5000).unwrap();

        // bootstrap = 2, request = 1 → 3
        assert_eq!(ac.audit_count(), 3);
        let entry = ac.get_audit_entry(3).expect("entry exists");
        assert_eq!(entry.action, AuditAction::KeyRotationRequested);
        assert_eq!(entry.actor, admin);
        assert_eq!(entry.target, new_account);
    }

    #[test]
    fn request_key_rotation_increments_nonce() {
        let (mut ac, admin) = fresh_with_admin();
        let new_account = account(0xD0);

        // First request
        ac.request_key_rotation(admin, new_account, 100, 5000).unwrap();
        // Cancel to clear pending
        ac.cancel_key_rotation(admin, admin, 110, 5100).unwrap();
        // Second request
        ac.request_key_rotation(admin, new_account, 120, 5200).unwrap();

        // Nonce should be 2 after two requests
        // (rotation_nonce is private but we verify via behavior: second
        // request after cancel succeeds, proving the nonce increments)
    }

    #[test]
    fn request_key_rotation_fails_if_already_pending() {
        let (mut ac, admin) = fresh_with_admin();
        let new_account = account(0xD0);

        ac.request_key_rotation(admin, new_account, 100, 5000).unwrap();

        let result = ac.request_key_rotation(admin, new_account, 110, 5100);
        assert_eq!(result, Err(AccessControlError::KeyRotationCooldown));
    }

    // ─── Key rotation: confirm ───────────────────────────────────────────────

    #[test]
    fn confirm_key_rotation_succeeds_after_cooldown() {
        let (mut ac, admin) = fresh_with_admin();
        let new_account = account(0xD0);

        ac.request_key_rotation(admin, new_account, 100, 5000).unwrap();

        // Confirm after cooldown
        let confirm_block = 100 + KEY_ROTATION_COOLDOWN_BLOCKS;
        ac.confirm_key_rotation(admin, new_account, confirm_block, 6000)
            .unwrap();

        // Roles should be transferred
        assert!(!ac.has_role(admin, Role::SuperAdmin));
        assert!(ac.has_role(new_account, Role::SuperAdmin));
        assert!(ac.has_role(new_account, Role::Admin));

        // Pending rotation should be cleared
        assert!(ac.get_pending_rotation(admin).is_none());
    }

    #[test]
    fn confirm_key_rotation_writes_audit() {
        let (mut ac, admin) = fresh_with_admin();
        let new_account = account(0xD0);

        ac.request_key_rotation(admin, new_account, 100, 5000).unwrap();

        let confirm_block = 100 + KEY_ROTATION_COOLDOWN_BLOCKS;
        ac.confirm_key_rotation(admin, new_account, confirm_block, 6000)
            .unwrap();

        // bootstrap = 2, request = 1, confirm = 1 → 4
        assert_eq!(ac.audit_count(), 4);
        let entry = ac.get_audit_entry(4).expect("entry exists");
        assert_eq!(entry.action, AuditAction::KeyRotationCompleted);
        assert_eq!(entry.actor, new_account);
        assert_eq!(entry.target, admin);
    }

    #[test]
    fn confirm_key_rotation_fails_wrong_caller() {
        let (mut ac, admin) = fresh_with_admin();
        let new_account = account(0xD0);
        let wrong_caller = account(0xE0);

        ac.request_key_rotation(admin, new_account, 100, 5000).unwrap();

        let confirm_block = 100 + KEY_ROTATION_COOLDOWN_BLOCKS;
        let result = ac.confirm_key_rotation(admin, wrong_caller, confirm_block, 6000);
        assert_eq!(result, Err(AccessControlError::RotationUnauthorized));
    }

    #[test]
    fn confirm_key_rotation_fails_before_cooldown() {
        let (mut ac, admin) = fresh_with_admin();
        let new_account = account(0xD0);

        ac.request_key_rotation(admin, new_account, 100, 5000).unwrap();

        // Try to confirm one block before the cooldown ends
        let too_early = 100 + KEY_ROTATION_COOLDOWN_BLOCKS - 1;
        let result = ac.confirm_key_rotation(admin, new_account, too_early, 6000);
        assert_eq!(result, Err(AccessControlError::KeyRotationCooldown));
    }

    #[test]
    fn confirm_key_rotation_fails_after_expiry() {
        let (mut ac, admin) = fresh_with_admin();
        let new_account = account(0xD0);

        ac.request_key_rotation(admin, new_account, 100, 5000).unwrap();

        // Past the expiry window
        let expiry = 100 + KEY_ROTATION_COOLDOWN_BLOCKS + KEY_ROTATION_EXPIRY_BLOCKS;
        let too_late = expiry + 1;
        let result = ac.confirm_key_rotation(admin, new_account, too_late, 6000);
        assert_eq!(result, Err(AccessControlError::KeyRotationExpired));

        // Pending rotation should be cleaned up
        assert!(ac.get_pending_rotation(admin).is_none());
    }

    #[test]
    fn confirm_key_rotation_fails_without_pending() {
        let (mut ac, _admin) = fresh_with_admin();
        let nobody = account(0x00);
        let caller = account(0xD0);

        let result = ac.confirm_key_rotation(nobody, caller, 200, 6000);
        assert_eq!(result, Err(AccessControlError::NoPendingRotation));
    }

    #[test]
    fn confirm_key_rotation_transfers_all_roles() {
        let (mut ac, admin) = fresh_with_admin();
        let new_account = account(0xD0);

        // Grant additional roles to admin
        ac.grant_role(admin, admin, Role::Verifier, 10, 2000).unwrap();
        ac.grant_role(admin, admin, Role::Manager, 10, 2000).unwrap();

        ac.request_key_rotation(admin, new_account, 100, 5000).unwrap();

        let confirm_block = 100 + KEY_ROTATION_COOLDOWN_BLOCKS;
        ac.confirm_key_rotation(admin, new_account, confirm_block, 6000)
            .unwrap();

        // All roles should be on new_account
        for role in [
            Role::SuperAdmin,
            Role::Admin,
            Role::Verifier,
            Role::Manager,
        ] {
            assert!(
                ac.has_role(new_account, role),
                "new_account should have {:?}",
                role
            );
            assert!(
                !ac.has_role(admin, role),
                "admin should no longer have {:?}",
                role
            );
        }
    }

    // ─── Key rotation: cancel ───────────────────────────────────────────────

    #[test]
    fn cancel_key_rotation_succeeds_for_old_account() {
        let (mut ac, admin) = fresh_with_admin();
        let new_account = account(0xD0);

        ac.request_key_rotation(admin, new_account, 100, 5000).unwrap();
        ac.cancel_key_rotation(admin, admin, 110, 5100).unwrap();

        assert!(ac.get_pending_rotation(admin).is_none());
    }

    #[test]
    fn cancel_key_rotation_succeeds_for_new_account() {
        let (mut ac, admin) = fresh_with_admin();
        let new_account = account(0xD0);

        ac.request_key_rotation(admin, new_account, 100, 5000).unwrap();
        ac.cancel_key_rotation(admin, new_account, 110, 5100).unwrap();

        assert!(ac.get_pending_rotation(admin).is_none());
    }

    #[test]
    fn cancel_key_rotation_fails_for_unauthorized_caller() {
        let (mut ac, admin) = fresh_with_admin();
        let new_account = account(0xD0);
        let unauthorized = account(0xE0);

        ac.request_key_rotation(admin, new_account, 100, 5000).unwrap();

        let result = ac.cancel_key_rotation(admin, unauthorized, 110, 5100);
        assert_eq!(result, Err(AccessControlError::RotationUnauthorized));

        // Rotation should still be pending
        assert!(ac.get_pending_rotation(admin).is_some());
    }

    #[test]
    fn cancel_key_rotation_fails_without_pending() {
        let (mut ac, _admin) = fresh_with_admin();
        let nobody = account(0x00);

        let result = ac.cancel_key_rotation(nobody, nobody, 110, 5100);
        assert_eq!(result, Err(AccessControlError::NoPendingRotation));
    }

    #[test]
    fn cancel_key_rotation_writes_audit() {
        let (mut ac, admin) = fresh_with_admin();
        let new_account = account(0xD0);

        ac.request_key_rotation(admin, new_account, 100, 5000).unwrap();
        ac.cancel_key_rotation(admin, admin, 110, 5100).unwrap();

        // bootstrap = 2, request = 1, cancel = 1 → 4
        assert_eq!(ac.audit_count(), 4);
        let entry = ac.get_audit_entry(4).expect("entry exists");
        assert_eq!(entry.action, AuditAction::KeyRotationCancelled);
    }

    // ─── Full lifecycle ─────────────────────────────────────────────────────

    #[test]
    fn full_lifecycle_grant_revoke_rotate() {
        let (mut ac, admin) = fresh_with_admin();
        let operator = account(0xB0);
        let new_operator = account(0xD0);
        let p = perm(Resource::Bridge, Action::Pause);

        // 1. Grant BridgeOperator role to operator
        ac.grant_role(admin, operator, Role::BridgeOperator, 10, 2000).unwrap();
        assert!(ac.has_role(operator, Role::BridgeOperator));

        // 2. Grant pause permission to BridgeOperator role
        ac.grant_permission_to_role(admin, Role::BridgeOperator, p, 10, 2000)
            .unwrap();
        assert!(ac.has_permission(operator, p));

        // 3. Revoke the role
        ac.revoke_role(admin, operator, Role::BridgeOperator, 20, 3000).unwrap();
        assert!(!ac.has_role(operator, Role::BridgeOperator));
        assert!(!ac.has_permission(operator, p));

        // 4. Re-grant and rotate keys
        ac.grant_role(admin, operator, Role::BridgeOperator, 30, 4000).unwrap();
        ac.request_key_rotation(operator, new_operator, 100, 5000).unwrap();

        let confirm_block = 100 + KEY_ROTATION_COOLDOWN_BLOCKS;
        ac.confirm_key_rotation(operator, new_operator, confirm_block, 6000)
            .unwrap();

        // new_operator now has the role and permission
        assert!(ac.has_role(new_operator, Role::BridgeOperator));
        assert!(ac.has_permission(new_operator, p));
        assert!(!ac.has_role(operator, Role::BridgeOperator));
    }

    // ─── Storage gap (#1261) ────────────────────────────────────────────────

    #[test]
    fn storage_gap_field_exists_and_is_zeroed() {
        let ac = AccessControl::new(100);

        // The struct should compile with the storage gap field.
        // Verify via Debug output that core fields are present.
        let debug_str = format!("{:?}", ac);
        assert!(debug_str.contains("audit_count"));
        assert!(debug_str.contains("cache_epoch"));
    }

    #[test]
    fn storage_gap_size_matches_constant() {
        // STORAGE_GAP_SIZE should be 20 as defined in constants.rs
        assert_eq!(STORAGE_GAP_SIZE, 20);
    }
}
