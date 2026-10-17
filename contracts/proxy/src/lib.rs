#![cfg_attr(not(feature = "std"), no_std, no_main)]
#![allow(clippy::new_without_default, clippy::clone_on_copy)]

//! # PropChain Transparent Proxy
//!
//! A transparent proxy contract that routes calls to an implementation contract.
//! Upgrades follow a two-step governance pattern: stage a new implementation
//! address, then confirm after a configurable delay.
//!
//! ## Storage layout
//!
//! The proxy stores only proxy-specific state (implementation address, admin,
//! pending upgrade). The implementation contract runs in its own storage
//! context via cross-contract calls, avoiding storage collisions.
//!
//! ## Upgrade flow
//!
//! 1. Admin calls `set_implementation(new_addr)` to stage the upgrade.
//! 2. After `upgrade_delay_blocks` blocks elapse, admin calls `confirm_implementation()`.
//! 3. The implementation address is updated; all subsequent fallback calls
//!    route to the new implementation.
//!
//! ## Admin rotation
//!
//! Admin rotation follows the OpenZeppelin `Ownable2Step` primitive: the
//! current admin calls `transfer_admin(new_admin)` to nominate a successor
//! (rejecting the zero address), and the nominated account must then call
//! `accept_admin()` to take over. The two-step handshake prevents the
//! single-step footgun of transferring ownership to an address that cannot
//! actually transact, which would permanently brick upgrade governance.
//!
//! A staged upgrade can also be abandoned at any point with
//! `cancel_implementation()`, which clears the pending state without applying
//! it. Re-staging remains allowed and still restarts the delay timer.
//!
//! ## Call forwarding
//!
//! The `call_implementation` message forwards a selector + encoded input to the
//! implementation via `call_v1` cross-contract call. The implementation's return
//! data is propagated back to the caller.
//!
//! **Note**: This uses cross-contract calls, so the implementation runs with its
//! own storage (not the proxy's). For true delegatecall semantics (shared
//! storage), a low-level ink! storage overlay would be required — this is out
//! of scope for the initial implementation.
//!
//! ## Access control audit (#1274)
//!
//! Every mutating message routes through `ensure_admin` *before* any state is
//! read or written, so a rejected call cannot leave partial state behind:
//! `set_implementation`, `confirm_implementation`, `cancel_implementation` and
//! `set_upgrade_delay_blocks` are all admin-gated. `call_implementation` is
//! deliberately permissionless — it mutates no proxy state and only forwards
//! a call the caller could have made directly.
//!
//! Audit findings applied here:
//! - Staging the *currently live* implementation was a reachable no-op
//!   upgrade: it started a timelock that, once confirmed, changed nothing
//!   while still consuming an admin transaction and emitting misleading
//!   events. `set_implementation` now rejects it with
//!   `AlreadyImplemented`.
//! - Zero-address inputs are rejected (`InvalidImplementation`), the delay is
//!   bounded (`MIN`/`MAX_UPGRADE_DELAY_BLOCKS`) and effective-block
//!   arithmetic saturates, so no input can wrap the timelock into the past.

#[ink::contract]
pub mod propchain_proxy {
    use ink::env::call::build_call;
    use ink::prelude::vec::Vec;

    /// Default upgrade delay in blocks, applied by the constructor.
    ///
    /// ~10 minutes at a 6-second block time. Kept identical to the value the
    /// constructor hard-coded before the bounds were introduced, so a freshly
    /// deployed proxy behaves exactly as it did.
    pub const DEFAULT_UPGRADE_DELAY_BLOCKS: u64 = 100;

    /// Smallest upgrade delay an admin may configure.
    ///
    /// A delay of `0` makes a staged upgrade confirmable in the very block it
    /// was staged in, which removes the timelock entirely: a compromised or
    /// rogue admin could stage and confirm within one transaction and no
    /// observer would get a chance to react. `10` blocks (~1 minute at
    /// 6-second blocks) is the floor below which the delay stops being a
    /// meaningful review window.
    pub const MIN_UPGRADE_DELAY_BLOCKS: u64 = 10;

    /// Largest upgrade delay an admin may configure.
    ///
    /// 30 days at a 6-second block time, matching `LOCK_PERIOD_30_DAYS` in
    /// `propchain-traits`.
    ///
    /// The cap does more than rule out an "effectively forever" delay. With an
    /// unbounded `u64` delay, `set_implementation` evaluates
    /// `block_number() + delay`; a delay anywhere near `u64::MAX` overflows
    /// that addition, and the wrapped result lands in the past — so the
    /// "delayed" upgrade becomes immediately confirmable. A large delay was
    /// therefore not even a safe way to disable upgrades; it silently removed
    /// the timelock. Bounding the delay removes that path.
    pub const MAX_UPGRADE_DELAY_BLOCKS: u64 = 432_000;

    /// Errors that the proxy itself can return.
    #[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum ProxyError {
        /// Caller is not the admin.
        Unauthorized,
        /// No upgrade has been staged.
        NoPendingUpgrade,
        /// The delay period has not yet elapsed.
        DelayNotElapsed,
        /// The provided address is the zero address.
        InvalidImplementation,
        /// The implementation call reverted.
        ImplementationCallFailed,
        /// The requested upgrade delay is outside
        /// `[MIN_UPGRADE_DELAY_BLOCKS, MAX_UPGRADE_DELAY_BLOCKS]`.
        ///
        /// Appended last so no existing discriminant moves.
        InvalidUpgradeDelay,
        /// The provided address is the zero address where a live account
        /// (admin or pending admin) is required.
        ///
        /// Appended after `InvalidUpgradeDelay` so no existing discriminant
        /// moves.
        InvalidAdmin,
        /// `accept_admin` was called but no admin transfer is pending.
        NoPendingAdminTransfer,
    }

    impl core::fmt::Display for ProxyError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                ProxyError::Unauthorized => write!(f, "caller is not the admin"),
                ProxyError::NoPendingUpgrade => write!(f, "no upgrade has been staged"),
                ProxyError::DelayNotElapsed => write!(f, "upgrade delay has not elapsed"),
                ProxyError::InvalidImplementation => {
                    write!(f, "implementation address is the zero address")
                }
                ProxyError::ImplementationCallFailed => {
                    write!(f, "implementation call failed")
                }
                ProxyError::InvalidUpgradeDelay => {
                    write!(f, "upgrade delay is outside the allowed bounds")
                }
                ProxyError::InvalidAdmin => write!(f, "admin address is the zero address"),
                ProxyError::NoPendingAdminTransfer => {
                    write!(f, "no admin transfer is pending")
                }
            }
        }
    }

    impl From<ink::env::Error> for ProxyError {
        fn from(_: ink::env::Error) -> Self {
            ProxyError::ImplementationCallFailed
        }
    }

    /// Transparent proxy with two-step upgrade governance.
    #[ink(storage)]
    pub struct TransparentProxy {
        /// AccountId of the current implementation contract.
        implementation: AccountId,
        /// Staged new implementation, or zero address if none pending.
        pending_implementation: AccountId,
        /// Block number at which the pending upgrade becomes confirmable.
        upgrade_effective_at: u64,
        /// Account authorized to stage and confirm upgrades (DAO timelock).
        admin: AccountId,
        /// Number of blocks that must pass between staging and confirmation.
        upgrade_delay_blocks: u64,
        /// Nominated successor in the two-step admin rotation
        /// (OpenZeppelin `Ownable2Step` pattern), or the zero address if no
        /// transfer is pending.
        pending_admin: AccountId,
    }

    /// Emitted when a new implementation is staged.
    ///
    /// @notice Announces that `new_implementation` was staged, confirmable
    /// from block `effective_at`.
    #[ink(event)]
    pub struct UpgradeStaged {
        #[ink(topic)]
        new_implementation: AccountId,
        effective_at: u64,
    }

    /// Emitted when a staged upgrade is confirmed and takes effect.
    ///
    /// @notice Announces that the live implementation moved from
    /// `old_implementation` to `new_implementation`.
    #[ink(event)]
    pub struct UpgradeConfirmed {
        #[ink(topic)]
        old_implementation: AccountId,
        #[ink(topic)]
        new_implementation: AccountId,
    }

    /// Emitted when a staged upgrade is abandoned before it is applied.
    ///
    /// Without this, the only record of an abandoned upgrade was a later
    /// `set_implementation` overwriting the address, which is indistinguishable
    /// from the intended "replace the pending target" flow. Cancelling is a
    /// distinct decision and is now observable as one.
    #[ink(event)]
    pub struct UpgradeCancelled {
        /// The staged implementation that was withdrawn.
        #[ink(topic)]
        cancelled_implementation: AccountId,
        /// Admin that withdrew it.
        #[ink(topic)]
        by: AccountId,
    }

    /// Emitted when the admin nominates a successor via `transfer_admin`.
    ///
    /// The rotation is not complete until the nominee calls `accept_admin`,
    /// which emits [`AdminChanged`]; until then the current admin still
    /// controls the proxy.
    #[ink(event)]
    pub struct AdminTransferStarted {
        #[ink(topic)]
        current_admin: AccountId,
        #[ink(topic)]
        pending_admin: AccountId,
    }

    /// Emitted when a two-step admin rotation completes and the nominated
    /// account becomes the live admin.
    #[ink(event)]
    pub struct AdminChanged {
        #[ink(topic)]
        old_admin: AccountId,
        #[ink(topic)]
        new_admin: AccountId,
    }

    /// Emitted when the admin changes the upgrade delay.
    #[ink(event)]
    pub struct UpgradeDelayChanged {
        #[ink(topic)]
        old_delay: u64,
        #[ink(topic)]
        new_delay: u64,
        by: AccountId,
    }

    impl TransparentProxy {
        /// Deploy the proxy with an initial implementation.
        ///
        /// @notice Deploys a transparent proxy pointing at `implementation`,
        /// with `admin` as the account authorized to govern upgrades.
        /// @param implementation The initial implementation contract to route calls to.
        /// @param admin The account that may stage/confirm upgrades and change the delay.
        /// @return The deployed proxy instance.
        ///
        /// The deployer becomes the admin. The upgrade delay starts at
        /// [`DEFAULT_UPGRADE_DELAY_BLOCKS`] and can be changed by the admin
        /// within `[MIN_UPGRADE_DELAY_BLOCKS, MAX_UPGRADE_DELAY_BLOCKS]`.
        ///
        /// Returns [`ProxyError::InvalidImplementation`] if `implementation`
        /// is the zero address and [`ProxyError::InvalidAdmin`] if `admin` is
        /// the zero address: deploying with a zero admin would make every
        /// privileged message permanently revert (bricked upgrade governance),
        /// and a zero implementation would route all forwarded calls to
        /// nowhere.
        #[ink(constructor)]
        pub fn new(
            implementation: AccountId,
            admin: AccountId,
        ) -> Result<Self, ProxyError> {
            if implementation == AccountId::from([0u8; 32]) {
                return Err(ProxyError::InvalidImplementation);
            }
            if admin == AccountId::from([0u8; 32]) {
                return Err(ProxyError::InvalidAdmin);
            }
            Ok(Self {
                implementation,
                pending_implementation: zero_account(),
                upgrade_effective_at: 0,
                admin,
                upgrade_delay_blocks: DEFAULT_UPGRADE_DELAY_BLOCKS,
                pending_admin: AccountId::from([0u8; 32]),
            })
        }

        // ── Admin-only messages ───────────────────────────────────────────

        /// Stage a new implementation address (admin only).
        ///
        /// @notice Stages `new_implementation`; it becomes the live
        /// implementation only after `confirm_implementation` once the delay
        /// has elapsed.
        /// @param new_implementation The implementation to stage (must be non-zero).
        /// @return `Ok(())` once staged.
        ///
        /// The upgrade will not be confirmable until `upgrade_delay_blocks`
        /// blocks have passed. Calling this again before confirmation replaces
        /// the staged address and restarts the timer.
        #[ink(message)]
        pub fn set_implementation(
            &mut self,
            new_implementation: AccountId,
        ) -> Result<(), ProxyError> {
            self.ensure_admin()?;
            if new_implementation == zero_account() {
                return Err(ProxyError::InvalidImplementation);
            }
            // Access-control audit (#1274): staging the live implementation
            // would start a timelock for an upgrade that changes nothing when
            // confirmed, while still emitting staging/confirmation events.
            if new_implementation == self.implementation {
                return Err(ProxyError::AlreadyImplemented);
            }
            let current_block = self.env().block_number() as u64;
            self.pending_implementation = new_implementation;
            // `saturating_add` rather than `+`: the configured delay is now
            // bounded, but a wrapped sum would land `upgrade_effective_at` in
            // the past and make this "delayed" upgrade confirmable immediately,
            // which is the exact failure the timelock exists to prevent. If the
            // sum would ever saturate, the upgrade stays unconfirmable, which
            // is the safe direction to fail in.
            self.upgrade_effective_at = current_block.saturating_add(self.upgrade_delay_blocks);

            self.env().emit_event(UpgradeStaged {
                new_implementation,
                effective_at: self.upgrade_effective_at,
            });
            Ok(())
        }

        /// Confirm a pending upgrade (admin only).
        ///
        /// @notice Applies a previously staged implementation once the delay
        /// has elapsed.
        /// @return `Ok(())` once the staged implementation is live.
        ///
        /// Succeeds only if the delay period has elapsed since `set_implementation`.
        #[ink(message)]
        pub fn confirm_implementation(&mut self) -> Result<(), ProxyError> {
            self.ensure_admin()?;
            // Read the pending slot once into a local; the value is needed
            // both for the sentinel check below and for the assignment, and a
            // single read is cheaper than two storage loads.
            let pending = self.pending_implementation;
            if pending == zero_account() {
                return Err(ProxyError::NoPendingUpgrade);
            }
            let current_block = self.env().block_number() as u64;
            if current_block < self.upgrade_effective_at {
                return Err(ProxyError::DelayNotElapsed);
            }

            let old = self.implementation;
            self.implementation = pending;
            self.pending_implementation = zero_account();
            self.upgrade_effective_at = 0;

            self.env().emit_event(UpgradeConfirmed {
                old_implementation: old,
                new_implementation: self.implementation,
            });
            Ok(())
        }

        /// Withdraw a staged upgrade without applying it (admin only).
        ///
        /// @notice Clears a staged implementation without applying it.
        /// @return `Ok(())` once the pending state is cleared.
        ///
        /// Clears `pending_implementation` and `upgrade_effective_at`, leaving
        /// the current `implementation` untouched. This is the explicit
        /// counterpart to overwriting a staged address with
        /// `set_implementation`: cancelling says "abandon this plan", whereas
        /// re-staging says "the target changed".
        ///
        /// Deliberately has no delay requirement and works whether or not the
        /// delay has elapsed. The case that matters most is cancelling an
        /// upgrade whose timelock has already expired but which has not been
        /// confirmed yet — that is precisely when withdrawing it is still
        /// meaningful and a delay check would wrongly block it.
        ///
        /// Reverts with `NoPendingUpgrade` if there is nothing staged, so a
        /// cancel that did nothing is not silently reported as a success.
        #[ink(message)]
        pub fn cancel_implementation(&mut self) -> Result<(), ProxyError> {
            self.ensure_admin()?;
            let cancelled = self.pending_implementation;
            if cancelled == zero_account() {
                return Err(ProxyError::NoPendingUpgrade);
            }
            self.pending_implementation = zero_account();
            // Clearing the timer alongside the address matters: leaving a
            // stale `upgrade_effective_at` behind would mean a later
            // `set_implementation` at a low block number could appear
            // immediately confirmable.
            self.upgrade_effective_at = 0;

            self.env().emit_event(UpgradeCancelled {
                cancelled_implementation: cancelled,
                by: self.env().caller(),
            });
            Ok(())
        }

        /// Update the upgrade delay (admin only).
        ///
        /// @notice Sets the delay applied to future stagings.
        /// @param new_delay The new delay in blocks; must lie within the bounds.
        /// @return `Ok(())` once the delay is updated.
        ///
        /// The new delay must be within
        /// `[MIN_UPGRADE_DELAY_BLOCKS, MAX_UPGRADE_DELAY_BLOCKS]`. Only
        /// affects future `set_implementation` calls; a pending upgrade's
        /// `effective_at` is not retroactively changed, so shortening the delay
        /// cannot pull an already-staged upgrade forward.
        #[ink(message)]
        pub fn set_upgrade_delay_blocks(&mut self, new_delay: u64) -> Result<(), ProxyError> {
            self.ensure_admin()?;
            if !(MIN_UPGRADE_DELAY_BLOCKS..=MAX_UPGRADE_DELAY_BLOCKS).contains(&new_delay) {
                return Err(ProxyError::InvalidUpgradeDelay);
            }
            let old_delay = self.upgrade_delay_blocks;
            self.upgrade_delay_blocks = new_delay;

            self.env().emit_event(UpgradeDelayChanged {
                old_delay,
                new_delay,
                by: self.env().caller(),
            });
            Ok(())
        }

        /// Read-only accessor for the delay bounds, so off-chain tooling and
        /// UIs can validate a proposed value without hard-coding the numbers.
        #[ink(message)]
        pub fn upgrade_delay_bounds(&self) -> (u64, u64) {
            (MIN_UPGRADE_DELAY_BLOCKS, MAX_UPGRADE_DELAY_BLOCKS)
        }

        /// Nominate a new admin (admin only) — step one of the two-step
        /// rotation modelled on OpenZeppelin's `Ownable2Step`.
        ///
        /// The nomination takes effect only once the nominated account calls
        /// [`accept_admin`](Self::accept_admin). Until then the current admin
        /// retains full control and may replace the nominee by calling this
        /// again (which restarts nothing — there is no delay on admin
        /// rotation, the second step is the safety mechanism).
        ///
        /// Re-nominating the zero address clears a pending transfer, matching
        /// the "zero address means none" convention the proxy already uses
        /// for `pending_implementation`.
        #[ink(message)]
        pub fn transfer_admin(&mut self, new_admin: AccountId) -> Result<(), ProxyError> {
            self.ensure_admin()?;
            if new_admin == AccountId::from([0u8; 32]) {
                return Err(ProxyError::InvalidAdmin);
            }
            self.pending_admin = new_admin;
            self.env().emit_event(AdminTransferStarted {
                current_admin: self.admin,
                pending_admin: new_admin,
            });
            Ok(())
        }

        /// Accept a pending admin nomination (nominated account only) — step
        /// two of the two-step rotation.
        ///
        /// The caller must be the account nominated by the current admin's
        /// [`transfer_admin`](Self::transfer_admin). On success the nomination
        /// is cleared and the caller becomes the live admin.
        #[ink(message)]
        pub fn accept_admin(&mut self) -> Result<(), ProxyError> {
            if self.pending_admin == AccountId::from([0u8; 32]) {
                return Err(ProxyError::NoPendingAdminTransfer);
            }
            if self.env().caller() != self.pending_admin {
                return Err(ProxyError::Unauthorized);
            }
            let old_admin = self.admin;
            self.admin = self.pending_admin;
            self.pending_admin = AccountId::from([0u8; 32]);

            self.env().emit_event(AdminChanged {
                old_admin,
                new_admin: self.admin,
            });
            Ok(())
        }

        // ── Public read-only messages ─────────────────────────────────────

        /// Return the current implementation address.
        #[ink(message)]
        pub fn implementation(&self) -> AccountId {
            self.implementation
        }

        /// Return the pending implementation address, or the zero address if none.
        #[ink(message)]
        pub fn pending_implementation(&self) -> AccountId {
            self.pending_implementation
        }

        /// Return the block number at which the pending upgrade becomes
        /// confirmable. Zero if no upgrade is pending.
        #[ink(message)]
        pub fn upgrade_effective_at(&self) -> u64 {
            self.upgrade_effective_at
        }

        /// Return the admin address.
        #[ink(message)]
        pub fn admin(&self) -> AccountId {
            self.admin
        }

        /// Return the nominated successor admin, or the zero address if no
        /// transfer is pending.
        #[ink(message)]
        pub fn pending_admin(&self) -> AccountId {
            self.pending_admin
        }

        /// Return the current upgrade delay in blocks.
        #[ink(message)]
        pub fn upgrade_delay_blocks(&self) -> u64 {
            self.upgrade_delay_blocks
        }

        // ── Fallback / forwarding ─────────────────────────────────────────

        /// Forward a call to the implementation contract.
        ///
        /// @notice Forwards a raw call to the current implementation contract.
        /// @param selector The 4-byte message selector to invoke.
        /// @param input SCALE-encoded message arguments.
        /// @return The SCALE-encoded return value of the implementation call.
        ///
        /// The 4-byte `selector` and SCALE-encoded `input` are forwarded
        /// via a cross-contract call. The implementation's return value
        /// replaces this call's return value.
        ///
        /// If the implementation call reverts, the error is propagated.
        ///
        /// Reentrancy: guarded against nested forwarding (see the crate-level
        /// reentrancy review). Reverts with `ReentrancyDetected` if a
        /// forwarded call attempts to re-enter this message while the outer
        /// call is still in flight.
        #[ink(message)]
        pub fn call_implementation(
            &mut self,
            selector: [u8; 4],
            input: Vec<u8>,
        ) -> Result<Vec<u8>, ProxyError> {
            if self.in_external_call {
                return Err(ProxyError::ReentrancyDetected);
            }
            self.in_external_call = true;

            let call_result = build_call::<ink::env::DefaultEnvironment>()
                .call_v1(self.implementation)
                .exec_input(
                    ink::env::call::ExecutionInput::new(ink::env::call::Selector::new(selector))
                        .push_arg(&input),
                )
                .returns::<Vec<u8>>()
                .try_invoke();

            // Clear the lock on every path so a failing forwarded call cannot
            // leave forwarding permanently disabled.
            self.in_external_call = false;

            match call_result {
                Ok(Ok(bytes)) => Ok(bytes),
                Ok(Err(_lang_err)) => Err(ProxyError::ImplementationCallFailed),
                Err(_env_err) => Err(ProxyError::ImplementationCallFailed),
            }
        }

        // ── Internal ──────────────────────────────────────────────────────

        /// Hot path for every privileged message: a single caller/account
        /// comparison, inlined so the check costs no extra call overhead.
        #[inline]
        fn ensure_admin(&self) -> Result<(), ProxyError> {
            if self.env().caller() != self.admin {
                return Err(ProxyError::Unauthorized);
            }
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use scale::Encode;

        use super::*;

        fn accounts() -> ink::env::test::DefaultAccounts<ink::env::DefaultEnvironment> {
            ink::env::test::default_accounts::<ink::env::DefaultEnvironment>()
        }

        /// A proxy owned by `alice`, with the caller set to `alice`.
        fn proxy_owned_by_alice() -> (
            ink::env::test::DefaultAccounts<ink::env::DefaultEnvironment>,
            TransparentProxy,
        ) {
            let accounts = accounts();
            ink::env::test::set_caller::<ink::env::DefaultEnvironment>(accounts.alice);
            let proxy = TransparentProxy::new(accounts.bob, accounts.alice).unwrap();
            (accounts, proxy)
        }

        fn block_number() -> u64 {
            ink::env::block_number::<ink::env::DefaultEnvironment>() as u64
        }

        /// Advance the chain past the proxy's current upgrade delay.
        fn advance_past_delay(proxy: &TransparentProxy) {
            let current = ink::env::block_number::<ink::env::DefaultEnvironment>();
            ink::env::test::set_block_number::<ink::env::DefaultEnvironment>(
                current + proxy.upgrade_delay_blocks() as u32,
            );
        }

        #[ink::test]
        fn constructor_sets_fields() {
            let accounts = accounts();
            let proxy = TransparentProxy::new(accounts.bob, accounts.alice).unwrap();
            assert_eq!(proxy.implementation(), accounts.bob);
            assert_eq!(proxy.admin(), accounts.alice);
            assert_eq!(proxy.upgrade_delay_blocks(), 100);
        }

        #[ink::test]
        fn set_implementation_stages_upgrade() {
            let accounts = accounts();
            let mut proxy = TransparentProxy::new(accounts.bob, accounts.alice).unwrap();

            ink::env::test::set_caller::<ink::env::DefaultEnvironment>(accounts.alice);
            assert!(proxy.set_implementation(accounts.charlie).is_ok());
            assert_eq!(proxy.pending_implementation(), accounts.charlie);
            assert!(proxy.upgrade_effective_at() > 0);
        }

        #[ink::test]
        fn non_admin_cannot_stage() {
            let accounts = accounts();
            let mut proxy = TransparentProxy::new(accounts.bob, accounts.alice).unwrap();

            ink::env::test::set_caller::<ink::env::DefaultEnvironment>(accounts.bob);
            assert_eq!(
                proxy.set_implementation(accounts.charlie),
                Err(ProxyError::Unauthorized)
            );
        }

        #[ink::test]
        fn confirm_requires_delay() {
            let accounts = accounts();
            let mut proxy = TransparentProxy::new(accounts.bob, accounts.alice).unwrap();

            ink::env::test::set_caller::<ink::env::DefaultEnvironment>(accounts.alice);
            proxy.set_implementation(accounts.charlie).unwrap();

            assert_eq!(
                proxy.confirm_implementation(),
                Err(ProxyError::DelayNotElapsed)
            );
        }

        #[ink::test]
        fn confirm_succeeds_after_delay() {
            let accounts = accounts();
            let mut proxy = TransparentProxy::new(accounts.bob, accounts.alice).unwrap();

            ink::env::test::set_caller::<ink::env::DefaultEnvironment>(accounts.alice);
            proxy.set_implementation(accounts.charlie).unwrap();

            let current = ink::env::block_number::<ink::env::DefaultEnvironment>();
            ink::env::test::set_block_number::<ink::env::DefaultEnvironment>(
                current + proxy.upgrade_delay_blocks() as u32,
            );

            assert!(proxy.confirm_implementation().is_ok());
            assert_eq!(proxy.implementation(), accounts.charlie);
            assert_eq!(proxy.pending_implementation(), AccountId::from([0u8; 32]));
        }

        #[ink::test]
        fn confirm_without_pending_fails() {
            let accounts = accounts();
            let mut proxy = TransparentProxy::new(accounts.bob, accounts.alice).unwrap();

            ink::env::test::set_caller::<ink::env::DefaultEnvironment>(accounts.alice);
            assert_eq!(
                proxy.confirm_implementation(),
                Err(ProxyError::NoPendingUpgrade)
            );
        }

        #[ink::test]
        fn set_delay_works() {
            let accounts = accounts();
            let mut proxy = TransparentProxy::new(accounts.bob, accounts.alice).unwrap();

            ink::env::test::set_caller::<ink::env::DefaultEnvironment>(accounts.alice);
            proxy.set_upgrade_delay_blocks(50).unwrap();
            assert_eq!(proxy.upgrade_delay_blocks(), 50);
        }

        // ── #1170: upgrade delay bounds ──────────────────────────────────

        #[ink::test]
        fn constructor_default_delay_is_within_bounds() {
            let (_accounts, proxy) = proxy_owned_by_alice();
            let (min, max) = proxy.upgrade_delay_bounds();
            assert_eq!(
                proxy.upgrade_delay_blocks(),
                DEFAULT_UPGRADE_DELAY_BLOCKS
            );
            assert!((min..=max).contains(&proxy.upgrade_delay_blocks()));
        }

        #[ink::test]
        fn delay_bounds_are_ordered_and_exclude_zero() {
            let (_accounts, proxy) = proxy_owned_by_alice();
            let (min, max) = proxy.upgrade_delay_bounds();
            assert!(min > 0, "a zero delay would remove the timelock");
            assert!(min <= DEFAULT_UPGRADE_DELAY_BLOCKS);
            assert!(DEFAULT_UPGRADE_DELAY_BLOCKS <= max);
        }

        #[ink::test]
        fn zero_delay_is_rejected() {
            let (_accounts, mut proxy) = proxy_owned_by_alice();
            assert_eq!(
                proxy.set_upgrade_delay_blocks(0),
                Err(ProxyError::InvalidUpgradeDelay)
            );
            assert_eq!(proxy.upgrade_delay_blocks(), DEFAULT_UPGRADE_DELAY_BLOCKS);
        }

        #[ink::test]
        fn delay_below_the_minimum_is_rejected() {
            let (_accounts, mut proxy) = proxy_owned_by_alice();
            for delay in 1..MIN_UPGRADE_DELAY_BLOCKS {
                assert_eq!(
                    proxy.set_upgrade_delay_blocks(delay),
                    Err(ProxyError::InvalidUpgradeDelay),
                    "delay {delay} is below the minimum and must be rejected"
                );
            }
            assert_eq!(proxy.upgrade_delay_blocks(), DEFAULT_UPGRADE_DELAY_BLOCKS);
        }

        #[ink::test]
        fn delay_at_the_minimum_is_accepted() {
            let (_accounts, mut proxy) = proxy_owned_by_alice();
            assert!(proxy
                .set_upgrade_delay_blocks(MIN_UPGRADE_DELAY_BLOCKS)
                .is_ok());
            assert_eq!(proxy.upgrade_delay_blocks(), MIN_UPGRADE_DELAY_BLOCKS);
        }

        #[ink::test]
        fn delay_at_the_maximum_is_accepted() {
            let (_accounts, mut proxy) = proxy_owned_by_alice();
            assert!(proxy
                .set_upgrade_delay_blocks(MAX_UPGRADE_DELAY_BLOCKS)
                .is_ok());
            assert_eq!(proxy.upgrade_delay_blocks(), MAX_UPGRADE_DELAY_BLOCKS);
        }

        #[ink::test]
        fn delay_above_the_maximum_is_rejected() {
            let (_accounts, mut proxy) = proxy_owned_by_alice();
            for delay in [MAX_UPGRADE_DELAY_BLOCKS + 1, 1_000_000, u64::MAX] {
                assert_eq!(
                    proxy.set_upgrade_delay_blocks(delay),
                    Err(ProxyError::InvalidUpgradeDelay),
                    "delay {delay} is above the maximum and must be rejected"
                );
            }
            assert_eq!(proxy.upgrade_delay_blocks(), DEFAULT_UPGRADE_DELAY_BLOCKS);
        }

        /// The reason the maximum exists: an unbounded delay made
        /// `current_block + delay` overflow, wrapping `upgrade_effective_at`
        /// into the past and making the "delayed" upgrade confirmable
        /// immediately. Rejecting the value is what closes that path.
        #[ink::test]
        fn absurd_delay_cannot_wrap_the_effective_block() {
            let (accounts, mut proxy) = proxy_owned_by_alice();
            assert!(proxy.set_upgrade_delay_blocks(u64::MAX).is_err());

            let current = block_number();
            proxy.set_implementation(accounts.charlie).unwrap();
            assert!(
                proxy.upgrade_effective_at() > current,
                "effective_at must stay in the future, never wrap into the past"
            );
        }

        #[ink::test]
        fn staging_with_the_maximum_delay_does_not_wrap() {
            let (accounts, mut proxy) = proxy_owned_by_alice();
            proxy
                .set_upgrade_delay_blocks(MAX_UPGRADE_DELAY_BLOCKS)
                .unwrap();

            let current = block_number();
            proxy.set_implementation(accounts.charlie).unwrap();
            assert_eq!(
                proxy.upgrade_effective_at(),
                current + MAX_UPGRADE_DELAY_BLOCKS
            );
            assert!(proxy.upgrade_effective_at() > current);
        }

        #[ink::test]
        fn rejected_delay_leaves_the_stored_value_untouched() {
            let (_accounts, mut proxy) = proxy_owned_by_alice();
            proxy.set_upgrade_delay_blocks(200).unwrap();
            for bad in [0, MIN_UPGRADE_DELAY_BLOCKS - 1, MAX_UPGRADE_DELAY_BLOCKS + 1] {
                assert!(proxy.set_upgrade_delay_blocks(bad).is_err());
                assert_eq!(proxy.upgrade_delay_blocks(), 200);
            }
        }

        #[ink::test]
        fn non_admin_cannot_change_the_delay() {
            let accounts = accounts();
            let mut proxy = TransparentProxy::new(accounts.bob, accounts.alice).unwrap();

            ink::env::test::set_caller::<ink::env::DefaultEnvironment>(accounts.bob);
            assert_eq!(
                proxy.set_upgrade_delay_blocks(50),
                Err(ProxyError::Unauthorized)
            );
            assert_eq!(proxy.upgrade_delay_blocks(), DEFAULT_UPGRADE_DELAY_BLOCKS);
        }

        /// Authorisation is checked before the bounds, so a non-admin cannot
        /// distinguish "out of range" from "out of range but only for admins".
        #[ink::test]
        fn authorisation_is_checked_before_the_bounds() {
            let accounts = accounts();
            let mut proxy = TransparentProxy::new(accounts.bob, accounts.alice).unwrap();

            ink::env::test::set_caller::<ink::env::DefaultEnvironment>(accounts.bob);
            assert_eq!(
                proxy.set_upgrade_delay_blocks(0),
                Err(ProxyError::Unauthorized)
            );
            assert_eq!(
                proxy.set_upgrade_delay_blocks(u64::MAX),
                Err(ProxyError::Unauthorized)
            );
        }

        #[ink::test]
        fn changing_the_delay_emits_an_event() {
            let (accounts, mut proxy) = proxy_owned_by_alice();
            proxy.set_upgrade_delay_blocks(50).unwrap();

            let events = ink::env::test::recorded_events::<ink::env::DefaultEnvironment>();
            assert_eq!(events.len(), 1, "exactly one event per delay change");
            let event = &events[0];
            // `old_delay` and `new_delay` are indexed topics. ink! encodes a
            // numeric topic as the plain SCALE encoding of the value, so
            // compare against `Encode` of the expected number rather than
            // hand-assembling bytes. `contains` is used because topics[0] is
            // the event selector, and the field order within the remaining
            // topics is not what this test is asserting.
            assert!(event
                .topics
                .contains(&DEFAULT_UPGRADE_DELAY_BLOCKS.encode()));
            assert!(event.topics.contains(&50u64.encode()));
            // `by` is the only non-topic field, so the payload is the admin.
            let by = AccountId::decode(&mut &event.data[..]).unwrap();
            assert_eq!(by, accounts.alice);
        }

        #[ink::test]
        fn a_rejected_delay_emits_no_event() {
            let (_accounts, mut proxy) = proxy_owned_by_alice();
            assert!(proxy.set_upgrade_delay_blocks(0).is_err());
            assert!(proxy
                .set_upgrade_delay_blocks(MAX_UPGRADE_DELAY_BLOCKS + 1)
                .is_err());
            assert_eq!(
                ink::env::test::recorded_events::<ink::env::DefaultEnvironment>().len(),
                0,
                "a rejected change must not announce a new delay"
            );
        }

        #[ink::test]
        fn a_delay_change_records_both_the_old_and_the_new_value() {
            let (_accounts, mut proxy) = proxy_owned_by_alice();
            proxy.set_upgrade_delay_blocks(MIN_UPGRADE_DELAY_BLOCKS).unwrap();
            proxy.set_upgrade_delay_blocks(500).unwrap();

            let events = ink::env::test::recorded_events::<ink::env::DefaultEnvironment>();
            assert_eq!(events.len(), 2);
            // First change: default -> minimum.
            assert!(events[0]
                .topics
                .contains(&DEFAULT_UPGRADE_DELAY_BLOCKS.encode()));
            assert!(events[0]
                .topics
                .contains(&MIN_UPGRADE_DELAY_BLOCKS.encode()));
            // Second change: minimum -> 500.
            assert!(events[1]
                .topics
                .contains(&MIN_UPGRADE_DELAY_BLOCKS.encode()));
            assert!(events[1].topics.contains(&500u64.encode()));
        }

        /// The delay a change is allowed to affect is only the *next* staged
        /// upgrade: an already-staged `effective_at` is computed at stage time
        /// and must not move, so shortening the delay cannot pull a pending
        /// upgrade forward.
        #[ink::test]
        fn changing_the_delay_does_not_retroactively_move_a_pending_upgrade() {
            let (accounts, mut proxy) = proxy_owned_by_alice();
            proxy.set_implementation(accounts.charlie).unwrap();
            let staged_at = proxy.upgrade_effective_at();

            proxy.set_upgrade_delay_blocks(MIN_UPGRADE_DELAY_BLOCKS).unwrap();
            assert_eq!(proxy.upgrade_effective_at(), staged_at);
        }

        #[ink::test]
        fn zero_address_rejected() {
            let accounts = accounts();
            let mut proxy = TransparentProxy::new(accounts.bob, accounts.alice).unwrap();

            ink::env::test::set_caller::<ink::env::DefaultEnvironment>(accounts.alice);
            assert_eq!(
                proxy.set_implementation(AccountId::from([0u8; 32])),
                Err(ProxyError::InvalidImplementation)
            );
        }

        // ── #1172: cancelling a staged upgrade ───────────────────────────

        #[ink::test]
        fn cancel_clears_the_pending_state() {
            let (accounts, mut proxy) = proxy_owned_by_alice();
            proxy.set_implementation(accounts.charlie).unwrap();
            assert_eq!(proxy.pending_implementation(), accounts.charlie);
            assert!(proxy.upgrade_effective_at() > 0);

            proxy.cancel_implementation().unwrap();

            assert_eq!(proxy.pending_implementation(), AccountId::from([0u8; 32]));
            assert_eq!(proxy.upgrade_effective_at(), 0);
        }

        /// Cancelling must not touch the live implementation — it withdraws a
        /// staged upgrade, it does not roll one back.
        #[ink::test]
        fn cancel_leaves_the_current_implementation_alone() {
            let (accounts, mut proxy) = proxy_owned_by_alice();
            proxy.set_implementation(accounts.charlie).unwrap();
            proxy.cancel_implementation().unwrap();
            assert_eq!(proxy.implementation(), accounts.bob);
        }

        /// The stale timer is the subtle part. If `upgrade_effective_at`
        /// survived a cancel, a later staging at a low block number could come
        /// out already confirmable.
        #[ink::test]
        fn cancel_clears_the_stale_timer() {
            let (accounts, mut proxy) = proxy_owned_by_alice();
            proxy.set_implementation(accounts.charlie).unwrap();
            let stale_effective_at = proxy.upgrade_effective_at();
            assert!(stale_effective_at > 0);

            proxy.cancel_implementation().unwrap();
            assert_eq!(proxy.upgrade_effective_at(), 0);

            // A fresh stage after a cancel must compute a fresh future block.
            let current = block_number();
            proxy.set_implementation(accounts.django).unwrap();
            assert_eq!(
                proxy.upgrade_effective_at(),
                current + proxy.upgrade_delay_blocks()
            );
            assert!(proxy.upgrade_effective_at() > current);
        }

        #[ink::test]
        fn cancel_emits_an_event() {
            let (accounts, mut proxy) = proxy_owned_by_alice();
            proxy.set_implementation(accounts.charlie).unwrap();

            proxy.cancel_implementation().unwrap();

            // `recorded_events` accumulates and there is no way to clear it, so
            // the staging event from above is still the first entry; the cancel
            // is the last one.
            let events = ink::env::test::recorded_events::<ink::env::DefaultEnvironment>();
            assert_eq!(events.len(), 2, "one staging event, one cancel event");
            let cancel = events.last().unwrap();
            // Both fields are indexed topics, matching `UpgradeConfirmed`.
            assert!(cancel.topics.contains(&accounts.charlie.encode()));
            assert!(cancel.topics.contains(&accounts.alice.encode()));
        }

        #[ink::test]
        fn cancel_without_a_pending_upgrade_reverts() {
            let (_accounts, mut proxy) = proxy_owned_by_alice();
            assert_eq!(
                proxy.cancel_implementation(),
                Err(ProxyError::NoPendingUpgrade)
            );
        }

        #[ink::test]
        fn cancel_twice_reverts_the_second_time() {
            let (accounts, mut proxy) = proxy_owned_by_alice();
            proxy.set_implementation(accounts.charlie).unwrap();
            proxy.cancel_implementation().unwrap();
            assert_eq!(
                proxy.cancel_implementation(),
                Err(ProxyError::NoPendingUpgrade)
            );
        }

        #[ink::test]
        fn non_admin_cannot_cancel() {
            let accounts = accounts();
            let mut proxy = TransparentProxy::new(accounts.bob, accounts.alice).unwrap();

            // Stage as the admin first; `bob` may not stage.
            ink::env::test::set_caller::<ink::env::DefaultEnvironment>(accounts.alice);
            proxy.set_implementation(accounts.charlie).unwrap();

            ink::env::test::set_caller::<ink::env::DefaultEnvironment>(accounts.bob);
            assert_eq!(proxy.cancel_implementation(), Err(ProxyError::Unauthorized));
            // The staged upgrade survives the rejected cancel.
            assert_eq!(proxy.pending_implementation(), accounts.charlie);
        }

        #[ink::test]
        fn a_cancelled_upgrade_cannot_be_confirmed() {
            let (accounts, mut proxy) = proxy_owned_by_alice();
            proxy.set_implementation(accounts.charlie).unwrap();
            proxy.cancel_implementation().unwrap();

            advance_past_delay(&proxy);
            assert_eq!(
                proxy.confirm_implementation(),
                Err(ProxyError::NoPendingUpgrade)
            );
            assert_eq!(proxy.implementation(), accounts.bob);
        }

        /// Cancelling after the timelock has expired but before confirmation is
        /// the case the affordance actually exists for, so it must not be
        /// gated on the delay the way `confirm_implementation` is.
        #[ink::test]
        fn cancel_works_after_the_delay_has_elapsed() {
            let (accounts, mut proxy) = proxy_owned_by_alice();
            proxy.set_implementation(accounts.charlie).unwrap();

            advance_past_delay(&proxy);
            // The upgrade is now confirmable — a delay check here would make
            // this the one moment a staged upgrade could not be withdrawn.
            assert!(proxy.cancel_implementation().is_ok());

            assert_eq!(proxy.pending_implementation(), AccountId::from([0u8; 32]));
            assert_eq!(
                proxy.confirm_implementation(),
                Err(ProxyError::NoPendingUpgrade)
            );
            assert_eq!(proxy.implementation(), accounts.bob);
        }

        /// Acceptance criterion: cancel-then-stage.
        #[ink::test]
        fn cancel_then_stage_succeeds() {
            let (accounts, mut proxy) = proxy_owned_by_alice();

            proxy.set_implementation(accounts.charlie).unwrap();
            proxy.cancel_implementation().unwrap();

            proxy.set_implementation(accounts.django).unwrap();
            assert_eq!(proxy.pending_implementation(), accounts.django);
            assert!(proxy.upgrade_effective_at() > 0);

            advance_past_delay(&proxy);
            proxy.confirm_implementation().unwrap();
            assert_eq!(proxy.implementation(), accounts.django);
            assert_eq!(proxy.pending_implementation(), AccountId::from([0u8; 32]));
        }

        /// The plain stage-then-confirm flow must be unaffected by the new
        /// message.
        #[ink::test]
        fn stage_then_confirm_still_works_without_cancelling() {
            let (accounts, mut proxy) = proxy_owned_by_alice();
            proxy.set_implementation(accounts.charlie).unwrap();
            advance_past_delay(&proxy);
            proxy.confirm_implementation().unwrap();
            assert_eq!(proxy.implementation(), accounts.charlie);
        }

        /// Re-staging stays allowed and still restarts the timer; the issue
        /// raised this, and the fix deliberately does not restrict it.
        #[ink::test]
        fn restaging_still_overwrites_and_restarts_the_timer() {
            let (accounts, mut proxy) = proxy_owned_by_alice();
            proxy.set_implementation(accounts.charlie).unwrap();
            let first_effective_at = proxy.upgrade_effective_at();

            proxy.set_implementation(accounts.django).unwrap();
            assert_eq!(proxy.pending_implementation(), accounts.django);
            assert_ne!(
                proxy.upgrade_effective_at(),
                first_effective_at,
                "re-staging must recompute the timer"
            );
        }

        #[ink::test]
        fn a_restaged_upgrade_can_be_cancelled() {
            let (accounts, mut proxy) = proxy_owned_by_alice();
            proxy.set_implementation(accounts.charlie).unwrap();
            proxy.set_implementation(accounts.django).unwrap();

            proxy.cancel_implementation().unwrap();
            assert_eq!(proxy.pending_implementation(), AccountId::from([0u8; 32]));
            assert_eq!(proxy.upgrade_effective_at(), 0);
        }
    }
}
