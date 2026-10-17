#![allow(unexpected_cfgs)]

use propchain_traits::{ReentrancyError, ReentrancyGuard};

struct Vault {
    guard: ReentrancyGuard,
    balance: u128,
}

impl Vault {
    fn new(balance: u128) -> Self {
        Self { guard: ReentrancyGuard::new(), balance }
    }

    /// A protected withdrawal that optionally re-enters itself.
    fn withdraw(&mut self, amount: u128, reenter: bool) -> Result<(), ReentrancyError> {
        self.guard.enter()?;
        let result = if reenter {
            self.withdraw(amount, false)
        } else {
            self.balance -= amount;
            Ok(())
        };
        self.guard.exit();
        result
    }
}

#[test]
fn protected_call_succeeds_and_unlocks() {
    let mut vault = Vault::new(100);
    assert_eq!(vault.withdraw(40, false), Ok(()));
    assert_eq!(vault.balance, 60);
    assert!(!vault.guard.is_locked());
}

#[test]
fn reentrant_call_is_rejected_and_state_is_untouched() {
    let mut vault = Vault::new(100);
    assert_eq!(vault.withdraw(40, true), Err(ReentrancyError::ReentrantCall));
    assert_eq!(vault.balance, 100);
    assert!(!vault.guard.is_locked());
}

#[test]
fn invariant_guard_is_unlocked_after_every_completed_call() {
    let mut vault = Vault::new(1_000);
    for i in 0..20u128 {
        let _ = vault.withdraw(i, i % 3 == 0);
        assert!(!vault.guard.is_locked());
    }
}

#[test]
fn invariant_failed_enter_does_not_unlock_the_guard() {
    let mut guard = ReentrancyGuard::new();
    guard.enter().expect("first enter");
    assert_eq!(guard.enter(), Err(ReentrancyError::ReentrantCall));
    assert!(guard.is_locked());
    guard.exit();
    assert!(!guard.is_locked());
}
