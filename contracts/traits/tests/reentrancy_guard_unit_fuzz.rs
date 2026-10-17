#![allow(unexpected_cfgs)]

use propchain_traits::{ReentrancyError, ReentrancyGuard};

#[test]
fn unit_new_guard_is_unlocked() {
    assert!(!ReentrancyGuard::new().is_locked());
}

#[test]
fn unit_enter_locks_and_exit_unlocks() {
    let mut guard = ReentrancyGuard::new();
    assert!(guard.enter().is_ok());
    assert!(guard.is_locked());
    guard.exit();
    assert!(!guard.is_locked());
}

#[test]
fn unit_second_enter_is_rejected() {
    let mut guard = ReentrancyGuard::new();
    guard.enter().expect("first enter");
    assert_eq!(guard.enter(), Err(ReentrancyError::ReentrantCall));
}

/// Deterministic pseudo-random operation sequences checked against a model.
#[test]
fn fuzz_random_sequences_match_a_boolean_model() {
    let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..200 {
        let mut guard = ReentrancyGuard::new();
        let mut model = false;
        for _ in 0..64 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            if (seed >> 33) & 1 == 0 {
                let result = guard.enter();
                if model {
                    assert_eq!(result, Err(ReentrancyError::ReentrantCall));
                } else {
                    assert_eq!(result, Ok(()));
                    model = true;
                }
            } else {
                guard.exit();
                model = false;
            }
            assert_eq!(guard.is_locked(), model);
        }
    }
}
