#![allow(unexpected_cfgs)]

use propchain_traits::{ReentrancyError, ReentrancyGuard};

#[test]
fn reentrant_enter_returns_the_typed_error() {
    let mut guard = ReentrancyGuard::new();
    guard.enter().expect("first enter");
    assert_eq!(guard.enter(), Err(ReentrancyError::ReentrantCall));
}

#[test]
fn error_has_a_stable_debug_name() {
    assert_eq!(format!("{:?}", ReentrancyError::ReentrantCall), "ReentrantCall");
}

#[test]
fn exit_without_enter_leaves_the_guard_unlocked() {
    let mut guard = ReentrancyGuard::new();
    guard.exit();
    assert!(!guard.is_locked());
}

#[test]
fn repeated_exit_is_idempotent() {
    let mut guard = ReentrancyGuard::new();
    guard.enter().expect("enter");
    guard.exit();
    guard.exit();
    assert!(!guard.is_locked());
    assert!(guard.enter().is_ok());
}

#[test]
fn default_guard_is_unlocked() {
    assert!(!ReentrancyGuard::default().is_locked());
}
