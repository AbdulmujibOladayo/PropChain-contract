#![allow(unexpected_cfgs)]
#![allow(clippy::clone_on_copy)]

//! Validation and error tests for `pause_contract`.

use ink::env::{test, DefaultEnvironment};
use ink::primitives::AccountId;
use propchain_contracts::propchain_contracts::{Error, PropertyRegistry};
use propchain_traits::PropertyMetadata;

fn metadata() -> PropertyMetadata {
    PropertyMetadata {
        location: "Pausable Street".into(),
        size: 100,
        legal_description: "Pausable test asset".into(),
        valuation: 1_000,
        documents_url: "ipfs://pausable".into(),
    }
}

#[ink::test]
fn duration_below_minimum_is_rejected() {
    let mut contract = PropertyRegistry::new();
    assert_eq!(
        contract.pause_contract("short".into(), Some(1)),
        Err(Error::ValueOutOfBounds)
    );
    assert!(!contract.get_pause_state().paused);
}

#[ink::test]
fn duration_above_maximum_is_rejected() {
    let mut contract = PropertyRegistry::new();
    assert_eq!(
        contract.pause_contract("long".into(), Some(u64::MAX)),
        Err(Error::ValueOutOfBounds)
    );
    assert!(!contract.get_pause_state().paused);
}

#[ink::test]
fn valid_duration_sets_an_auto_resume_time() {
    let mut contract = PropertyRegistry::new();
    contract.pause_contract("window".into(), Some(3_600)).expect("valid duration");
    let state = contract.get_pause_state();
    assert!(state.paused);
    assert!(state.auto_resume_at.is_some());
}

#[ink::test]
fn oversized_reason_is_rejected() {
    let mut contract = PropertyRegistry::new();
    let reason: String = "x".repeat(2_001);
    assert!(contract.pause_contract(reason, None).is_err());
    assert!(!contract.get_pause_state().paused);
}

#[ink::test]
fn unauthorized_pause_returns_a_typed_error() {
    let mut contract = PropertyRegistry::new();
    test::set_caller::<DefaultEnvironment>(AccountId::from([0x66u8; 32]));
    assert_eq!(
        contract.pause_contract("x".into(), None),
        Err(Error::NotAuthorizedToPause)
    );
}
