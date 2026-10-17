#![allow(unexpected_cfgs)]
#![allow(clippy::clone_on_copy)]

//! Unit and fuzz-style tests for the pause flow.

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
fn unit_initial_state_is_not_paused() {
    let contract = PropertyRegistry::new();
    assert!(!contract.get_pause_state().paused);
    assert!(contract.ensure_not_paused().is_ok());
}

#[ink::test]
fn unit_pause_sets_reason_and_pauser() {
    let mut contract = PropertyRegistry::new();
    contract.pause_contract("maintenance".into(), None).expect("admin can pause");
    let state = contract.get_pause_state();
    assert!(state.paused);
    assert_eq!(state.reason, Some("maintenance".into()));
    assert!(state.paused_by.is_some());
    assert!(contract.ensure_not_paused().is_err());
}

#[ink::test]
fn unit_emergency_pause_then_pause_is_rejected() {
    let mut contract = PropertyRegistry::new();
    contract.emergency_pause("breach".into()).expect("admin can emergency pause");
    assert_eq!(contract.pause_contract("again".into(), None), Err(Error::AlreadyPaused));
}

#[ink::test]
fn fuzz_many_unprivileged_callers_can_never_pause() {
    let mut contract = PropertyRegistry::new();
    for i in 0x10u8..0x60u8 {
        test::set_caller::<DefaultEnvironment>(AccountId::from([i; 32]));
        assert_eq!(
            contract.pause_contract("fuzz".into(), None),
            Err(Error::NotAuthorizedToPause)
        );
    }
    assert!(!contract.get_pause_state().paused);
}
