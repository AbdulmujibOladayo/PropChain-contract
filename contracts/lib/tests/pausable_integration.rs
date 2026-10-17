#![allow(unexpected_cfgs)]
#![allow(clippy::clone_on_copy)]

//! Integration and invariant tests for the pause flow.

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
fn pause_blocks_state_changes_until_resumed() {
    let mut contract = PropertyRegistry::new();
    contract.pause_contract("Incident".into(), None).expect("admin can pause");
    assert!(contract.get_pause_state().paused);
    assert_eq!(contract.register_property(metadata()), Err(Error::ContractPaused));

    contract.request_resume().expect("resume can be requested");
    let guardian = AccountId::from([0x22u8; 32]);
    test::set_caller::<DefaultEnvironment>(contract.admin());
    contract.set_pause_guardian(guardian, true).expect("admin can add a guardian");
    test::set_caller::<DefaultEnvironment>(guardian);
    contract.approve_resume().expect("second approval resumes");

    assert!(!contract.get_pause_state().paused);
    assert!(contract.register_property(metadata()).is_ok());
}

#[ink::test]
fn invariant_second_pause_is_rejected_and_state_is_unchanged() {
    let mut contract = PropertyRegistry::new();
    contract.pause_contract("first".into(), None).expect("admin can pause");
    let before = contract.get_pause_state();

    assert_eq!(contract.pause_contract("second".into(), None), Err(Error::AlreadyPaused));

    let after = contract.get_pause_state();
    assert_eq!(before.paused_at, after.paused_at);
    assert_eq!(before.reason, after.reason);
}

#[ink::test]
fn invariant_non_privileged_caller_cannot_pause() {
    let mut contract = PropertyRegistry::new();
    test::set_caller::<DefaultEnvironment>(AccountId::from([0x77u8; 32]));
    assert_eq!(
        contract.pause_contract("nope".into(), None),
        Err(Error::NotAuthorizedToPause)
    );
    assert!(!contract.get_pause_state().paused);
}
