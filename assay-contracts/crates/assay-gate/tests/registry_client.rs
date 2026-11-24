//! Cross-crate tests: register the real registry contract and call every
//! read-only entrypoint through the `assay-gate` client. A signature or
//! `Quorum` shape that drifts from the registry fails here at runtime.

use assay_gate::{Quorum, SafetyRegistryClient, MAX_ATTESTORS};
use assay_safety_registry::{SafetyRegistry as Registry, SafetyRegistryClient as RealClient};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    vec, Address, BytesN, Env, Vec,
};

const AUTH_REVOCABLE: u32 = 1 << 1;
const NOW: u64 = 1_000_000;

struct Fixture<'a> {
    env: Env,
    admin: Address,
    asset: Address,
    real: RealClient<'a>,
    gate: SafetyRegistryClient<'a>,
}

fn setup<'a>() -> Fixture<'a> {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(NOW);
    let id = env.register(Registry, ());
    let admin = Address::generate(&env);
    let asset = Address::generate(&env);
    let real = RealClient::new(&env, &id);
    let gate = SafetyRegistryClient::new(&env, &id);
    real.init(&admin);
    Fixture {
        env,
        admin,
        asset,
        real,
        gate,
    }
}

fn hash(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[7u8; 32])
}

#[test]
fn admin_and_pending_admin() {
    let f = setup();
    assert_eq!(f.gate.admin(), Some(f.admin.clone()));
    assert_eq!(f.gate.pending_admin(), None);
    let next = Address::generate(&f.env);
    f.real.transfer_admin(&next);
    assert_eq!(f.gate.pending_admin(), Some(next));
    assert_eq!(f.gate.admin(), Some(f.admin.clone()));
}

#[test]
fn version_matches_registry() {
    let f = setup();
    assert_eq!(f.gate.version(), f.real.version());
}

#[test]
fn get_safety_and_is_safe() {
    let f = setup();
    assert_eq!(f.gate.get_safety(&f.asset), None);
    assert!(!f.gate.is_safe(&f.asset, &4, &0));
    f.real.attest(&f.asset, &2, &AUTH_REVOCABLE, &hash(&f.env));
    let s = f.gate.get_safety(&f.asset).unwrap();
    assert_eq!(s.severity, 2);
    assert_eq!(s.flags, AUTH_REVOCABLE);
    assert_eq!(s.evidence_hash, hash(&f.env));
    assert_eq!(s.attested_at, NOW);
    assert!(f.gate.is_safe(&f.asset, &2, &0));
    assert!(!f.gate.is_safe(&f.asset, &1, &0));
}

#[test]
fn get_safety_many_preserves_order_and_missing() {
    let f = setup();
    let other = Address::generate(&f.env);
    f.real.attest(&f.asset, &1, &0, &hash(&f.env));
    let out = f
        .gate
        .get_safety_many(&vec![&f.env, other.clone(), f.asset.clone()]);
    assert_eq!(out.len(), 2);
    assert_eq!(out.get(0).unwrap(), None);
    assert_eq!(out.get(1).unwrap().unwrap().severity, 1);
    assert_eq!(f.gate.get_safety_many(&Vec::new(&f.env)).len(), 0);
}

#[test]
fn get_safety_many_over_bound_fails() {
    let f = setup();
    let mut assets = Vec::new(&f.env);
    for _ in 0..51 {
        assets.push_back(Address::generate(&f.env));
    }
    assert!(f.gate.try_get_safety_many(&assets).is_err());
}

#[test]
fn is_safe_masked_branches() {
    let f = setup();
    assert!(!f.gate.is_safe_masked(&f.asset, &0, &0)); // unattested fails closed
    f.real.attest(&f.asset, &2, &AUTH_REVOCABLE, &hash(&f.env));
    assert!(!f.gate.is_safe_masked(&f.asset, &AUTH_REVOCABLE, &0)); // forbidden bit
    assert!(f.gate.is_safe_masked(&f.asset, &(1 << 2), &0)); // bit not set
    f.env.ledger().set_timestamp(NOW + 100);
    assert!(f.gate.is_safe_masked(&f.asset, &0, &0)); // 0 disables freshness
    assert!(!f.gate.is_safe_masked(&f.asset, &0, &50)); // stale
}

#[test]
fn get_attestation_reads_admin_legacy_entry() {
    let f = setup();
    let stranger = Address::generate(&f.env);
    assert_eq!(f.gate.get_attestation(&f.admin, &f.asset), None);
    f.real.attest(&f.asset, &3, &(1 << 2), &hash(&f.env));
    let s = f.gate.get_attestation(&f.admin, &f.asset).unwrap();
    assert_eq!(s.severity, 3);
    assert_eq!(f.gate.get_attestation(&stranger, &f.asset), None);
}

#[test]
fn quorum_met_unavailable_and_invalid_threshold() {
    let f = setup();
    let stranger = Address::generate(&f.env);
    f.real.attest(&f.asset, &1, &0, &hash(&f.env));
    let one = vec![&f.env, f.admin.clone()];
    match f.gate.quorum(&f.asset, &one, &1, &0) {
        Quorum::Met(s) => {
            assert_eq!(s.severity, 1);
            assert_eq!(s.attested_at, NOW);
        }
        other => panic!("expected Met, got {other:?}"),
    }
    let two = vec![&f.env, f.admin.clone(), stranger];
    assert_eq!(
        f.gate.quorum(&f.asset, &two, &2, &0),
        Quorum::Unavailable(1)
    );
    assert_eq!(
        f.gate.quorum(&f.asset, &one, &0, &0),
        Quorum::InvalidArguments
    );
}

#[test]
fn quorum_rejects_more_than_max_attestors() {
    let f = setup();
    f.real.attest(&f.asset, &1, &0, &hash(&f.env));
    let mut many = Vec::new(&f.env);
    many.push_back(f.admin.clone());
    for _ in 0..MAX_ATTESTORS {
        many.push_back(Address::generate(&f.env));
    }
    assert_eq!(many.len(), MAX_ATTESTORS + 1);
    assert_eq!(
        f.gate.quorum(&f.asset, &many, &1, &0),
        Quorum::InvalidArguments
    );
    assert!(!f.gate.is_safe_quorum(&f.asset, &many, &1, &4, &0));
}

#[test]
fn is_safe_quorum_branches() {
    let f = setup();
    let stranger = Address::generate(&f.env);
    let one = vec![&f.env, f.admin.clone()];
    assert!(!f.gate.is_safe_quorum(&f.asset, &one, &1, &4, &0)); // unattested
    f.real.attest(&f.asset, &2, &0, &hash(&f.env));
    assert!(f.gate.is_safe_quorum(&f.asset, &one, &1, &2, &0));
    assert!(!f.gate.is_safe_quorum(&f.asset, &one, &1, &1, &0)); // too severe
    let two = vec![&f.env, f.admin.clone(), stranger];
    assert!(!f.gate.is_safe_quorum(&f.asset, &two, &2, &4, &0)); // quorum short
}
