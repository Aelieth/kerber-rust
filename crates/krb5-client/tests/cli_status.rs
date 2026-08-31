//! Drive shipped klist -s / kinit argv (not a reimplementation).

use std::process::Command;

use krb5_client::cli::{check_ccache, parse_kinit, parse_klist};
use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_protocol::{CcacheCred, CcacheKeyblock, FileCcache, realm};
use krb5_types::PrincipalName;

#[test]
fn klist_s_missing_is_exit_1_silent() {
    let bin = env!("CARGO_BIN_EXE_krb5-klist");
    let out = Command::new(bin)
        .args(["-s", "-c", "/no/such/krb5cc_g8b_missing"])
        .output()
        .expect("spawn klist");
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty(), "stdout={:?}", out.stdout);
}

#[test]
fn klist_s_live_tgt_is_exit_0_silent() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(0));
    let cred = sample(now + 3600, PrincipalName::krbtgt("KERBER.TEST"));
    let cc = FileCcache::new(cred.client.clone(), vec![cred]);
    let path = std::env::temp_dir().join(format!("krb5cc-klist-s-{}-{}", std::process::id(), now));
    cc.write_file(&path).unwrap();
    let bin = env!("CARGO_BIN_EXE_krb5-klist");
    let out = Command::new(bin)
        .args(["-s", "-c", path.to_str().unwrap()])
        .output()
        .expect("spawn klist");
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.is_empty(), "stdout={:?}", out.stdout);
}

#[test]
fn kinit_kt_cluster_parses_as_keytab() {
    let a = parse_kinit(&[
        "-kt".into(),
        "/tmp/user.keytab".into(),
        "user@KERBER.TEST".into(),
    ])
    .unwrap();
    assert!(a.keytab);
    assert_eq!(a.keytab_path.as_deref(), Some("/tmp/user.keytab"));
}

#[test]
fn klist_fe_cluster_parses() {
    let a = parse_klist(&["-fe".into()]).unwrap();
    assert!(a.flags && a.etype);
}

#[test]
fn check_ccache_expired_tgt_beats_live_service() {
    let now = 1_700_100_000;
    let dead = sample(now - 1, PrincipalName::krbtgt("KERBER.TEST"));
    let live = sample(
        now + 100,
        PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc"]),
    );
    let cc = FileCcache::new(dead.client.clone(), vec![dead, live]);
    assert_eq!(check_ccache(&cc, now), 1);
}

fn sample(end: u32, server: PrincipalName) -> CcacheCred {
    let r = realm("KERBER.TEST");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    let key = ProtocolKey::from_bytes(EncryptionType::Aes128CtsHmacSha196, &[0u8; 16]).unwrap();
    CcacheCred {
        client: (r.clone(), user),
        server: (r, server),
        key: CcacheKeyblock::from_protocol(&key),
        authtime: 1_700_000_000,
        starttime: 1_700_000_000,
        endtime: end,
        renew_till: 0,
        is_skey: 0,
        ticket_flags: 0,
        addresses: Vec::new(),
        authdata: Vec::new(),
        ticket: Vec::new(),
        second_ticket: Vec::new(),
    }
}
