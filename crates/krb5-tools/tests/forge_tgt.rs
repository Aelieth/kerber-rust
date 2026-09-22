//! `krb5-forge-tgt` decrypts a profile-first TGT. This package owns
//! the bin, so Cargo sets `CARGO_BIN_EXE_krb5-forge-tgt`.

use krb5_asn1::decode_enc_kdc_rep_part;
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt};
use krb5_kdc::testrealm::{
    TEST_ADMIN, TEST_ADMIN_PASSWORD, TEST_REALM, TEST_USER, TEST_USER_PASSWORD,
};
use krb5_protocol::{as_req, pa_enc_timestamp};
use krb5_types::{PrincipalName, ku};

#[test]
fn tgt_hex_must_use_ticket_etype_not_preferred() {
    let kdc = krb5_config::KdcConf::parse(
        r"
[realms]
    KERBER.TEST = {
        supported_enctypes = aes256-cts-hmac-sha384-192:normal aes128-cts-hmac-sha256-128:normal aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
    }
",
    )
    .unwrap();
    let store = krb5_kdc::PrincipalStore::bootstrap_with_kdc_conf(
        TEST_REALM,
        TEST_USER,
        TEST_USER_PASSWORD,
        TEST_ADMIN,
        TEST_ADMIN_PASSWORD,
        Some(&kdc),
    )
    .unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = as_req(
        user,
        TEST_REALM,
        1920,
        Some(vec![pa_enc_timestamp(&user_key).unwrap()]),
    )
    .unwrap();
    let tgt = krb5_kdc::issue_as(&store, &req).unwrap();
    assert_eq!(tgt.rep.0.ticket.enc_part.etype, 20);
    let first = store.krbtgt().unwrap().first_current_key().unwrap();
    assert_eq!(first.etype.to_iana(), 20);
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let as18 =
        ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, first.key.as_bytes()).unwrap();
    assert!(
        decrypt(&as18, usage, tgt.rep.0.ticket.enc_part.cipher.as_ref()).is_err(),
        "etype-20 TGT is not decryptable as preferred etype 18"
    );
    decrypt(&first.key, usage, tgt.rep.0.ticket.enc_part.cipher.as_ref()).unwrap();

    let as_usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let enc_plain = decrypt(
        &tgt.as_rep_key,
        as_usage,
        tgt.rep.0.enc_part.cipher.as_ref(),
    )
    .unwrap();
    let enc = decode_enc_kdc_rep_part(&enc_plain).unwrap();
    let cred = krb5_protocol::tgt_cred(
        &tgt.rep.0.crealm,
        &tgt.rep.0.cname,
        &tgt.rep.0.ticket,
        &tgt.session_key,
        &enc,
    )
    .unwrap();
    let cc = krb5_protocol::FileCcache::new(
        (tgt.rep.0.crealm.clone(), tgt.rep.0.cname.clone()),
        vec![cred],
    );
    let scratch = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("CARGO_TARGET_DIR")
                .map(|p| std::path::PathBuf::from(p).join("test-krb5"))
        })
        .or_else(|| std::env::var_os("KERBER_SCRATCH").map(std::path::PathBuf::from))
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/test-krb5")
        });
    let dir = scratch.join(format!("a4-19-forge-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let in_cc = dir.join("in.cc");
    let out_cc = dir.join("out.cc");
    cc.write_file(&in_cc).unwrap();
    let mut hex = String::with_capacity(first.key.as_bytes().len() * 2);
    for &b in first.key.as_bytes() {
        hex.push(char::from(b"0123456789abcdef"[(b >> 4) as usize]));
        hex.push(char::from(b"0123456789abcdef"[(b & 0x0f) as usize]));
    }
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_krb5-forge-tgt"))
        .args([
            "--ccache",
            in_cc.to_str().unwrap(),
            "--out",
            out_cc.to_str().unwrap(),
            "--tgt",
            "krbtgt/KERBER.TEST",
            "--claim-realm",
            "B.TEST",
            "--key-hex",
            &hex,
        ])
        .status()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        status.success(),
        "forge-tgt must decrypt a profile-first (etype 20) TGT"
    );
}
