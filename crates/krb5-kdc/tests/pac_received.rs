//! PAC checksums over received bytes (MIT `pac.c` `verify_pac_checksums`).

use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, checksum};
use krb5_kdc::{
    Error, TEST_REALM, TEST_USER, bootstrap_documented, documented_host, sign_pac,
    ticket_checksum_der, verify_pac_signatures,
};
use krb5_protocol::{as_req, pa_enc_timestamp};
use krb5_types::ku;
use krb5_types::pac::{
    PAC_CLIENT_INFO, PAC_LOGON_INFO, PAC_PRIVSVR_CHECKSUM, PAC_SERVER_CHECKSUM, Pac, PacError,
    signature_buffer,
};
use krb5_types::{PrincipalName, err};

fn signed_as_pac() -> (Vec<u8>, ProtocolKey, ProtocolKey) {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user = store.get_name(&cname).unwrap().best_key().unwrap();
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        801,
        Some(vec![pa_enc_timestamp(&user.key).unwrap()]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &req).unwrap();
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let part = krb5_kdc::decrypt_ticket_part(&krbtgt.key, &as_out.rep.0.ticket).unwrap();
    let der = ticket_checksum_der(&part).unwrap();
    let ident = store.pac_identity(&cname, TEST_REALM);
    let host = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let signed = sign_pac(
        &cname,
        part.authtime.unix_seconds(),
        &host.key,
        &krbtgt.key,
        &der,
        &ident,
        None,
    )
    .unwrap();
    (signed, host.key.clone(), krbtgt.key.clone())
}

fn samba_member_key() -> ProtocolKey {
    ProtocolKey::from_bytes(
        EncryptionType::Rc4Hmac,
        b"\xD2\x17\xFA\xEA\xE5\xE6\xB5\xF9\x5C\xCC\x94\x07\x7A\xB8\xA5\xFC",
    )
    .unwrap()
}

fn samba_kdc_key() -> ProtocolKey {
    ProtocolKey::from_bytes(
        EncryptionType::Rc4Hmac,
        b"\xB2\x86\x75\x71\x48\xAF\x7F\xD2\x52\xC5\x36\x03\xA1\x50\xB7\xE7",
    )
    .unwrap()
}

fn s4u_srv_key() -> ProtocolKey {
    ProtocolKey::from_bytes(
        EncryptionType::Aes256CtsHmacSha196,
        b"\x14\xDF\xB5\xB2\xCD\xB4\x2C\x88\x94\xDA\x2F\xA8\x82\xE9\x72\x9F\x4A\x4D\xC7\x4B\xA0\x2A\x24\x2C\xC6\xA8\xD7\x10\x79\xB9\xAD\x9A",
    )
    .unwrap()
}

fn s4u_tgt_srv_key() -> ProtocolKey {
    ProtocolKey::from_bytes(
        EncryptionType::Aes256CtsHmacSha196,
        b"\x42\x0C\x39\xC5\x1A\x17\x54\x04\x45\x1F\x95\x6B\x8C\x58\xE0\xF4\x1B\xCA\x66\x9A\x64\x47\x95\xCA\x6E\x3A\xD5\x5A\x3B\x91\x8C\x9F",
    )
    .unwrap()
}

#[test]
fn accept_missing_privsvr_buffer_is_generic_60() {
    let (signed, server, kdc) = signed_as_pac();
    let mut parsed = Pac::parse(&signed).unwrap();
    parsed.buffers.retain(|b| b.kind != PAC_PRIVSVR_CHECKSUM);
    let out = parsed.to_bytes();
    match verify_pac_signatures(&out, &server, Some(&kdc), None) {
        Err(Error::Protocol { code, .. }) => assert_eq!(code, err::GENERIC),
        other => panic!("expected GENERIC 60, got {other:?}"),
    }
}

#[test]
fn accept_t_pac_saved_pac_verifies() {
    let bytes = include_bytes!("data/t_pac_saved.bin");
    let member = samba_member_key();
    let kdc = samba_kdc_key();
    verify_pac_signatures(bytes, &member, Some(&kdc), None).expect("t_pac saved_pac");
    let pac = Pac::parse(bytes).unwrap();
    let kinds: Vec<u32> = pac.buffers.iter().map(|b| b.kind).collect();
    assert_eq!(
        kinds,
        [
            PAC_LOGON_INFO,
            PAC_CLIENT_INFO,
            PAC_SERVER_CHECKSUM,
            PAC_PRIVSVR_CHECKSUM
        ]
    );
    let recoded = pac.to_bytes();
    if recoded.as_slice() != bytes.as_slice() {
        assert!(
            verify_pac_signatures(&recoded, &member, Some(&kdc), None).is_err(),
            "re-encode must not satisfy checksums over the received layout"
        );
    }
}

#[test]
fn accept_t_pac_s4u_pacs_verify_server_only() {
    let regular = (
        include_bytes!("data/t_pac_s4u_pac_regular.bin").as_slice(),
        false,
    );
    let enterprise = (
        include_bytes!("data/t_pac_s4u_pac_enterprise.bin").as_slice(),
        false,
    );
    let xrealm = (
        include_bytes!("data/t_pac_s4u_pac_xrealm.bin").as_slice(),
        true,
    );
    let ent_xrealm = (
        include_bytes!("data/t_pac_s4u_pac_ent_xrealm.bin").as_slice(),
        true,
    );
    for (bytes, xrealm) in [regular, enterprise, xrealm, ent_xrealm] {
        let server = if xrealm {
            s4u_tgt_srv_key()
        } else {
            s4u_srv_key()
        };
        verify_pac_signatures(bytes, &server, None, None).expect("t_pac s4u_pac");
    }
}

#[test]
fn accept_t_pac_fuzz_blobs_parse_or_truncate() {
    assert_eq!(
        Pac::parse(include_bytes!("data/t_pac_fuzz1.bin")),
        Err(PacError::Truncated)
    );
    assert_eq!(
        Pac::parse(include_bytes!("data/t_pac_fuzz2.bin")),
        Err(PacError::Truncated)
    );
}

#[test]
fn accept_wrong_server_key_still_checks_privsvr() {
    let (signed, server, kdc) = signed_as_pac();
    let mut wrong = server.as_bytes().to_vec();
    wrong[0] ^= 0xff;
    let wrong_key = ProtocolKey::from_bytes(server.etype(), &wrong).unwrap();
    verify_pac_signatures(&signed, &wrong_key, Some(&kdc), None)
        .expect("MIT overwrites a failed server checksum with a valid privsvr result");
}

#[test]
fn accept_noncanonical_buffer_order_still_verifies() {
    let (signed, server, kdc) = signed_as_pac();
    let mut parsed = Pac::parse(&signed).unwrap();
    parsed.buffers.swap(0, 1);
    let recoded = parsed.to_bytes();
    let recoded_pac = Pac::parse(&recoded).unwrap();
    let copy = recoded_pac.bytes_for_checksum();
    let usage = KeyUsage::new(ku::KERB_NON_KERB_CKSUM_SALT).unwrap();
    let server_mac = checksum(&server, usage, &copy).unwrap();
    let mut out_bufs = recoded_pac.buffers.clone();
    for b in &mut out_bufs {
        if b.kind == PAC_SERVER_CHECKSUM {
            b.data = signature_buffer(server.etype().checksum_type(), &server_mac);
        }
    }
    let privsvr_over = {
        let s = out_bufs
            .iter()
            .find(|b| b.kind == PAC_SERVER_CHECKSUM)
            .unwrap();
        checksum(&kdc, usage, &s.data[4..]).unwrap()
    };
    for b in &mut out_bufs {
        if b.kind == PAC_PRIVSVR_CHECKSUM {
            b.data = signature_buffer(kdc.etype().checksum_type(), &privsvr_over);
        }
    }
    let out = {
        let mut rebuilt = recoded_pac;
        rebuilt.buffers = out_bufs;
        rebuilt.to_bytes()
    };
    verify_pac_signatures(&out, &server, Some(&kdc), None)
        .expect("swapped buffer order still verifies");
}
