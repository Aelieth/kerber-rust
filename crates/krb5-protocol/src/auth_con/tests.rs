use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt};
use krb5_types::{
    ApRep, Authenticator, AuthorizationDataValue, EncApRepPart, EncKrbPrivPart, EncTicketPart,
    EncryptionKey, KerberosTime, KrbPriv, Microseconds, PrincipalName, TicketFlags,
    TransitedEncoding, ku, pa,
};

use super::{
    AUTH_CONTEXT_DO_SEQUENCE, AUTH_CONTEXT_USE_SUBKEY, AcceptorAuthContext, generate_seq_number,
    local_host_address,
};
use crate::ap_req::ApVerifyOk;
use crate::error::Error;
use crate::safe_priv::wiped;

const AES256: EncryptionType = EncryptionType::Aes256CtsHmacSha196;
const AES256_SHA2: EncryptionType = EncryptionType::Aes256CtsHmacSha384192;

fn enc_key(k: &ProtocolKey) -> EncryptionKey {
    EncryptionKey {
        keytype: k.etype().to_iana(),
        keyvalue: k.as_bytes().to_vec().into(),
    }
}

/// An accepted AP-REQ as `verify_ap_req_ex` returns it: an aes256-cts session key, the
/// authenticator's own subkey and sequence number, and its authorization data.
fn accepted(
    session: &ProtocolKey,
    subkey: Option<&ProtocolKey>,
    seq: Option<u32>,
    mutual: bool,
    authdata: Option<Vec<AuthorizationDataValue>>,
) -> ApVerifyOk {
    let realm = krb5_types::try_ascii("KERBER.TEST").unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    let now = KerberosTime::now();
    ApVerifyOk {
        ticket_part: EncTicketPart {
            flags: TicketFlags::initial_preauth(),
            key: enc_key(session),
            crealm: realm.clone(),
            cname: cname.clone(),
            transited: TransitedEncoding::empty(),
            authtime: now.clone(),
            starttime: None,
            endtime: now.add_hours(1).unwrap(),
            renew_till: None,
            caddr: None,
            authorization_data: None,
        },
        sname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["kadmin", "changepw"]),
        srealm: realm.clone(),
        authenticator: Authenticator {
            authenticator_vno: Authenticator::VNO,
            crealm: realm,
            cname,
            cksum: None,
            cusec: Microseconds::from_subsec_micros(306_250),
            ctime: now,
            subkey: subkey.map(enc_key),
            seq_number: seq,
            authorization_data: authdata,
        },
        mutual_required: mutual,
        ticket_etype: AES256.to_iana(),
    }
}

fn etype_negotiation(list: &[i32]) -> Vec<AuthorizationDataValue> {
    let inner = vec![AuthorizationDataValue {
        ad_type: pa::AD_ETYPE_NEGOTIATION,
        ad_data: encode(&list.to_vec()).unwrap().into(),
    }];
    vec![AuthorizationDataValue {
        ad_type: pa::AD_IF_RELEVANT,
        ad_data: encode(&inner).unwrap().into(),
    }]
}

fn rep_part(rep: &ApRep, session: &ProtocolKey) -> EncApRepPart {
    let usage = KeyUsage::new(ku::AP_REP_ENC_PART).unwrap();
    decode(&decrypt(session, usage, rep.enc_part.cipher.as_ref()).unwrap()).unwrap()
}

fn priv_part(msg: &KrbPriv, key: &ProtocolKey) -> EncKrbPrivPart {
    let usage = KeyUsage::new(ku::KRB_PRIV_ENC_PART).unwrap();
    decode(&decrypt(key, usage, msg.enc_part.cipher.as_ref()).unwrap()).unwrap()
}

const DEFAULT_LIST: [EncryptionType; 4] = [
    EncryptionType::Aes256CtsHmacSha196,
    EncryptionType::Aes128CtsHmacSha196,
    EncryptionType::Aes256CtsHmacSha384192,
    EncryptionType::Aes128CtsHmacSha256128,
];

#[test]
fn kpasswd_shaped_ap_rep_echoes_the_subkey_with_a_fresh_seq() {
    let session = ProtocolKey::random(AES256).unwrap();
    let subkey = ProtocolKey::random(AES256).unwrap();
    let ok = accepted(&session, Some(&subkey), None, false, None);
    let mut ac = AcceptorAuthContext::from_ap_req(&ok, &DEFAULT_LIST).unwrap();
    ac.set_flags(AUTH_CONTEXT_DO_SEQUENCE);
    let part = rep_part(&ac.mk_rep().unwrap(), &session);
    assert_eq!(part.ctime, ok.authenticator.ctime);
    assert_eq!(part.cusec.get(), ok.authenticator.cusec.get());
    assert_eq!(
        part.subkey,
        Some(enc_key(&subkey)),
        "the authenticator's own subkey"
    );
    let seq = part.seq_number.unwrap();
    assert!(seq != 0 && seq < 1 << 30, "a fresh 30-bit seq, got {seq}");
    assert_eq!(seq, ac.local_seq());
    assert_eq!(
        ac.send_subkey().map(ProtocolKey::as_bytes),
        Some(subkey.as_bytes())
    );
}

#[test]
fn use_subkey_ap_rep_carries_a_fresh_key_of_the_negotiated_etype() {
    let session = ProtocolKey::random(AES256).unwrap();
    let subkey = ProtocolKey::random(AES256).unwrap();
    let ok = accepted(&session, Some(&subkey), Some(864_518_167), true, None);
    let mut ac = AcceptorAuthContext::from_ap_req(&ok, &DEFAULT_LIST).unwrap();
    ac.set_flags(AUTH_CONTEXT_DO_SEQUENCE | AUTH_CONTEXT_USE_SUBKEY);
    let part = rep_part(&ac.mk_rep().unwrap(), &session);
    let fresh = part.subkey.unwrap();
    assert_eq!(fresh.keytype, AES256.to_iana());
    assert_ne!(
        fresh.keyvalue.as_ref(),
        subkey.as_bytes(),
        "not the initiator's"
    );
    assert_eq!(
        Some(fresh.keyvalue.as_ref()),
        ac.send_subkey().map(ProtocolKey::as_bytes)
    );
    assert_eq!(
        Some(fresh.keyvalue.as_ref()),
        ac.recv_subkey().map(ProtocolKey::as_bytes)
    );
    let seq = part.seq_number.unwrap();
    assert!(seq != 0 && seq < 1 << 30);
    assert_ne!(seq, 864_518_167, "not the authenticator's seq");
}

#[test]
fn rfc4537_list_negotiates_the_first_permitted_enctype() {
    let session = ProtocolKey::random(AES256).unwrap();
    let subkey = ProtocolKey::random(AES256).unwrap();
    let ad = etype_negotiation(&[20, 19, 18]);
    let ok = accepted(&session, Some(&subkey), Some(1), true, Some(ad));
    let sha2_first = [
        AES256_SHA2,
        EncryptionType::Aes128CtsHmacSha256128,
        AES256,
        EncryptionType::Aes128CtsHmacSha196,
    ];
    let mut ac = AcceptorAuthContext::from_ap_req(&ok, &sha2_first).unwrap();
    assert_eq!(ac.negotiated_etype(), AES256_SHA2);
    assert!(ac.ap_req_use_subkey());
    ac.set_flags(AUTH_CONTEXT_DO_SEQUENCE | AUTH_CONTEXT_USE_SUBKEY);
    let part = rep_part(&ac.mk_rep().unwrap(), &session);
    assert_eq!(part.subkey.unwrap().keytype, AES256_SHA2.to_iana());
    let sha1_first = AcceptorAuthContext::from_ap_req(&ok, &DEFAULT_LIST).unwrap();
    assert_eq!(sha1_first.negotiated_etype(), AES256);
    assert!(!sha1_first.ap_req_use_subkey());
}

#[test]
fn a_session_key_the_acceptor_does_not_permit_is_noperm_etype() {
    let session = ProtocolKey::random(AES256).unwrap();
    let ok = accepted(&session, None, None, true, None);
    let only_aes128 = [EncryptionType::Aes128CtsHmacSha196];
    let err = AcceptorAuthContext::from_ap_req(&ok, &only_aes128).unwrap_err();
    assert_eq!(
        err.to_string(),
        "Encryption type aes256-cts-hmac-sha1-96 not permitted"
    );
    assert!(matches!(err, Error::NopermEtype(_)));
}

#[test]
fn an_etype_list_that_does_not_decode_fails_the_request() {
    let session = ProtocolKey::random(AES256).unwrap();
    let ad = vec![AuthorizationDataValue {
        ad_type: pa::AD_ETYPE_NEGOTIATION,
        ad_data: vec![0x30, 0x05, 0x02].into(),
    }];
    let ok = accepted(&session, None, None, true, Some(ad));
    assert!(matches!(
        AcceptorAuthContext::from_ap_req(&ok, &DEFAULT_LIST),
        Err(Error::Asn1(_))
    ));
}

#[test]
fn reply_krb_priv_has_no_timestamp_and_advances_the_seq() {
    let session = ProtocolKey::random(AES256).unwrap();
    let subkey = ProtocolKey::random(AES256).unwrap();
    let ok = accepted(&session, Some(&subkey), None, false, None);
    let mut ac = AcceptorAuthContext::from_ap_req(&ok, &DEFAULT_LIST).unwrap();
    ac.set_flags(AUTH_CONTEXT_DO_SEQUENCE);
    let seq = rep_part(&ac.mk_rep().unwrap(), &session)
        .seq_number
        .unwrap();
    let laddr = local_host_address(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 177, 10))));
    let first = priv_part(&ac.mk_priv(&[0, 0], &laddr, None).unwrap(), &subkey);
    assert_eq!(first.user_data.as_ref(), &[0, 0]);
    assert_eq!(first.timestamp, None);
    assert_eq!(first.usec, None);
    assert_eq!(first.seq_number, Some(seq), "the AP-REP's seq");
    assert_eq!(first.s_address, laddr);
    assert_eq!(first.r_address, None);
    let second = priv_part(&ac.mk_priv(b"x", &laddr, None).unwrap(), &subkey);
    assert_eq!(second.seq_number, Some(seq.wrapping_add(1)));
}

#[test]
fn without_mutual_the_local_seq_is_the_peers() {
    let session = ProtocolKey::random(AES256).unwrap();
    let ok = accepted(&session, None, Some(77), false, None);
    let mut ac = AcceptorAuthContext::from_ap_req(&ok, &DEFAULT_LIST).unwrap();
    assert_eq!(ac.local_seq(), 77);
    ac.set_flags(AUTH_CONTEXT_DO_SEQUENCE);
    let part = rep_part(&ac.mk_rep().unwrap(), &session);
    assert_eq!(part.seq_number, Some(77));
    assert_eq!(part.subkey, None);
}

#[test]
fn generated_seq_numbers_are_thirty_bits_and_never_zero() {
    for _ in 0..256 {
        let n = generate_seq_number().unwrap();
        assert!(n != 0 && n < 1 << 30, "{n}");
    }
}

#[test]
fn local_host_address_is_k5_sockaddr_to_address() {
    let v4 = local_host_address(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    assert_eq!(
        (v4.addr_type, v4.address.as_ref()),
        (2, &[127, 0, 0, 1][..])
    );
    let mapped = local_host_address(Some(IpAddr::V6(
        Ipv4Addr::new(10, 1, 2, 3).to_ipv6_mapped(),
    )));
    assert_eq!(
        (mapped.addr_type, mapped.address.as_ref()),
        (2, &[10, 1, 2, 3][..])
    );
    let v6 = local_host_address(Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    assert_eq!(v6.addr_type, 24);
    assert_eq!(v6.address.as_ref(), Ipv6Addr::LOCALHOST.octets());
    let none = local_host_address(None);
    assert_eq!(
        (none.addr_type, none.address.as_ref()),
        (3, &[0, 0, 0, 1][..])
    );
}

#[test]
fn a_permitted_session_key_with_a_subkey_outside_the_list_is_noperm_etype() {
    let session = ProtocolKey::random(AES256).unwrap();
    let subkey = ProtocolKey::random(EncryptionType::Aes128CtsHmacSha196).unwrap();
    let ok = accepted(&session, Some(&subkey), None, true, None);
    let err = AcceptorAuthContext::from_ap_req(&ok, &[AES256]).unwrap_err();
    assert_eq!(
        err.to_string(),
        "Encryption type aes128-cts-hmac-sha1-96 not permitted"
    );
}

#[test]
fn the_kdc_profile_libdefaults_come_before_krb5_conf() {
    use krb5_config::{KdcConf, Krb5Conf};

    let krb5 =
        Krb5Conf::parse("[libdefaults]\n permitted_enctypes = aes128-cts-hmac-sha1-96\n").unwrap();
    let kdc_sets =
        KdcConf::parse("[libdefaults]\n permitted_enctypes = aes256-cts-hmac-sha1-96\n").unwrap();
    let kdc_silent = KdcConf::parse("[kdcdefaults]\n kdc_ports = 88\n").unwrap();
    let iana = |r: Result<Vec<EncryptionType>, Error>| -> Vec<i32> {
        r.unwrap().iter().map(|e| e.to_iana()).collect()
    };
    let first = super::permitted_enctypes_in(Some(&kdc_sets), Some(&krb5));
    assert_eq!(iana(first), [18], "kdc.conf's [libdefaults] wins");
    let fallback = super::permitted_enctypes_in(Some(&kdc_silent), Some(&krb5));
    assert_eq!(iana(fallback), [17], "else krb5.conf's");
    let plain = super::permitted_enctypes_in(None, Some(&krb5));
    assert_eq!(iana(plain), [17]);
    let neither = super::permitted_enctypes_in(None, None);
    assert_eq!(
        iana(neither),
        [18, 17, 20, 19, 16, 23, 25, 26],
        "MIT's DEFAULT"
    );
}

#[test]
fn a_krb_priv_under_do_time_carries_the_time_to_the_microsecond() {
    let session = ProtocolKey::random(AES256).unwrap();
    let ok = accepted(&session, None, None, true, None);
    let mut ac = AcceptorAuthContext::from_ap_req(&ok, &DEFAULT_LIST).unwrap();
    ac.set_flags(super::AUTH_CONTEXT_DO_TIME);
    let laddr = local_host_address(None);
    let part = priv_part(&ac.mk_priv(b"t", &laddr, None).unwrap(), &session);
    let sent = part.timestamp.unwrap().unix_seconds();
    let now = KerberosTime::now().unix_seconds();
    assert!(now.abs_diff(sent) <= 2, "timestamp {sent}, now {now}");
    assert!(part.usec.is_some());
    assert_eq!(part.seq_number, None, "no DO_SEQUENCE, no seq-number");
}

#[test]
fn mk_rep_zeroes_the_encoded_part_it_encrypted() {
    let session = ProtocolKey::random(AES256).unwrap();
    let subkey = ProtocolKey::random(AES256).unwrap();
    let ok = accepted(&session, Some(&subkey), Some(864_518_167), true, None);
    let mut ac = AcceptorAuthContext::from_ap_req(&ok, &DEFAULT_LIST).unwrap();
    ac.set_flags(AUTH_CONTEXT_DO_SEQUENCE | AUTH_CONTEXT_USE_SUBKEY);
    wiped::take();
    let rep = ac.mk_rep().unwrap();
    let zeroed = wiped::take();
    let plain = encode(&rep_part(&rep, &session)).unwrap();
    assert_eq!(
        zeroed.len(),
        1,
        "the encoded EncAPRepPart, fresh subkey and all"
    );
    assert!(zeroed[0].len() >= plain.len(), "the whole allocation");
    assert!(zeroed[0].iter().all(|b| *b == 0));
}

#[test]
fn mk_priv_zeroes_its_encoded_part_and_its_copy_of_the_user_data() {
    let session = ProtocolKey::random(AES256).unwrap();
    let subkey = ProtocolKey::random(AES256).unwrap();
    let ok = accepted(&session, Some(&subkey), None, false, None);
    let mut ac = AcceptorAuthContext::from_ap_req(&ok, &DEFAULT_LIST).unwrap();
    ac.set_flags(AUTH_CONTEXT_DO_SEQUENCE);
    let laddr = local_host_address(None);
    let secret = b"scratch-new-password";
    wiped::take();
    let msg = ac.mk_priv(secret, &laddr, None).unwrap();
    let zeroed = wiped::take();
    let plain = encode(&priv_part(&msg, &subkey)).unwrap();
    assert_eq!(
        zeroed.len(),
        2,
        "the user data's copy, then the encoded EncKrbPrivPart"
    );
    assert!(zeroed.iter().all(|w| w.iter().all(|b| *b == 0)));
    assert!(zeroed[0].len() >= secret.len() && zeroed[1].len() >= plain.len());
}

#[test]
fn generated_seq_numbers_keep_thirty_of_the_random_bits() {
    for (raw, want) in [
        (0xffff_ffff, 0x3fff_ffff),
        (0x1234_5678, 0x1234_5678),
        (0x4000_0001, 1),
        (0xc000_0000, 1),
    ] {
        super::set_test_seq_random(Some(raw));
        assert_eq!(generate_seq_number().unwrap(), want, "{raw:#x}");
    }
    super::set_test_seq_random(None);
}

#[test]
fn the_kdc_profile_a_test_pins_is_the_one_read() {
    let kdc = krb5_testkit::scratch_dir("p15a-kdc-profile").join("kdc.conf");
    std::fs::write(
        &kdc,
        "[libdefaults]\n permitted_enctypes = aes128-cts-hmac-sha1-96\n",
    )
    .unwrap();
    let iana = |v: Vec<EncryptionType>| -> Vec<i32> { v.iter().map(|e| e.to_iana()).collect() };
    krb5_config::isolate_test_krb5();
    assert_eq!(
        iana(super::permitted_enctypes_kdc().unwrap()),
        [18, 17, 20, 19, 16, 23, 25, 26],
        "the isolation's empty KDC profile and realm-only krb5.conf: MIT's DEFAULT"
    );
    krb5_config::set_test_kdc_profile(Some(kdc));
    assert_eq!(
        iana(super::permitted_enctypes_kdc().unwrap()),
        [17],
        "the pinned kdc.conf's [libdefaults]"
    );
    krb5_config::set_test_kdc_profile(None);
}

#[test]
fn remote_seq_takes_the_exact_number_then_the_next() {
    let mut r = super::RemoteSeq::new(864_518_167);
    assert!(!r.check(864_518_168), "one too high");
    assert!(!r.check(0), "none, where the authenticator had one");
    assert!(r.check(864_518_167));
    r.advance();
    assert_eq!(r.expected(), 864_518_168);
    let mut none = super::RemoteSeq::new(0);
    assert!(
        none.check(0),
        "none where the authenticator had none (MIT kpasswd's shape)"
    );
    assert!(!none.check(1));
}

#[test]
fn remote_seq_reads_old_heimdal_numbers_as_mit_does() {
    // privsafe.c's table: an old Heimdal counter 0x80 arrives sign-extended as 0xFFFFFF80.
    let mut one = super::RemoteSeq::new(0x80);
    assert!(
        one.check(0xFFFF_FF80),
        "chk_heimdal_seqnum: the 1-octet form"
    );
    let mut two = super::RemoteSeq::new(0x8000);
    assert!(two.check(0xFFFF_8000), "the 2-octet form");
    let mut three = super::RemoteSeq::new(0x0080_0000);
    assert!(three.check(0xFF80_0000), "the 3-octet form");
    // An exact match of an expected number in an ambiguous range marks the peer sane, which then
    // gets exact matches only.
    let mut sane = super::RemoteSeq::new(0x80);
    assert!(sane.check(0x80));
    sane.advance();
    assert!(
        !sane.check(0xFFFF_FF81),
        "a sane peer's numbers are never read as Heimdal's"
    );
    // Heimdal's counter wrapping through zero from an ambiguous start.
    assert!(super::RemoteSeq::new(0).check(0x100));
    assert!(!super::RemoteSeq::new(0).check(0x200));
}

/// A peer's KRB-PRIV, under `key`, carrying `seq` (no field when `None`).
fn peer_priv(key: &ProtocolKey, data: &[u8], seq: Option<u32>) -> Vec<u8> {
    encode(&crate::safe_priv::build_krb_priv_with_seq(key, data, seq).unwrap()).unwrap()
}

#[test]
fn rd_priv_takes_the_request_only_with_the_authenticators_seq() {
    let session = ProtocolKey::random(AES256).unwrap();
    let subkey = ProtocolKey::random(AES256).unwrap();
    // MIT kpasswd's shape: no seq-number in the authenticator or the KRB-PRIV.
    let ok = accepted(&session, Some(&subkey), None, false, None);
    let fresh = || {
        let mut ac = AcceptorAuthContext::from_ap_req(&ok, &DEFAULT_LIST).unwrap();
        ac.set_flags(AUTH_CONTEXT_DO_SEQUENCE);
        ac
    };
    assert_eq!(
        fresh().rd_priv(&peer_priv(&subkey, b"pw", None)).unwrap(),
        b"pw"
    );
    let one = fresh()
        .rd_priv(&peer_priv(&subkey, b"pw", Some(1)))
        .unwrap_err();
    assert!(
        matches!(one, Error::KrbError { code: 42, .. }),
        "seq 1 where the authenticator had none is BADORDER, got {one:?}"
    );
    // An authenticator seq-number: the KRB-PRIV must carry it, then the next one.
    let ok = accepted(&session, Some(&subkey), Some(864_518_167), false, None);
    let mut ac = AcceptorAuthContext::from_ap_req(&ok, &DEFAULT_LIST).unwrap();
    ac.set_flags(AUTH_CONTEXT_DO_SEQUENCE);
    for wrong in [None, Some(864_518_168)] {
        let e = ac.rd_priv(&peer_priv(&subkey, b"pw", wrong)).unwrap_err();
        assert!(
            matches!(e, Error::KrbError { code: 42, .. }),
            "{wrong:?}: {e:?}"
        );
    }
    assert_eq!(
        ac.rd_priv(&peer_priv(&subkey, b"one", Some(864_518_167)))
            .unwrap(),
        b"one"
    );
    assert_eq!(
        ac.rd_priv(&peer_priv(&subkey, b"two", Some(864_518_168)))
            .unwrap(),
        b"two"
    );
    assert_eq!(ac.remote_seq(), 864_518_169);
    // Without DO_SEQUENCE the number is not looked at.
    let mut lax = AcceptorAuthContext::from_ap_req(&ok, &DEFAULT_LIST).unwrap();
    lax.set_flags(0);
    assert!(lax.rd_priv(&peer_priv(&subkey, b"x", Some(7))).is_ok());
}

#[test]
fn rd_priv_refuses_a_replay_and_a_stale_time_under_do_time() {
    let session = ProtocolKey::random(AES256).unwrap();
    let ok = accepted(&session, None, None, false, None);
    let mut ac = AcceptorAuthContext::from_ap_req(&ok, &DEFAULT_LIST).unwrap();
    assert_eq!(
        ac.flags(),
        super::AUTH_CONTEXT_DO_TIME,
        "krb5_auth_con_init's flags"
    );
    let msg = encode(&crate::safe_priv::build_krb_priv(&session, b"t").unwrap()).unwrap();
    assert_eq!(ac.rd_priv(&msg).unwrap(), b"t");
    let again = ac.rd_priv(&msg).unwrap_err();
    assert!(
        matches!(again, Error::KrbError { code: 34, .. }),
        "REPEAT, got {again:?}"
    );
    let untimed = crate::safe_priv::build_krb_priv_chained(
        &session,
        b"u",
        None,
        false,
        &mut krb5_crypto::CipherState::initial(),
    )
    .unwrap();
    let skew = ac.rd_priv(&encode(&untimed).unwrap()).unwrap_err();
    assert!(
        matches!(skew, Error::KrbError { code: 37, .. }),
        "no timestamp under DO_TIME is SKEW, got {skew:?}"
    );
}

#[test]
fn rd_priv_chains_the_cipher_state_after_init_ivector() {
    let session = ProtocolKey::random(AES256).unwrap();
    let ok = accepted(&session, None, Some(500), true, None);
    let mut ac = AcceptorAuthContext::from_ap_req(&ok, &DEFAULT_LIST).unwrap();
    ac.set_flags(AUTH_CONTEXT_DO_SEQUENCE);
    ac.init_ivector();
    let mut state = krb5_crypto::CipherState::initial();
    for (seq, block) in [(500, b"block-0"), (501, b"block-1")] {
        let msg =
            crate::safe_priv::build_krb_priv_chained(&session, block, Some(seq), false, &mut state)
                .unwrap();
        assert_eq!(ac.rd_priv(&encode(&msg).unwrap()).unwrap(), block);
    }
    let unchained = crate::safe_priv::build_krb_priv_chained(
        &session,
        b"block-2",
        Some(502),
        false,
        &mut krb5_crypto::CipherState::initial(),
    )
    .unwrap();
    assert!(
        ac.rd_priv(&encode(&unchained).unwrap()).is_err(),
        "a block not chained from the last one does not decrypt"
    );
}

#[test]
fn rd_safe_takes_the_size_only_with_the_authenticators_seq() {
    let session = ProtocolKey::random(AES256).unwrap();
    let ok = accepted(&session, None, Some(4242), true, None);
    let size = 1989u32.to_be_bytes();
    let safe = |seq: u32| {
        encode(&crate::safe_priv::build_krb_safe_ex(&session, &size, Some(seq), false).unwrap())
            .unwrap()
    };
    let mut ac = AcceptorAuthContext::from_ap_req(&ok, &DEFAULT_LIST).unwrap();
    ac.set_flags(AUTH_CONTEXT_DO_SEQUENCE);
    let e = ac.rd_safe(&safe(4243)).unwrap_err();
    assert!(matches!(e, Error::KrbError { code: 42, .. }), "{e:?}");
    assert_eq!(ac.rd_safe(&safe(4242)).unwrap(), size);
    assert_eq!(ac.remote_seq(), 4243);
}

#[test]
fn rd_priv_refuses_another_message_type() {
    let session = ProtocolKey::random(AES256).unwrap();
    let ok = accepted(&session, None, None, false, None);
    let mut ac = AcceptorAuthContext::from_ap_req(&ok, &DEFAULT_LIST).unwrap();
    let e = ac.rd_priv(&[0x30, 0x00]).unwrap_err();
    assert!(matches!(e, Error::KrbError { code: 40, .. }), "{e:?}");
}

/// A KRB-PRIV from the peer whose encrypted part is `part_der`, as given.
fn sealed_priv(key: &ProtocolKey, part_der: &[u8]) -> Vec<u8> {
    let usage = KeyUsage::new(ku::KRB_PRIV_ENC_PART).unwrap();
    let cipher = krb5_crypto::encrypt(key, usage, part_der).unwrap();
    encode(&KrbPriv {
        pvno: KrbPriv::PVNO,
        msg_type: KrbPriv::MSG_TYPE,
        enc_part: krb5_types::EncryptedData {
            etype: key.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    })
    .unwrap()
}

fn priv_part_der(
    data: &[u8],
    timestamp: Option<KerberosTime>,
    seq: Option<u32>,
    s_address: krb5_types::HostAddress,
    r_address: Option<krb5_types::HostAddress>,
) -> Vec<u8> {
    encode(&EncKrbPrivPart {
        user_data: data.to_vec().into(),
        usec: timestamp
            .as_ref()
            .map(|_| Microseconds::from_subsec_micros(5)),
        timestamp,
        seq_number: seq,
        s_address,
        r_address,
    })
    .unwrap()
}

/// MIT `decode_seqno` (`asn1_k_encode.c:133-146`): a seq-number sent as a negative INTEGER reads as its 32 bits unsigned, so -2 is 0xFFFFFFFE, and an old Heimdal's -128 for its count 0x80 passes `k5_privsafe_check_seqnum`'s Heimdal check.
#[test]
fn rd_priv_reads_a_negative_seq_number_as_mit_does() {
    let session = ProtocolKey::random(AES256).unwrap();
    for (expected, sent) in [(0xFFFF_FFFE, 0xfe), (0x80, 0x80)] {
        let ok = accepted(&session, None, Some(expected), true, None);
        let mut ac = AcceptorAuthContext::from_ap_req(&ok, &DEFAULT_LIST).unwrap();
        ac.set_flags(AUTH_CONTEXT_DO_SEQUENCE);
        let mut der = priv_part_der(b"h", None, Some(0x7f), local_host_address(None), None);
        let at = der
            .windows(5)
            .position(|w| w == [0xa3, 0x03, 0x02, 0x01, 0x7f])
            .unwrap();
        der[at + 4] = sent;
        assert_eq!(
            ac.rd_priv(&sealed_priv(&session, &der)).unwrap(),
            b"h",
            "the INTEGER {sent:#04x} for {expected:#010x}"
        );
        assert_eq!(ac.remote_seq(), expected.wrapping_add(1));
    }
}

/// MIT `krb5_init_context_profile` (`lib/krb5/krb/init_ctx.c:251-252`): under `DO_TIME`, a KRB-PRIV must be within the clock skew `[libdefaults] clockskew` sets, 300 seconds unless it is set.
#[test]
fn rd_priv_takes_the_clock_skew_krb5_conf_sets() {
    let session = ProtocolKey::random(AES256).unwrap();
    let old = KerberosTime::from_unix_seconds(KerberosTime::now().unix_seconds() - 400);
    let msg = |data: &[u8]| {
        sealed_priv(
            &session,
            &priv_part_der(
                data,
                Some(old.clone()),
                None,
                local_host_address(None),
                None,
            ),
        )
    };
    krb5_config::isolate_test_krb5();
    let ok = accepted(&session, None, None, false, None);
    let mut ac = AcceptorAuthContext::from_ap_req(&ok, &DEFAULT_LIST).unwrap();
    let err = ac.rd_priv(&msg(b"a")).unwrap_err();
    assert!(
        matches!(err, Error::KrbError { code: 37, .. }),
        "400 s is outside the default 300, got {err:?}"
    );
    let conf = krb5_testkit::scratch_dir("p15a-clockskew").join("krb5.conf");
    std::fs::write(&conf, "[libdefaults]\n    clockskew = 600\n").unwrap();
    krb5_config::set_test_krb5_paths(Some(vec![conf]));
    let taken = ac.rd_priv(&msg(b"b"));
    krb5_config::set_test_krb5_paths(None);
    assert_eq!(taken.unwrap(), b"b");
}

/// MIT `read_krbpriv` (`rd_priv.c:77-78`): a KRB-PRIV's r-address, when it has one, must be the local address the context holds.
#[test]
fn rd_priv_checks_the_addresses_the_context_holds() {
    let session = ProtocolKey::random(AES256).unwrap();
    let ok = accepted(&session, None, None, false, None);
    let mut ac = AcceptorAuthContext::from_ap_req(&ok, &DEFAULT_LIST).unwrap();
    ac.set_flags(AUTH_CONTEXT_DO_SEQUENCE);
    let here = local_host_address(Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))));
    let there = local_host_address(Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8))));
    ac.set_addrs(Some(here.clone()), None);
    let msg = |r: Option<krb5_types::HostAddress>, seq: Option<u32>| {
        sealed_priv(&session, &priv_part_der(b"p", None, seq, there.clone(), r))
    };
    let err = ac.rd_priv(&msg(Some(there.clone()), None)).unwrap_err();
    assert!(
        matches!(err, Error::KrbError { code: 38, .. }),
        "BADADDR, got {err:?}"
    );
    assert_eq!(ac.rd_priv(&msg(Some(here.clone()), None)).unwrap(), b"p");
    assert_eq!(ac.rd_priv(&msg(None, Some(1))).unwrap(), b"p");
}
