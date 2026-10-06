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
