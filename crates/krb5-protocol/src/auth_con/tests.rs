use std::net::{IpAddr, Ipv4Addr};

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt};
use krb5_types::{
    ApRep, Authenticator, AuthorizationDataValue, EncApRepPart, EncKrbPrivPart, EncTicketPart,
    EncryptionKey, KerberosTime, KrbPriv, Microseconds, PrincipalName, TicketFlags,
    TransitedEncoding, ku, pa,
};

use super::{
    AUTH_CONTEXT_DO_SEQUENCE, AUTH_CONTEXT_USE_SUBKEY, AcceptorAuthContext, local_host_address,
};
use crate::acceptor_conf::AcceptorConfig;
use crate::ap_req::ApVerifyOk;
use crate::error::Error;

const AES256: EncryptionType = EncryptionType::Aes256CtsHmacSha196;

fn conf(permitted: &[EncryptionType]) -> AcceptorConfig {
    AcceptorConfig {
        permitted_enctypes: permitted.to_vec(),
        ..AcceptorConfig::default()
    }
}
const AES256_SHA2: EncryptionType = EncryptionType::Aes256CtsHmacSha384192;

fn enc_key(k: &ProtocolKey) -> EncryptionKey {
    EncryptionKey {
        keytype: k.etype().to_iana(),
        keyvalue: k.as_bytes().to_vec().into(),
    }
}

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
    let mut ac = AcceptorAuthContext::from_ap_req(&ok, &conf(&DEFAULT_LIST)).unwrap();
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
    let mut ac = AcceptorAuthContext::from_ap_req(&ok, &conf(&sha2_first)).unwrap();
    assert_eq!(ac.negotiated_etype(), AES256_SHA2);
    assert!(ac.ap_req_use_subkey());
    ac.set_flags(AUTH_CONTEXT_DO_SEQUENCE | AUTH_CONTEXT_USE_SUBKEY);
    let part = rep_part(&ac.mk_rep().unwrap(), &session);
    assert_eq!(part.subkey.unwrap().keytype, AES256_SHA2.to_iana());
    let sha1_first = AcceptorAuthContext::from_ap_req(&ok, &conf(&DEFAULT_LIST)).unwrap();
    assert_eq!(sha1_first.negotiated_etype(), AES256);
    assert!(!sha1_first.ap_req_use_subkey());
}

#[test]
fn a_session_key_the_acceptor_does_not_permit_is_noperm_etype() {
    let session = ProtocolKey::random(AES256).unwrap();
    let mut ok = accepted(&session, None, None, true, None);
    ok.ticket_etype = EncryptionType::Aes128CtsHmacSha196.to_iana();
    let only_aes128 = [EncryptionType::Aes128CtsHmacSha196];
    let err = AcceptorAuthContext::from_ap_req(&ok, &conf(&only_aes128)).unwrap_err();
    assert_eq!(
        err.to_string(),
        "Encryption type aes256-cts-hmac-sha1-96 not permitted"
    );
    assert!(matches!(err, Error::NopermEtype(_)));
}

/// the ticket's own enctype is refused before `negotiate_etype` sees the session key's, with the error table's text alone.
#[test]
fn a_ticket_enctype_the_acceptor_does_not_permit_is_noperm_etype_first() {
    let aes128 = EncryptionType::Aes128CtsHmacSha196;
    let session = ProtocolKey::random(AES256).unwrap();
    let ok = accepted(&session, None, None, true, None);
    let err = AcceptorAuthContext::from_ap_req(&ok, &conf(&[aes128])).unwrap_err();
    assert!(matches!(err, Error::NopermEtype(_)));
    assert_eq!(err.to_string(), "Encryption type not permitted");
    let permitted_session = ProtocolKey::random(aes128).unwrap();
    let ok = accepted(&permitted_session, None, None, true, None);
    let err = AcceptorAuthContext::from_ap_req(&ok, &conf(&[aes128])).unwrap_err();
    assert_eq!(err.to_string(), "Encryption type not permitted");
    assert!(AcceptorAuthContext::from_ap_req(&ok, &conf(&[AES256, aes128])).is_ok());
}

#[test]
fn a_permitted_session_key_with_a_subkey_outside_the_list_is_noperm_etype() {
    let session = ProtocolKey::random(AES256).unwrap();
    let subkey = ProtocolKey::random(EncryptionType::Aes128CtsHmacSha196).unwrap();
    let ok = accepted(&session, Some(&subkey), None, true, None);
    let err = AcceptorAuthContext::from_ap_req(&ok, &conf(&[AES256])).unwrap_err();
    assert_eq!(
        err.to_string(),
        "Encryption type aes128-cts-hmac-sha1-96 not permitted"
    );
}

#[test]
fn the_kdc_profile_libdefaults_come_before_krb5_conf() {
    let krb5 = "[libdefaults]\n permitted_enctypes = aes128-cts-hmac-sha1-96\n";
    let kdc_sets = "[libdefaults]\n permitted_enctypes = aes256-cts-hmac-sha1-96\n";
    let kdc_silent = "[kdcdefaults]\n kdc_ports = 88\n";
    let iana = |files: &[&str]| -> Vec<i32> {
        let profile = krb5_config::Krb5Conf::parse_files(files).unwrap();
        let conf = AcceptorConfig::from_krb5_conf(&profile);
        conf.permitted()
            .unwrap()
            .iter()
            .map(|e| e.to_iana())
            .collect()
    };
    assert_eq!(
        iana(&[kdc_sets, krb5]),
        [18],
        "kdc.conf's [libdefaults] wins"
    );
    assert_eq!(iana(&[kdc_silent, krb5]), [17], "else krb5.conf's");
    assert_eq!(iana(&[krb5]), [17]);
    assert_eq!(iana(&[]), [18, 17, 20, 19, 16, 23, 25, 26], "MIT's DEFAULT");
}

#[test]
fn rd_priv_refuses_a_replay_and_a_stale_time_under_do_time() {
    let session = ProtocolKey::random(AES256).unwrap();
    let ok = accepted(&session, None, None, false, None);
    let mut ac = AcceptorAuthContext::from_ap_req(&ok, &conf(&DEFAULT_LIST)).unwrap();
    assert_eq!(
        ac.flags(),
        super::AUTH_CONTEXT_DO_TIME,
        "krb5_auth_con_init's flags"
    );
    let msg = encode(&crate::safe_priv::build_krb_priv_with_seq(&session, b"t", Some(1)).unwrap())
        .unwrap();
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
fn rd_safe_takes_the_size_only_with_the_authenticators_seq() {
    let session = ProtocolKey::random(AES256).unwrap();
    let ok = accepted(&session, None, Some(4242), true, None);
    let size = 1989u32.to_be_bytes();
    let safe = |seq: u32| {
        encode(&crate::safe_priv::build_krb_safe_ex(&session, &size, Some(seq), false).unwrap())
            .unwrap()
    };
    let mut ac = AcceptorAuthContext::from_ap_req(&ok, &conf(&DEFAULT_LIST)).unwrap();
    ac.set_flags(AUTH_CONTEXT_DO_SEQUENCE);
    let e = ac.rd_safe(&safe(4243)).unwrap_err();
    assert!(matches!(e, Error::KrbError { code: 42, .. }), "{e:?}");
    assert_eq!(ac.rd_safe(&safe(4242)).unwrap(), size);
    assert_eq!(ac.remote_seq(), 4243);
}

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

/// a KRB-PRIV's r-address, when it has one, must be the local address the context holds.
#[test]
fn rd_priv_checks_the_addresses_the_context_holds() {
    let session = ProtocolKey::random(AES256).unwrap();
    let ok = accepted(&session, None, None, false, None);
    let mut ac = AcceptorAuthContext::from_ap_req(&ok, &conf(&DEFAULT_LIST)).unwrap();
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

// MIT: `k5_privsafe_check_addrs` (privsafe.c:355-378)
/// With no local address (kpasswd sets none), a KRB-PRIV's receiver must be one of the host's,
/// whatever the sender says.
#[test]
fn rd_priv_with_no_local_address_wants_the_receiver_among_the_hosts() {
    let session = ProtocolKey::random(AES256).unwrap();
    let ok = accepted(&session, None, None, false, None);
    let mut ac = AcceptorAuthContext::from_ap_req(&ok, &conf(&DEFAULT_LIST)).unwrap();
    ac.set_flags(0);
    let here = local_host_address(Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))));
    let there = local_host_address(Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8))));
    ac.set_host_addrs(Some(vec![here.clone()]));
    let msg = |r: Option<krb5_types::HostAddress>| {
        sealed_priv(&session, &priv_part_der(b"p", None, None, there.clone(), r))
    };
    let err = ac.rd_priv(&msg(Some(there.clone()))).unwrap_err();
    assert!(
        matches!(err, Error::KrbError { code: 38, .. }),
        "BADADDR, got {err:?}"
    );
    assert_eq!(ac.rd_priv(&msg(Some(here.clone()))).unwrap(), b"p");
    assert_eq!(ac.rd_priv(&msg(None)).unwrap(), b"p");
    ac.set_addrs(Some(there.clone()), None);
    assert_eq!(ac.rd_priv(&msg(Some(there.clone()))).unwrap(), b"p");
}

/// The same check against the machine's own addresses, which hold no documentation address (RFC 5737's 203.0.113.0/24): kpasswd's request from a client that names such a receiver is refused as MIT refuses it.
#[test]
fn rd_priv_with_no_addresses_set_refuses_a_receiver_the_machine_does_not_have() {
    let session = ProtocolKey::random(AES256).unwrap();
    let ok = accepted(&session, None, None, false, None);
    let mut ac = AcceptorAuthContext::from_ap_req(&ok, &conf(&DEFAULT_LIST)).unwrap();
    ac.set_flags(AUTH_CONTEXT_DO_SEQUENCE);
    let sender = local_host_address(Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8))));
    let foreign = local_host_address(Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77))));
    let msg = |r: Option<krb5_types::HostAddress>| {
        sealed_priv(
            &session,
            &priv_part_der(b"p", None, Some(0), sender.clone(), r),
        )
    };
    let err = ac.rd_priv(&msg(Some(foreign))).unwrap_err();
    assert!(
        matches!(err, Error::KrbError { code: 38, .. }),
        "BADADDR, got {err:?}"
    );
    assert_eq!(ac.rd_priv(&msg(None)).unwrap(), b"p");
}
