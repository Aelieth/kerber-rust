//! The subkeys the client library draws under a des3-cbc-sha1 session key.
//!
// MIT: `krb5_c_make_random_key` (lib/crypto/krb/make_random_key.c:31-76)
//! `keybytes` random octets through the enctype's random-to-key, so a des3 key is 24 octets of odd parity; `krb5_generate_subkey` draws the subkey of an authenticator with it.
//! A MIT service that is given a subkey of even parity cannot use it ("DES key has bad parity").
// MIT: `fast_armor_ap_request` (lib/krb5/krb/fast.c:52-108)
//! the FAST armor AP-REQ carries such a subkey, as does the authenticator of a TGS-REQ.
//! Both are read here off the wire, from a KDC on loopback that records what it is sent; the kpasswd request's subkey is checked in `chpw.rs`.

#[path = "common/mod.rs"]
mod common;
use common::isolate_host_krb5;
use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt};
use krb5_protocol::{
    AsOutcome, AsRequest, AsTicketOpts, FastArmor, KdcAddr, as_exchange, tgs_exchange,
};
use krb5_types::fast::PaFxFast;
use krb5_types::{
    ApReq, AsReq, Authenticator, EncKdcRepPart, EncryptedData, EncryptionKey, KerberosTime,
    KrbError, Microseconds, OctetString, PrincipalName, TgsReq, Ticket, TicketFlags, ascii, err,
    ku, pa,
};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;

const DES3: EncryptionType = EncryptionType::Des3CbcSha1;

fn user() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"])
}

fn krbtgt_ticket() -> Ticket {
    Ticket {
        tkt_vno: Ticket::VNO,
        realm: ascii("KERBER.TEST"),
        sname: PrincipalName::krbtgt("KERBER.TEST"),
        enc_part: EncryptedData {
            etype: 18,
            kvno: Some(1),
            cipher: OctetString::from(vec![0u8; 16]),
        },
    }
}

/// A TGT whose session key is `session`; nothing that makes a request reads the ticket's contents.
fn tgt(session: &ProtocolKey) -> AsOutcome {
    let t = KerberosTime::now();
    let sname = PrincipalName::krbtgt("KERBER.TEST");
    AsOutcome {
        ticket: krbtgt_ticket(),
        enc_part: EncKdcRepPart {
            key: EncryptionKey {
                keytype: session.etype().to_iana(),
                keyvalue: OctetString::from(session.as_bytes().to_vec()),
            },
            last_req: vec![],
            nonce: 1,
            key_expiration: None,
            flags: TicketFlags::none(),
            authtime: t.clone(),
            starttime: None,
            endtime: t,
            renew_till: None,
            srealm: ascii("KERBER.TEST"),
            sname,
            caddr: None,
            encrypted_pa_data: None,
        },
        client_key: session.clone(),
        session_key: session.clone(),
        cname: user(),
        crealm: ascii("KERBER.TEST"),
        fast_avail: false,
        used_fast: false,
        pa_type: None,
        pa_config: None,
    }
}

fn generic_error() -> Vec<u8> {
    encode(&KrbError {
        pvno: KrbError::PVNO,
        msg_type: KrbError::MSG_TYPE,
        ctime: None,
        cusec: None,
        stime: KerberosTime::now(),
        susec: Microseconds::ZERO,
        error_code: err::GENERIC,
        crealm: None,
        cname: None,
        realm: ascii("KERBER.TEST"),
        sname: PrincipalName::krbtgt("KERBER.TEST"),
        e_text: None,
        e_data: None,
    })
    .expect("KRB-ERROR")
}

/// A KDC on loopback, UDP and TCP on one port, that keeps every request it is sent and answers each with a KRB-ERROR.
fn recorder() -> (KdcAddr, Arc<Mutex<Vec<Vec<u8>>>>) {
    let (udp, tcp) = krb5_testkit::loopback_udp_tcp();
    let port = udp.local_addr().unwrap().port();
    let shots = Arc::new(Mutex::new(Vec::new()));
    let reply = generic_error();
    {
        let shots = shots.clone();
        let reply = reply.clone();
        thread::spawn(move || {
            let mut buf = vec![0u8; 65535];
            while let Ok((n, src)) = udp.recv_from(&mut buf) {
                shots.lock().unwrap().push(buf[..n].to_vec());
                let _ = udp.send_to(&reply, src);
            }
        });
    }
    {
        let shots = shots.clone();
        thread::spawn(move || {
            for conn in tcp.incoming() {
                let Ok(mut conn) = conn else {
                    break;
                };
                let shots = shots.clone();
                let reply = reply.clone();
                thread::spawn(move || {
                    let mut len = [0u8; 4];
                    if conn.read_exact(&mut len).is_err() {
                        return;
                    }
                    let mut req = vec![0u8; u32::from_be_bytes(len) as usize];
                    if conn.read_exact(&mut req).is_err() {
                        return;
                    }
                    shots.lock().unwrap().push(req);
                    let n = u32::try_from(reply.len()).unwrap();
                    let _ = conn.write_all(&n.to_be_bytes());
                    let _ = conn.write_all(&reply);
                });
            }
        });
    }
    (
        KdcAddr {
            host: "127.0.0.1".into(),
            port,
        },
        shots,
    )
}

/// The subkey in the authenticator of an AP-REQ, which is under `session` with key usage `usage`.
fn subkey_of(ap_req: &[u8], session: &ProtocolKey, usage: u32) -> EncryptionKey {
    let ap: ApReq = decode(ap_req).expect("AP-REQ");
    let usage = KeyUsage::new(usage).unwrap();
    let plain = decrypt(session, usage, ap.authenticator.cipher.as_ref()).expect("authenticator");
    decode::<Authenticator>(&plain)
        .expect("Authenticator")
        .subkey
        .expect("a subkey")
}

fn assert_des3_of_odd_parity(sub: &EncryptionKey) {
    assert_eq!(sub.keytype, DES3.to_iana());
    let key = sub.keyvalue.as_ref();
    assert_eq!(key.len(), 24);
    assert!(key.iter().all(|b| b.count_ones() % 2 == 1), "{key:02x?}");
}

/// The TGS-REQ's authenticator carries a subkey of the TGT session key's enctype. It also carries a checksum of the request body
/// under that key, which for des3 is hmac-sha1-des3-kd (`krb5int_dk_checksum`).
#[test]
fn the_subkey_of_a_tgs_request_under_a_des3_tgt_has_odd_parity() {
    isolate_host_krb5();
    for _ in 0..16 {
        let session = ProtocolKey::random(DES3).unwrap();
        let (kdc, shots) = recorder();
        let service =
            PrincipalName::try_new(PrincipalName::NT_SRV_HST, ["host", "des3.kerber.test"])
                .unwrap();
        let _ = tgs_exchange(
            &krb5_config::isolated_profile(),
            &kdc,
            &tgt(&session),
            service,
            "KERBER.TEST",
        );
        let raw = shots.lock().unwrap().first().cloned().expect("a TGS-REQ");
        let req: TgsReq = decode(&raw).expect("TGS-REQ");
        let pa_tgs = req
            .0
            .padata
            .as_deref()
            .and_then(|v| v.iter().find(|p| p.padata_type == pa::TGS_REQ))
            .expect("PA-TGS-REQ");
        assert_des3_of_odd_parity(&subkey_of(
            pa_tgs.padata_value.as_ref(),
            &session,
            ku::TGS_REQ_AUTHENTICATOR,
        ));
    }
}

/// The FAST armor AP-REQ's authenticator carries a subkey of the armor ticket's session key's enctype, from which the armor key is made.
#[test]
fn the_subkey_of_a_fast_armor_under_a_des3_session_key_has_odd_parity() {
    isolate_host_krb5();
    for _ in 0..16 {
        let session = ProtocolKey::random(DES3).unwrap();
        let (kdc, shots) = recorder();
        let armor = FastArmor {
            ticket: krbtgt_ticket(),
            session: session.clone(),
            crealm: ascii("KERBER.TEST"),
            cname: user(),
        };
        let _ = as_exchange(&AsRequest {
            cname: user(),
            realm: "KERBER.TEST",
            password: b"x",
            kdc: &kdc,
            profile: &krb5_config::isolated_profile(),
            want_spake: false,
            fast_armor: Some(&armor),
            pkinit: None,
            canonicalize: false,
            sname: None,
            etypes: None,
            ticket: AsTicketOpts::default(),
        });
        let raw = shots.lock().unwrap().first().cloned().expect("an AS-REQ");
        let req: AsReq = decode(&raw).expect("AS-REQ");
        let fx = req
            .0
            .padata
            .as_deref()
            .and_then(|v| v.iter().find(|p| p.padata_type == pa::FX_FAST))
            .expect("PA-FX-FAST on the request");
        let PaFxFast::ArmoredData(armored) = decode(fx.padata_value.as_ref()).expect("PA-FX-FAST");
        let armor_ap = armored.armor.expect("explicit armor").armor_value;
        assert_des3_of_odd_parity(&subkey_of(
            armor_ap.as_ref(),
            &session,
            ku::AP_REQ_AUTHENTICATOR,
        ));
    }
}

/// A des3 session key of bad parity, as an earlier build's KDC issued it and a ticket, a credential cache or a reply carries it.
fn session_of_bad_parity() -> ProtocolKey {
    let mut bytes = ProtocolKey::random(DES3).unwrap().as_bytes().to_vec();
    bytes[3] ^= 1;
    ProtocolKey::from_bytes(DES3, &bytes).expect("a 24-octet key loads, whatever its parity")
}

/// A TGT whose session key has bad parity cannot seal the authenticator of a TGS-REQ: the request is refused with MIT's code, and
/// nothing is sent. MIT's own `kvno` says the same ("DES key has bad parity while getting credentials for ...").
// MIT: `validate_and_schedule` (lib/crypto/builtin/enc_provider/des3.c:33-53)
/// the encryption of the authenticator under the session key fails with `KRB5DES_BAD_KEYPAR`.
#[test]
fn a_tgt_whose_session_key_has_bad_parity_is_refused_before_the_tgs_request_is_sent() {
    isolate_host_krb5();
    let session = session_of_bad_parity();
    let (kdc, shots) = recorder();
    let service =
        PrincipalName::try_new(PrincipalName::NT_SRV_HST, ["host", "des3.kerber.test"]).unwrap();
    let r = tgs_exchange(
        &krb5_config::isolated_profile(),
        &kdc,
        &tgt(&session),
        service,
        "KERBER.TEST",
    );
    assert!(
        matches!(r, Err(krb5_protocol::Error::DesBadParity)),
        "{r:?}"
    );
    assert_eq!(shots.lock().unwrap().len(), 0, "nothing was sent");
}

/// The same for the armor session key of a FAST AS-REQ: the armor AP-REQ cannot be made.
// MIT: `fast_armor_ap_request` (lib/krb5/krb/fast.c:52-108)
/// `krb5_mk_req_extended` encrypts the armor authenticator under the armor ticket's session key.
#[test]
fn an_armor_session_key_of_bad_parity_is_refused_before_the_as_request_is_sent() {
    isolate_host_krb5();
    let session = session_of_bad_parity();
    let (kdc, shots) = recorder();
    let armor = FastArmor {
        ticket: krbtgt_ticket(),
        session,
        crealm: ascii("KERBER.TEST"),
        cname: user(),
    };
    let r = as_exchange(&AsRequest {
        cname: user(),
        realm: "KERBER.TEST",
        password: b"x",
        kdc: &kdc,
        profile: &krb5_config::isolated_profile(),
        want_spake: false,
        fast_armor: Some(&armor),
        pkinit: None,
        canonicalize: false,
        sname: None,
        etypes: None,
        ticket: AsTicketOpts::default(),
    });
    assert!(
        matches!(r, Err(krb5_protocol::Error::DesBadParity)),
        "{r:?}"
    );
    // The first request of a FAST AS is the armored one; it is never made.
    assert_eq!(shots.lock().unwrap().len(), 0, "nothing was sent");
}
