//! W1-B B1: FAST AS outer `till` is the epoch snapshot.
//! MIT `get_in_tkt.c:836-838` + `fast.c:157-161` copy the request into
//! `fast_outer_request` before `set_request_times` (`get_in_tkt.c:1278-1280`).
//! Live oracle: `client-differential-gate.sh` `MIT_fast_outer_till_zero`.

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, checksum, decrypt};
use krb5_protocol::{armor_key, as_req, attach_fast, build_fast_armor};
use krb5_types::{EncryptedData, PrincipalName, Ticket, ku, pa, try_ascii};

fn dummy_ticket(realm: &str) -> Ticket {
    Ticket {
        tkt_vno: Ticket::VNO,
        realm: try_ascii(realm).expect("realm"),
        sname: PrincipalName::krbtgt(realm),
        enc_part: EncryptedData {
            etype: EncryptionType::Aes256CtsHmacSha196.to_iana(),
            kvno: Some(1),
            cipher: vec![0u8; 32].into(),
        },
    }
}

fn wrap_fast() -> (krb5_types::AsReq, ProtocolKey, krb5_types::KerberosTime) {
    let realm = "KERBER.TEST";
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    let session =
        ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x11; 32]).expect("session");
    let sub =
        ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x22; 32]).expect("sub");
    let armor = build_fast_armor(
        dummy_ticket(realm),
        &session,
        &try_ascii(realm).expect("realm"),
        &cname,
        Some(&sub),
    )
    .expect("armor");
    let akey = armor_key(&session, Some(&sub)).expect("akey");
    let mut req = as_req(cname, realm, 42, None).expect("as-req");
    let live_till = req.0.req_body.till.clone();
    req.0.req_body.from = Some(live_till.clone());
    req.0.req_body.rtime = Some(live_till.clone());
    attach_fast(&mut req, &armor, &akey, Vec::new()).expect("FAST wrap");
    (req, akey, live_till)
}

#[test]
fn b1_fast_outer_till_is_epoch() {
    let (req, akey, live_till) = wrap_fast();
    assert!(
        live_till.unix_seconds() > 0,
        "as_req till is now+10h before the snapshot"
    );
    assert_eq!(
        req.0.req_body.till.unix_seconds(),
        0,
        "get_in_tkt.c:836-838 / fast.c:157-161 outer till is 0"
    );
    assert!(
        req.0.req_body.from.is_none(),
        "opt_kerberos_time from=0 is omitted"
    );
    assert!(
        req.0.req_body.rtime.is_none(),
        "opt_kerberos_time rtime=0 is omitted"
    );

    let till_der = encode(&req.0.req_body.till).expect("till der");
    assert!(
        till_der.windows(8).any(|w| w == b"19700101"),
        "epoch GeneralizedTime is 19700101, got {till_der:?}"
    );

    let pa = &req.0.padata.as_ref().expect("padata")[0];
    assert_eq!(pa.padata_type, pa::FX_FAST);
    let fx: krb5_types::fast::PaFxFast = decode(pa.padata_value.as_ref()).expect("pa-fx-fast");
    let krb5_types::fast::PaFxFast::ArmoredData(armored) = fx;
    let enc_usage = KeyUsage::new(ku::FAST_ENC).expect("enc usage");
    let plain = decrypt(&akey, enc_usage, armored.enc_fast_req.cipher.as_ref()).expect("decrypt");
    let inner: krb5_types::fast::KrbFastReq = decode(&plain).expect("fast-req");
    assert_eq!(
        inner.req_body.till, live_till,
        "inner FAST-REQ keeps the live till"
    );
    assert_eq!(inner.req_body.from.as_ref(), Some(&live_till));
    assert_eq!(inner.req_body.rtime.as_ref(), Some(&live_till));

    let outer_der = encode(&req.0.req_body).expect("outer body");
    let ck_usage = KeyUsage::new(ku::FAST_REQ_CHKSUM).expect("ck usage");
    let mic = checksum(&akey, ck_usage, &outer_der).expect("req_checksum");
    assert_eq!(
        armored.req_checksum.checksum.as_ref(),
        mic.as_slice(),
        "fast.c:310-313 checksums the snapshotted outer body"
    );
}

#[test]
fn b1_fast_outer_till_inner_nonce_unchanged() {
    let (req, akey, _) = wrap_fast();
    let pa = &req.0.padata.as_ref().expect("padata")[0];
    let fx: krb5_types::fast::PaFxFast = decode(pa.padata_value.as_ref()).expect("pa-fx-fast");
    let krb5_types::fast::PaFxFast::ArmoredData(armored) = fx;
    let enc_usage = KeyUsage::new(ku::FAST_ENC).expect("enc usage");
    let plain = decrypt(&akey, enc_usage, armored.enc_fast_req.cipher.as_ref()).expect("decrypt");
    let inner: krb5_types::fast::KrbFastReq = decode(&plain).expect("fast-req");
    assert_eq!(inner.req_body.nonce, 42);
    assert_eq!(req.0.req_body.nonce, 42);
}
