//! A′-3 R33: TGS FAST_REQUIRED swallow + empty-groups stray PA-SPAKE skip.
//! A′-4 item 16 units that compile at `e483047` and fail there.
//! Phase 5–8 protocol tests: kpasswd, FAST, SPAKE, PKINIT, PAC, S4U, U2U.
//!
//! These call shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry
//! points from a bootstrapped realm. They fail if those paths are type-only.

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    EncryptionType, KeyUsage, ProtocolKey, checksum, decrypt, encrypt, krb_fx_cf2, unkeyed_checksum,
};
use krb5_kdc::{
    Error, PrincipalStore, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, as_req, bootstrap_documented,
    decrypt_ticket_part, documented_host, pa_enc_timestamp, tgs_req,
};
use krb5_protocol::{
    AsOutcome, KdcAddr, apply_strengthen, armor_key, build_fast_armor, tgs_exchange,
    unwrap_fast_rep,
};
use krb5_testkit::{TgsReqBuilder, issue_tgt_password, password_key};
use krb5_types::{
    ApReq, Authenticator, AuthorizationDataValue, Checksum, EncKdcRepPart, EncTgsRepPart,
    EncTicketPart, EncryptedData, EncryptionKey, KdcOptions, KerberosTime, KrbError, OctetString,
    PrincipalName, TgsRep, TgsReq, Ticket, TicketFlags, ascii, err, flag_bit, ku, pa,
};
use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn session() -> ProtocolKey {
    ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[7u8; 32]).unwrap()
}

fn password_as_tgt() -> AsOutcome {
    let t = KerberosTime::now();
    let sname = PrincipalName::krbtgt("KERBER.TEST");
    AsOutcome {
        ticket: Ticket {
            tkt_vno: Ticket::VNO,
            realm: ascii("KERBER.TEST"),
            sname: sname.clone(),
            enc_part: EncryptedData {
                etype: 18,
                kvno: Some(1),
                cipher: OctetString::from(vec![0u8; 16]),
            },
        },
        enc_part: EncKdcRepPart {
            key: EncryptionKey {
                keytype: 18,
                keyvalue: OctetString::from(vec![7u8; 32]),
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
        client_key: session(),
        session_key: session(),
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        crealm: ascii("KERBER.TEST"),
        fast_avail: false,
        used_fast: false,
        pa_type: None,
    }
}

fn unwrapped_tgs_rep(tgt: &AsOutcome, wire: &[u8]) -> Vec<u8> {
    let tgs: TgsReq = decode(wire).expect("TgsReq");
    let pa_tgs = tgs
        .0
        .padata
        .as_ref()
        .into_iter()
        .flatten()
        .find(|p| p.padata_type == pa::TGS_REQ)
        .expect("PA-TGS-REQ");
    let ap: ApReq = decode(pa_tgs.padata_value.as_ref()).expect("AP-REQ");
    let usage = KeyUsage::new(ku::TGS_REQ_AUTHENTICATOR).unwrap();
    let plain = decrypt(&tgt.session_key, usage, ap.authenticator.cipher.as_ref()).unwrap();
    let auth: Authenticator = decode(&plain).expect("Authenticator");
    let subk = auth.subkey.expect("TGS subkey");
    let sub = ProtocolKey::from_bytes(
        EncryptionType::known(subk.keytype).unwrap(),
        subk.keyvalue.as_ref(),
    )
    .unwrap();
    let sname = tgs.0.req_body.sname.clone().expect("sname");
    let t = KerberosTime::now();
    let enc = EncKdcRepPart {
        key: EncryptionKey {
            keytype: 18,
            keyvalue: OctetString::from(vec![9u8; 32]),
        },
        last_req: vec![],
        nonce: tgs.0.req_body.nonce,
        key_expiration: None,
        flags: TicketFlags::none(),
        authtime: t,
        starttime: None,
        // till is the TGT endtime; a fresh now() can tick past it.
        endtime: tgs.0.req_body.till.clone(),
        renew_till: None,
        srealm: ascii("KERBER.TEST"),
        sname: sname.clone(),
        caddr: None,
        encrypted_pa_data: None,
    };
    let enc_der = encode(&EncTgsRepPart(enc)).unwrap();
    let enc_usage = KeyUsage::new(ku::TGS_REP_ENC_PART_SUBKEY).unwrap();
    let cipher = encrypt(&sub, enc_usage, &enc_der).unwrap();
    let rep = TgsRep(krb5_types::KdcRep {
        pvno: krb5_types::KdcRep::PVNO,
        msg_type: krb5_types::KdcRep::MSG_TGS_REP,
        padata: None,
        crealm: tgt.crealm.clone(),
        cname: tgt.cname.clone(),
        ticket: Ticket {
            tkt_vno: Ticket::VNO,
            realm: ascii("KERBER.TEST"),
            sname,
            enc_part: EncryptedData {
                etype: 18,
                kvno: Some(1),
                cipher: OctetString::from(vec![0u8; 16]),
            },
        },
        enc_part: EncryptedData {
            etype: sub.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    });
    encode(&rep).unwrap()
}

#[test]
fn tgs_unwrapped_fast_is_accepted() {
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(addr).unwrap();
    tcp.set_nonblocking(true).unwrap();
    let tgt = password_as_tgt();
    let tgt_srv = tgt.clone();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            let mut buf = vec![0u8; 65535];
            if let Ok((n, src)) = udp.recv_from(&mut buf) {
                let rep = unwrapped_tgs_rep(&tgt_srv, &buf[..n]);
                let _ = udp.send_to(&rep, src);
                let _ = tx.send(());
                return;
            }
            if let Ok((mut stream, _)) = tcp.accept() {
                let _ = stream.set_nonblocking(false);
                let mut hdr = [0u8; 4];
                if stream.read_exact(&mut hdr).is_ok() {
                    let n = u32::from_be_bytes(hdr) as usize;
                    if (1..=1024 * 1024).contains(&n) {
                        let mut body = vec![0u8; n];
                        if stream.read_exact(&mut body).is_ok() {
                            let rep = unwrapped_tgs_rep(&tgt_srv, &body);
                            let n = u32::try_from(rep.len()).expect("TGS-REP fits u32");
                            let _ = stream.write_all(&n.to_be_bytes());
                            let _ = stream.write_all(&rep);
                            let _ = tx.send(());
                            return;
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(5));
        }
    });
    let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "testhost.kerber.test"]);
    let out = tgs_exchange(
        &KdcAddr {
            host: "127.0.0.1".into(),
            port: addr.port(),
        },
        &tgt,
        host.clone(),
        "KERBER.TEST",
    )
    .expect("MIT decode_kdc.c FAST_REQUIRED swallow");
    rx.recv_timeout(Duration::from_secs(2))
        .expect("TGS-REQ seen");
    assert_eq!(out.ticket.sname, host);
}

fn wrap_tgs_fast_opts(
    req: &mut krb5_types::TgsReq,
    session: &ProtocolKey,
    inner_body: krb5_types::KdcReqBody,
    fast_options: krb5_types::fast::FastOptions,
) -> Result<ProtocolKey, krb5_protocol::Error> {
    let padata = req
        .0
        .padata
        .as_mut()
        .ok_or_else(|| krb5_protocol::Error::Asn1("no padata".into()))?;
    let pa_tgs = padata
        .iter_mut()
        .find(|x| x.padata_type == pa::TGS_REQ)
        .ok_or_else(|| krb5_protocol::Error::Asn1("no PA-TGS-REQ".into()))?;
    let mut ap: ApReq = decode(pa_tgs.padata_value.as_ref())
        .map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?;
    let auth_usage = KeyUsage::new(ku::TGS_REQ_AUTHENTICATOR)?;
    let auth_plain = decrypt(session, auth_usage, ap.authenticator.cipher.as_ref())?;
    let mut authenticator: krb5_types::Authenticator =
        decode(&auth_plain).map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?;
    let subkey = ProtocolKey::from_bytes(session.etype(), &[0x51u8; 32])
        .map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?;
    authenticator.subkey = Some(EncryptionKey {
        keytype: subkey.etype().to_iana(),
        keyvalue: subkey.as_bytes().to_vec().into(),
    });
    let auth_der = encode(&authenticator).map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?;
    ap.authenticator.cipher = encrypt(session, auth_usage, &auth_der)?.into();
    pa_tgs.padata_value = encode(&ap)
        .map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?
        .into();
    let ap_raw = pa_tgs.padata_value.as_ref().to_vec();
    let armor_key = krb_fx_cf2(&subkey, session, b"subkeyarmor", b"ticketarmor")?;
    let ck_usage = KeyUsage::new(ku::FAST_REQ_CHKSUM)?;
    let mic = checksum(&armor_key, ck_usage, &ap_raw)?;
    let inner = krb5_types::fast::KrbFastReq {
        fast_options,
        padata: Vec::new(),
        req_body: inner_body,
    };
    let inner_der = encode(&inner).map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?;
    let enc_usage = KeyUsage::new(ku::FAST_ENC)?;
    let cipher = encrypt(&armor_key, enc_usage, &inner_der)?;
    let armored = krb5_types::fast::KrbFastArmoredReq {
        armor: None,
        req_checksum: Checksum {
            cksumtype: armor_key.etype().checksum_type(),
            checksum: mic.into(),
        },
        enc_fast_req: EncryptedData {
            etype: armor_key.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    };
    let pa = krb5_types::PaData {
        padata_type: pa::FX_FAST,
        padata_value: encode(&krb5_types::fast::PaFxFast::ArmoredData(armored))
            .map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?
            .into(),
    };
    req.0.padata.get_or_insert_with(Vec::new).push(pa);
    Ok(subkey)
}

#[test]
fn tgs_fast_hide_outer_tgs_rep() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 851);
    let mut tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        101,
    )
    .unwrap();
    let inner_body = tgs.0.req_body.clone();
    let mut opts = krb5_types::fast::fast_options_none();
    opts.set(1, true);
    let subkey =
        wrap_tgs_fast_opts(&mut tgs, &issued.session_key, inner_body, opts).expect("TGS FAST");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("TGS");
    assert_eq!(out.rep.0.cname.components_joined(), "WELLKNOWN/ANONYMOUS");
    assert_eq!(
        String::from_utf8_lossy(out.rep.0.crealm.as_bytes()),
        "WELLKNOWN:ANONYMOUS"
    );
    let akey = krb_fx_cf2(&subkey, &issued.session_key, b"subkeyarmor", b"ticketarmor")
        .expect("TGS armor");
    let fast = unwrap_fast_rep(&akey, &out.rep.0.padata).expect("FAST TGS rep");
    assert!(fast.finished.is_some(), "finished keeps the real client");
}

fn user_key() -> ProtocolKey {
    password_key(TEST_USER, TEST_USER_PASSWORD)
}

fn decode_enc_part(plain: &[u8]) -> EncKdcRepPart {
    krb5_asn1::decode_enc_kdc_rep_part(plain).expect("enc-part")
}

fn assert_find_fast(err: Error, code: i32, detail: &str) {
    match err {
        Error::Protocol {
            code: got,
            text,
            detail: d,
            ..
        } => {
            assert_eq!(got, code);
            assert_eq!(text.as_deref(), Some("FIND_FAST"));
            assert_eq!(d.as_deref(), Some(detail));
        }
        other => panic!("expected {code} FIND_FAST {detail}, got {other:?}"),
    }
}

fn wrap_tgs_fast(
    req: &mut krb5_types::TgsReq,
    session: &ProtocolKey,
    inner_body: krb5_types::KdcReqBody,
) -> Result<ProtocolKey, krb5_protocol::Error> {
    wrap_tgs_fast_opts(
        req,
        session,
        inner_body,
        krb5_types::fast::fast_options_none(),
    )
}

fn wrap_tgs_fast_no_subkey(
    req: &mut krb5_types::TgsReq,
    armor_key: &ProtocolKey,
    inner_body: krb5_types::KdcReqBody,
) -> Result<(), krb5_protocol::Error> {
    let ap_raw = req
        .0
        .padata
        .as_ref()
        .and_then(|p| p.iter().find(|x| x.padata_type == pa::TGS_REQ))
        .map(|p| p.padata_value.as_ref().to_vec())
        .ok_or_else(|| krb5_protocol::Error::Asn1("no PA-TGS-REQ".into()))?;
    let ck_usage = KeyUsage::new(ku::FAST_REQ_CHKSUM)?;
    let mic = checksum(armor_key, ck_usage, &ap_raw)?;
    let inner = krb5_types::fast::KrbFastReq {
        fast_options: krb5_types::fast::fast_options_none(),
        padata: Vec::new(),
        req_body: inner_body,
    };
    let inner_der = encode(&inner).map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?;
    let enc_usage = KeyUsage::new(ku::FAST_ENC)?;
    let cipher = encrypt(armor_key, enc_usage, &inner_der)?;
    let armored = krb5_types::fast::KrbFastArmoredReq {
        armor: None,
        req_checksum: Checksum {
            cksumtype: armor_key.etype().checksum_type(),
            checksum: mic.into(),
        },
        enc_fast_req: EncryptedData {
            etype: armor_key.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    };
    let pa = krb5_types::PaData {
        padata_type: pa::FX_FAST,
        padata_value: encode(&krb5_types::fast::PaFxFast::ArmoredData(armored))
            .map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?
            .into(),
    };
    req.0.padata.get_or_insert_with(Vec::new).push(pa);
    Ok(())
}

fn wrap_tgs_fast_explicit_armor(
    req: &mut krb5_types::TgsReq,
    armor_ticket: krb5_types::Ticket,
    armor_session: &ProtocolKey,
    cname: &PrincipalName,
    inner_body: krb5_types::KdcReqBody,
    armor_sub: Option<&ProtocolKey>,
) -> Result<(), krb5_protocol::Error> {
    let ap_raw = req
        .0
        .padata
        .as_ref()
        .and_then(|p| p.iter().find(|x| x.padata_type == pa::TGS_REQ))
        .map(|p| p.padata_value.as_ref().to_vec())
        .ok_or_else(|| krb5_protocol::Error::Asn1("no PA-TGS-REQ".into()))?;
    let armor_ap = build_fast_armor(
        armor_ticket,
        armor_session,
        &ascii(TEST_REALM),
        cname,
        armor_sub,
    )?;
    let akey = armor_key(armor_session, armor_sub)?;
    let ck_usage = KeyUsage::new(ku::FAST_REQ_CHKSUM)?;
    let mic = checksum(&akey, ck_usage, &ap_raw)?;
    let inner = krb5_types::fast::KrbFastReq {
        fast_options: krb5_types::fast::fast_options_none(),
        padata: Vec::new(),
        req_body: inner_body,
    };
    let inner_der = encode(&inner).map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?;
    let enc_usage = KeyUsage::new(ku::FAST_ENC)?;
    let cipher = encrypt(&akey, enc_usage, &inner_der)?;
    let armor_der = encode(&armor_ap).map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?;
    let armored = krb5_types::fast::KrbFastArmoredReq {
        armor: Some(krb5_types::fast::KrbFastArmor {
            armor_type: krb5_types::fast::ARMOR_AP_REQUEST,
            armor_value: armor_der.into(),
        }),
        req_checksum: Checksum {
            cksumtype: akey.etype().checksum_type(),
            checksum: mic.into(),
        },
        enc_fast_req: EncryptedData {
            etype: akey.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    };
    let pa = krb5_types::PaData {
        padata_type: pa::FX_FAST,
        padata_value: encode(&krb5_types::fast::PaFxFast::ArmoredData(armored))
            .map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?
            .into(),
    };
    req.0.padata.get_or_insert_with(Vec::new).push(pa);
    Ok(())
}

fn fx_armor_ad() -> AuthorizationDataValue {
    AuthorizationDataValue {
        ad_type: pa::AD_FX_ARMOR,
        ad_data: Vec::<u8>::new().into(),
    }
}

fn reencrypt_tgt(store: &PrincipalStore, ticket: &mut krb5_types::Ticket, part: &EncTicketPart) {
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let plain = encode(part).expect("enc-tkt");
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    ticket.enc_part.cipher = encrypt(&krbtgt.key, usage, &plain).expect("ticket").into();
}

fn assert_process_tgs_policy(err: Error, detail: &str) {
    match err {
        Error::Protocol {
            code,
            text,
            detail: d,
            ..
        } => {
            assert_eq!(code, err::POLICY);
            assert_eq!(text.as_deref(), Some("PROCESS_TGS"));
            assert_eq!(d.as_deref(), Some(detail));
        }
        other => panic!("expected 12 PROCESS_TGS {detail}, got {other:?}"),
    }
}

fn map_fx_fast_tgs(
    req: &mut krb5_types::TgsReq,
    f: impl FnOnce(&mut krb5_types::fast::KrbFastArmoredReq),
) {
    let pa = req
        .0
        .padata
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|p| p.padata_type == pa::FX_FAST)
        .expect("FAST");
    let krb5_types::fast::PaFxFast::ArmoredData(mut armored) =
        decode(pa.padata_value.as_ref()).expect("fast");
    f(&mut armored);
    pa.padata_value = encode(&krb5_types::fast::PaFxFast::ArmoredData(armored))
        .expect("re-encode")
        .into();
}

fn fast_tgs_prepared(store: &PrincipalStore, nonce: u32) -> krb5_types::TgsReq {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(store, TEST_USER, TEST_USER_PASSWORD, nonce);
    let mut tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        nonce + 1,
    )
    .unwrap();
    let inner = tgs.0.req_body.clone();
    wrap_tgs_fast(&mut tgs, &issued.session_key, inner).expect("TGS FAST");
    tgs
}

fn assert_krb_error(bytes: &[u8], code: i32, e_text: &str) {
    assert_eq!(bytes.first(), Some(&0x7e), "expected KRB-ERROR");
    let e: KrbError = decode(bytes).expect("KrbError");
    assert_eq!(e.error_code, code);
    let text = e
        .e_text
        .as_ref()
        .and_then(|t| std::str::from_utf8(t.as_bytes()).ok());
    assert_eq!(text, Some(e_text));
}

#[test]
fn tgs_fast_inner_nonce_not_outer() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 850);
    let mut tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        100,
    )
    .unwrap();
    let mut inner_body = tgs.0.req_body.clone();
    inner_body.nonce = 200;
    let subkey = wrap_tgs_fast(&mut tgs, &issued.session_key, inner_body).expect("TGS FAST");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("TGS");
    let akey = krb_fx_cf2(&subkey, &issued.session_key, b"subkeyarmor", b"ticketarmor")
        .expect("TGS armor");
    let fast = unwrap_fast_rep(&akey, &out.rep.0.padata).expect("FAST TGS rep");
    let sk = fast.strengthen_key.expect("TGS strengthen-key");
    let reply = apply_strengthen(&sk, &subkey).expect("CF2");
    let usage = KeyUsage::new(ku::TGS_REP_ENC_PART_SUBKEY).unwrap();
    let plain = decrypt(&reply, usage, out.rep.0.enc_part.cipher.as_ref()).expect("TGS enc");
    let enc = decode_enc_part(&plain);
    assert_eq!(
        enc.nonce, 200,
        "EncTgsRepPart must echo the inner FAST nonce"
    );
}

#[test]
fn tgs_fast_validate_future_starttime_is_not_yet_valid() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = user_key();
    let from = KerberosTime::now().add_seconds(2).unwrap();
    let mut req = as_req(
        cname.clone(),
        TEST_REALM,
        860,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    req.0.req_body.from = Some(from);
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::MAY_POSTDATE, true)
        .with_bit(flag_bit::POSTDATED, true);
    let issued = krb5_kdc::issue_as(&store, &req).expect("postdated AS");
    let mut tgs = TgsReqBuilder::new(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        861,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::VALIDATE, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .expect("VALIDATE");
    let inner = tgs.0.req_body.clone();
    wrap_tgs_fast(&mut tgs, &issued.session_key, inner).expect("TGS FAST");
    let err = krb5_kdc::issue_tgs(&store, &tgs).expect_err("FAST VALIDATE future start");
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::TKT_NYV);
            assert_eq!(text.as_deref(), Some("NOT_YET_VALID"));
        }
        other => panic!("expected Protocol, got {other:?}"),
    }
}

#[test]
fn tgs_fast_forged_ticket_realm_is_process_tgs() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 870);
    let mut tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        871,
    )
    .unwrap();
    let inner = tgs.0.req_body.clone();
    wrap_tgs_fast(&mut tgs, &issued.session_key, inner).expect("TGS FAST");
    let pa = tgs
        .0
        .padata
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|p| p.padata_type == pa::TGS_REQ)
        .expect("PA-TGS-REQ");
    let mut ap: ApReq = decode(pa.padata_value.as_ref()).expect("ap");
    ap.ticket.realm = ascii("NOWHERE.TEST");
    pa.padata_value = encode(&ap).expect("ap").into();
    let err = krb5_kdc::issue_tgs(&store, &tgs).expect_err("forged realm");
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::S_PRINCIPAL_UNKNOWN);
            assert_eq!(text.as_deref(), Some("PROCESS_TGS"));
        }
        other => panic!("expected 7 PROCESS_TGS, got {other:?}"),
    }
}

#[test]
fn tgs_fast_explicit_armor_is_preauth_failed() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 872);
    let mut tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        873,
    )
    .unwrap();
    let inner = tgs.0.req_body.clone();
    wrap_tgs_fast(&mut tgs, &issued.session_key, inner).expect("TGS FAST");
    let pa_tgs = tgs
        .0
        .padata
        .as_ref()
        .unwrap()
        .iter()
        .find(|p| p.padata_type == pa::TGS_REQ)
        .expect("PA-TGS-REQ")
        .padata_value
        .clone();
    let pa_fast = tgs
        .0
        .padata
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|p| p.padata_type == pa::FX_FAST)
        .expect("FAST");
    let krb5_types::fast::PaFxFast::ArmoredData(mut armored) =
        decode(pa_fast.padata_value.as_ref()).expect("fast");
    armored.armor = Some(krb5_types::fast::KrbFastArmor {
        armor_type: krb5_types::fast::ARMOR_AP_REQUEST,
        armor_value: pa_tgs,
    });
    pa_fast.padata_value = encode(&krb5_types::fast::PaFxFast::ArmoredData(armored))
        .expect("re-encode")
        .into();
    let err = krb5_kdc::issue_tgs(&store, &tgs).expect_err("explicit TGS armor");
    assert_find_fast(
        err,
        err::PREAUTH_FAILED,
        "Ap-request armor not permitted with TGS",
    );
}

#[test]
fn tgs_fast_without_subkey_is_preauth_failed() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 874);
    let mut tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        875,
    )
    .unwrap();
    let inner = tgs.0.req_body.clone();
    wrap_tgs_fast_no_subkey(&mut tgs, &issued.session_key, inner).expect("TGS FAST");
    let err = krb5_kdc::issue_tgs(&store, &tgs).expect_err("no subkey");
    assert_find_fast(
        err,
        err::PREAUTH_FAILED,
        "No armor key but FAST armored request present",
    );
}

#[test]
fn tgs_fast_explicit_armor_without_pa_tgs_subkey_is_accepted() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 882);
    let mut tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        883,
    )
    .unwrap();
    let inner = tgs.0.req_body.clone();
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x53u8; 32])
        .expect("armor subkey");
    wrap_tgs_fast_explicit_armor(
        &mut tgs,
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        &cname,
        inner,
        Some(&sub),
    )
    .expect("TGS FAST explicit armor");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("explicit armor without PA-TGS-REQ subkey");
    assert_eq!(out.rep.0.ticket.sname, documented_host());
}

#[test]
fn tgs_fast_explicit_armor_without_any_subkey_is_policy() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 884);
    let mut tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        885,
    )
    .unwrap();
    let inner = tgs.0.req_body.clone();
    wrap_tgs_fast_explicit_armor(
        &mut tgs,
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        &cname,
        inner,
        None,
    )
    .expect("TGS FAST explicit armor");
    let err = krb5_kdc::issue_tgs(&store, &tgs).expect_err("armor without subkey");
    assert_find_fast(err, err::POLICY, "ap-request armor without subkey");
}

#[test]
fn tgs_header_ticket_ad_fx_armor_is_policy() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 886);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &issued.rep.0.ticket).expect("TGT");
    part.authorization_data = Some(vec![fx_armor_ad()]);
    let mut ticket = issued.rep.0.ticket.clone();
    reencrypt_tgt(&store, &mut ticket, &part);
    let tgs = tgs_req(
        ticket,
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        887,
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).expect_err("AD-FX-ARMOR in ticket");
    assert_process_tgs_policy(err, "ticket valid only as FAST armor");
}

#[test]
// oracle: differential-gate.sh armor-ap-req-as-pa-tgs-req
fn tgs_header_ticket_if_relevant_ad_fx_armor_is_policy() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 888);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &issued.rep.0.ticket).expect("TGT");
    let inner = encode(&vec![fx_armor_ad()]).expect("inner AD");
    part.authorization_data = Some(vec![AuthorizationDataValue {
        ad_type: pa::AD_IF_RELEVANT,
        ad_data: inner.into(),
    }]);
    let mut ticket = issued.rep.0.ticket.clone();
    reencrypt_tgt(&store, &mut ticket, &part);
    let tgs = tgs_req(
        ticket,
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        889,
    )
    .unwrap();
    let bytes = krb5_kdc::handle_request(&store, &encode(&tgs).expect("der")).expect("reply");
    assert_krb_error(&bytes, err::POLICY, "PROCESS_TGS");
}

#[test]
// oracle: differential-gate.sh tgs-ad-fx-armor-authenticator
fn tgs_header_authenticator_ad_fx_armor_is_policy() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 890);
    let mut tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        891,
    )
    .unwrap();
    let pa = tgs
        .0
        .padata
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|p| p.padata_type == pa::TGS_REQ)
        .expect("PA-TGS-REQ");
    let mut ap: ApReq = decode(pa.padata_value.as_ref()).expect("ap");
    let auth_usage = KeyUsage::new(ku::TGS_REQ_AUTHENTICATOR).unwrap();
    let auth_plain = decrypt(
        &issued.session_key,
        auth_usage,
        ap.authenticator.cipher.as_ref(),
    )
    .expect("auth");
    let mut authenticator: krb5_types::Authenticator = decode(&auth_plain).expect("authenticator");
    authenticator.authorization_data = Some(vec![fx_armor_ad()]);
    let der = encode(&authenticator).expect("auth der");
    ap.authenticator.cipher = encrypt(&issued.session_key, auth_usage, &der)
        .expect("enc auth")
        .into();
    pa.padata_value = encode(&ap).expect("ap").into();
    let err = krb5_kdc::issue_tgs(&store, &tgs).expect_err("AD-FX-ARMOR in authenticator");
    assert_process_tgs_policy(err, "ticket valid only as FAST armor");
}

#[test]
fn fast_tgs_corrupt_enc_fast_req_is_bad_integrity_find_fast() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let mut tgs = fast_tgs_prepared(&store, 920);
    map_fx_fast_tgs(&mut tgs, |a| {
        let mut c = a.enc_fast_req.cipher.to_vec();
        c[0] ^= 0xff;
        a.enc_fast_req.cipher = c.into();
    });
    let err = krb5_kdc::issue_tgs(&store, &tgs).expect_err("corrupt TGS enc_fast_req");
    assert_find_fast(err, err::BAD_INTEGRITY, "integrity check failed");
}

#[test]
fn fast_tgs_bad_req_checksum_is_modified() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let mut tgs = fast_tgs_prepared(&store, 892);
    map_fx_fast_tgs(&mut tgs, |a| {
        let mut ck = a.req_checksum.checksum.to_vec();
        ck[0] ^= 0xff;
        a.req_checksum.checksum = ck.into();
    });
    let err = krb5_kdc::issue_tgs(&store, &tgs).expect_err("bad FAST checksum");
    assert_find_fast(err, err::MODIFIED, "modified checksum");
}

#[test]
fn fast_tgs_unkeyed_checksum_is_policy() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let mut tgs = fast_tgs_prepared(&store, 896);
    let pa_tgs = tgs
        .0
        .padata
        .as_ref()
        .unwrap()
        .iter()
        .find(|p| p.padata_type == pa::TGS_REQ)
        .unwrap()
        .padata_value
        .as_ref()
        .to_vec();
    let digest = unkeyed_checksum(7, &pa_tgs).expect("md5");
    map_fx_fast_tgs(&mut tgs, |a| {
        a.req_checksum.cksumtype = 7;
        a.req_checksum.checksum = digest.into();
    });
    let err = krb5_kdc::issue_tgs(&store, &tgs).expect_err("unkeyed FAST checksum");
    assert_find_fast(err, err::POLICY, "Unkeyed checksum used in fast_req");
}

#[test]
fn fast_tgs_unkeyed_type_with_bad_bytes_is_modified() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let mut tgs = fast_tgs_prepared(&store, 910);
    map_fx_fast_tgs(&mut tgs, |a| {
        a.req_checksum.cksumtype = 7;
        a.req_checksum.checksum = vec![0xff; 16].into();
    });
    let err = krb5_kdc::issue_tgs(&store, &tgs).expect_err("unkeyed + bad bytes");
    assert_find_fast(err, err::MODIFIED, "modified checksum");
}
