//! W1-B B1: FAST reply nonce. MIT `fast.c:397-402` `decrypt_fast_reply`.
//! Unit-only: no MIT tool emits a flipped FAST nonce.

#[path = "common/mod.rs"]
mod common;
use common::isolate_host_krb5;
use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, checksum, decrypt, encrypt};
use krb5_kdc::{
    PrincipalStore, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented, serve,
    shared_store,
};
use krb5_protocol::{
    AsRequest, AsTicketOpts, Error, FastArmor, KdcAddr, armor_key, as_exchange, as_req,
    attach_fast, build_fast_armor, pa_enc_timestamp, unwrap_fast_rep, unwrap_fast_rep_checked,
};
use krb5_testkit::{password_key, user};
use krb5_types::fast::{KrbFastArmoredRep, KrbFastResponse, PaFxFast, PaFxFastRep};
use krb5_types::{
    ApReq, AsRep, AsReq, Authenticator, EncryptedData, KrbError, MethodData, PaData, PrincipalName,
    Ticket, ascii, err, ku, pa, try_ascii,
};
use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

fn armor() -> ProtocolKey {
    ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x5a; 32]).expect("armor")
}

fn sealed(key: &ProtocolKey, nonce: u32) -> PaData {
    let resp = KrbFastResponse {
        padata: Vec::new(),
        strengthen_key: None,
        finished: None,
        nonce,
    };
    let der = encode(&resp).expect("enc");
    let usage = KeyUsage::new(ku::FAST_REP).expect("usage");
    let cipher = encrypt(key, usage, &der).expect("seal");
    let armored = KrbFastArmoredRep {
        enc_fast_rep: EncryptedData {
            etype: key.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    };
    PaData {
        padata_type: pa::FX_FAST,
        padata_value: encode(&krb5_types::fast::PaFxFastRep::ArmoredData(armored))
            .expect("pa")
            .into(),
    }
}

#[test]
fn b1_fast_reply_nonce_mismatch_is_kdcrep_modified() {
    let key = armor();
    let pa = sealed(&key, 100);
    let err = unwrap_fast_rep_checked(&key, &Some(vec![pa]), 101).expect_err("flipped nonce");
    let msg = err.to_string();
    assert!(
        msg.contains("nonce modified in FAST response"),
        "MIT fast.c:398-402 text, got {msg}"
    );
}

#[test]
fn b1_fast_reply_nonce_match_unwraps() {
    let key = armor();
    let pa = sealed(&key, 100);
    let fast = unwrap_fast_rep_checked(&key, &Some(vec![pa.clone()]), 100).expect("match");
    assert_eq!(fast.nonce, 100);
    let raw = unwrap_fast_rep(&key, &Some(vec![pa])).expect("decrypt-only still works");
    assert_eq!(raw.nonce, 100);
}

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

#[test]
fn as_exchange_records_fast_availability() {
    isolate_host_krb5();
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = std::net::TcpListener::bind(addr).unwrap();
    let port = addr.port();
    let store = shared_store(store);
    thread::spawn(move || {
        let _ = serve(store, udp, tcp);
    });

    let out = as_exchange(&AsRequest {
        cname,
        realm: TEST_REALM,
        password: TEST_USER_PASSWORD,
        kdc: &KdcAddr {
            host: "127.0.0.1".into(),
            port,
        },
        want_spake: false,
        fast_armor: None,
        pkinit: None,
        canonicalize: false,
        sname: None,
        etypes: None,
        ticket: AsTicketOpts::default(),
    })
    .expect("AS exchange with enc-pa-rep negotiation");
    // The client advertised PA-149; the KDC echoed a valid checksum (else
    // as_exchange would fail KDCREP_MODIFIED) plus PA-FX-FAST.
    assert!(out.fast_avail, "PA-FX-FAST echoed => fast_avail");
}

fn request<'a>(
    cname: &PrincipalName,
    kdc: &'a KdcAddr,
    armor: Option<&'a FastArmor>,
) -> AsRequest<'a> {
    AsRequest {
        cname: cname.clone(),
        realm: TEST_REALM,
        password: TEST_USER_PASSWORD,
        kdc,
        want_spake: false,
        fast_armor: armor,
        pkinit: None,
        canonicalize: false,
        sname: None,
        etypes: None,
        ticket: AsTicketOpts::default(),
    }
}

#[test]
fn fast_exchange_negotiates_through_the_armor_like_mit() {
    isolate_host_krb5();
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = std::net::TcpListener::bind(addr).unwrap();
    let port = addr.port();
    let store = shared_store(store);
    thread::spawn(move || {
        let _ = serve(store, udp, tcp);
    });
    let kdc = KdcAddr {
        host: "127.0.0.1".into(),
        port,
    };
    // The documented user requires preauth and the KDC advertises SPAKE.
    // MIT `sort_krb5_padata_sequence` + `k5_preauth` records pa_type 151.
    let plain = as_exchange(&request(&cname, &kdc, None)).expect("plain AS exchange");
    assert!(plain.fast_avail);
    assert_eq!(plain.pa_type, Some(pa::SPAKE));
    let armor = FastArmor {
        ticket: plain.ticket.clone(),
        session: plain.session_key.clone(),
        crealm: plain.crealm.clone(),
        cname: plain.cname.clone(),
    };
    // Under FAST the advertised 150/149 travel inside the FAST-REQ, the KDC
    // swaps the inner request in, and the client verifies the echo over the
    // outer request with the strengthened reply key (krb5int_fast_verify_nego).
    let fast = as_exchange(&request(&cname, &kdc, Some(&armor))).expect("FAST AS exchange");
    assert!(fast.fast_avail, "PA-FX-FAST echoed inside the FAST reply");
    assert_eq!(fast.pa_type, Some(pa::ENC_TIMESTAMP));
}

#[test]
fn as_exchange_rejects_reply_missing_enc_pa_rep_checksum() {
    isolate_host_krb5();
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    // No-preauth so the KDC issues on the first AS-REQ (single round-trip).
    let attrs = store.get_name(&cname).unwrap().attributes & !krb5_kdc::KDB_REQUIRES_PRE_AUTH;
    store
        .apply_admin_fields(&cname, Some(attrs), None, None, None, None, false, None)
        .unwrap();

    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        if let Ok((n, src)) = udp.recv_from(&mut buf) {
            // Strip the client's PA-REQ-ENC-PA-REP so issue_as sets enc-pa-rep
            // (L3a) but echoes no checksum.
            if let Ok(mut req) = decode::<AsReq>(&buf[..n]) {
                if let Some(p) = req.0.padata.as_mut() {
                    p.retain(|d| d.padata_type != pa::REQ_ENC_PA_REP);
                }
                if let Ok(stripped) = encode(&req)
                    && let Ok(reply) = krb5_kdc::handle_request(&store, &stripped)
                {
                    let _ = udp.send_to(&reply, src);
                }
            }
        }
    });

    let err = as_exchange(&AsRequest {
        cname,
        realm: TEST_REALM,
        password: TEST_USER_PASSWORD,
        kdc: &KdcAddr {
            host: "127.0.0.1".into(),
            port,
        },
        want_spake: false,
        fast_armor: None,
        pkinit: None,
        canonicalize: false,
        sname: None,
        etypes: None,
        ticket: AsTicketOpts::default(),
    })
    .expect_err("enc-pa-rep flag without a PA-149 checksum => KDCREP_MODIFIED");
    match err {
        krb5_protocol::Error::ReplyMismatch(m) => {
            assert!(m.contains("modified"), "want KDCREP_MODIFIED text, got {m}");
        }
        other => panic!("want KDCREP_MODIFIED, got {other:?}"),
    }
}

fn mallory() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["mallory"])
}

/// A FAST armor TGT for `user` from the in-process KDC.
fn armor_tgt(store: &PrincipalStore, nonce: u32) -> FastArmor {
    let key = password_key(TEST_USER, TEST_USER_PASSWORD);
    let req = as_req(
        user(),
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    let issued = krb5_kdc::issue_as(store, &req).expect("armor TGT");
    FastArmor {
        ticket: issued.rep.0.ticket,
        session: issued.session_key,
        crealm: ascii(TEST_REALM),
        cname: user(),
    }
}

/// The armor key of the FAST request on the wire: the AP-REQ authenticator
/// (under the armor TGT session key) carries the client's subkey.
fn armor_key_of(req: &[u8], session: &ProtocolKey) -> ProtocolKey {
    let req: AsReq = decode(req).expect("AS-REQ");
    let fx = req
        .0
        .padata
        .as_deref()
        .and_then(|v| v.iter().find(|p| p.padata_type == pa::FX_FAST))
        .expect("PA-FX-FAST on the request");
    let PaFxFast::ArmoredData(armored) = decode(fx.padata_value.as_ref()).expect("PA-FX-FAST");
    let ap: ApReq =
        decode(armored.armor.expect("explicit armor").armor_value.as_ref()).expect("armor AP-REQ");
    let usage = KeyUsage::new(ku::AP_REQ_AUTHENTICATOR).unwrap();
    let plain = decrypt(session, usage, ap.authenticator.cipher.as_ref()).expect("authenticator");
    let auth: Authenticator = decode(&plain).expect("Authenticator");
    let sub = auth.subkey.expect("armor subkey");
    let sub = ProtocolKey::from_bytes(
        EncryptionType::known(sub.keytype).unwrap(),
        sub.keyvalue.as_ref(),
    )
    .unwrap();
    armor_key(session, Some(&sub)).expect("armor key")
}

fn wrap_fast_rep(akey: &ProtocolKey, resp: &KrbFastResponse) -> PaData {
    let der = encode(resp).unwrap();
    let usage = KeyUsage::new(ku::FAST_REP).unwrap();
    let cipher = encrypt(akey, usage, &der).unwrap();
    PaData {
        padata_type: pa::FX_FAST,
        padata_value: encode(&PaFxFastRep::ArmoredData(KrbFastArmoredRep {
            enc_fast_rep: EncryptedData {
                etype: akey.etype().to_iana(),
                kvno: None,
                cipher: cipher.into(),
            },
        }))
        .unwrap()
        .into(),
    }
}

fn replace_fx_fast(padata: &mut Vec<PaData>, fx: PaData) {
    padata.retain(|p| p.padata_type != pa::FX_FAST);
    padata.push(fx);
}

type Rewrite = dyn Fn(&[u8], Vec<u8>) -> Vec<u8> + Send + Sync + 'static;

/// A man in the middle on UDP and TCP (a FAST AS-REQ is over
/// `udp_preference_limit`, so the client uses TCP): every request goes to
/// the KDC, the reply goes through `rewrite(request, reply)`, and the request
/// count is kept.
fn mitm(store: PrincipalStore, rewrite: Box<Rewrite>) -> (KdcAddr, Arc<AtomicUsize>) {
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(addr).unwrap();
    let port = addr.port();
    let count = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(store);
    let rewrite: Arc<Rewrite> = Arc::from(rewrite);
    let answer = {
        let store = store.clone();
        let rewrite = rewrite.clone();
        let count = count.clone();
        move |req: &[u8]| -> Vec<u8> {
            count.fetch_add(1, Ordering::SeqCst);
            let reply = krb5_kdc::handle_request(&*store, req).expect("KDC reply");
            rewrite(req, reply)
        }
    };
    let answer_udp = answer.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 16384];
        while let Ok((n, src)) = udp.recv_from(&mut buf) {
            let reply = answer_udp(&buf[..n]);
            let _ = udp.send_to(&reply, src);
        }
    });
    thread::spawn(move || {
        for conn in tcp.incoming() {
            let Ok(mut conn) = conn else {
                break;
            };
            let answer = answer.clone();
            thread::spawn(move || {
                let mut len = [0u8; 4];
                if conn.read_exact(&mut len).is_err() {
                    return;
                }
                let n = u32::from_be_bytes(len) as usize;
                let mut req = vec![0u8; n];
                if conn.read_exact(&mut req).is_err() {
                    return;
                }
                let reply = answer(&req);
                let n = u32::try_from(reply.len()).unwrap();
                let _ = conn.write_all(&n.to_be_bytes());
                let _ = conn.write_all(&reply);
            });
        }
    });
    (
        KdcAddr {
            host: "127.0.0.1".into(),
            port,
        },
        count,
    )
}

fn fast_exchange(
    kdc: &KdcAddr,
    armor: &FastArmor,
    canonicalize: bool,
) -> Result<krb5_protocol::AsOutcome, Error> {
    krb5_config::isolate_test_krb5();
    as_exchange(&AsRequest {
        cname: user(),
        realm: TEST_REALM,
        password: TEST_USER_PASSWORD,
        kdc,
        want_spake: false,
        fast_armor: Some(armor),
        pkinit: None,
        canonicalize,
        sname: None,
        etypes: None,
        ticket: AsTicketOpts::default(),
    })
}

/// AS-REP (APPLICATION 11) with the outer, unauthenticated `cname` rewritten.
fn rewrite_outer_cname(reply: Vec<u8>) -> Vec<u8> {
    if reply.first() != Some(&0x6b) {
        return reply;
    }
    let mut rep: AsRep = decode(&reply).expect("AS-REP");
    rep.0.cname = mallory();
    encode(&rep).unwrap()
}

/// `fast.c:548-551`: after the finished checksum verifies, `resp->client`
/// is the finished client; the outer cname is never compared or returned.
/// With CANONICALIZE the outer name would otherwise be accepted as the
/// canonical name.
#[test]
fn z1_fast_as_rep_client_is_the_finished_client_under_canonicalize() {
    let (store, _) = bootstrap_documented().unwrap();
    let armor = armor_tgt(&store, 1201);
    let (kdc, _) = mitm(store, Box::new(|_, reply| rewrite_outer_cname(reply)));
    let out = fast_exchange(&kdc, &armor, true).expect("FAST AS with a rewritten outer cname");
    assert_eq!(
        out.cname,
        user(),
        "the outcome client is the FAST finished client, not the outer AS-REP cname"
    );
}

/// Without CANONICALIZE the compare in `get_in_tkt.c:239` runs on the
/// replaced (finished) client, which is the requested one — the rewritten
/// outer name is not a mismatch.
#[test]
fn z1_fast_as_rep_outer_cname_is_ignored_without_canonicalize() {
    let (store, _) = bootstrap_documented().unwrap();
    let armor = armor_tgt(&store, 1202);
    let (kdc, _) = mitm(store, Box::new(|_, reply| rewrite_outer_cname(reply)));
    let out = fast_exchange(&kdc, &armor, false)
        .expect("a rewritten outer cname is not a reply mismatch under FAST");
    assert_eq!(out.cname, user());
}

/// The finished client is what is compared: a finished cname that is not
/// the requested one (re-wrapped under the recovered armor key, the ticket
/// checksum untouched) is `KRB5_KDCREP_MODIFIED` without CANONICALIZE.
#[test]
fn z1_fast_as_rep_finished_cname_mismatch_is_kdcrep_modified() {
    let (store, _) = bootstrap_documented().unwrap();
    let armor = armor_tgt(&store, 1203);
    let session = armor.session.clone();
    let (kdc, _) = mitm(
        store,
        Box::new(move |req, reply| {
            if reply.first() != Some(&0x6b) {
                return reply;
            }
            let akey = armor_key_of(req, &session);
            let mut rep: AsRep = decode(&reply).expect("AS-REP");
            let mut fast = unwrap_fast_rep(&akey, &rep.0.padata).expect("FAST reply");
            fast.finished.as_mut().expect("finished").cname = mallory();
            let mut padata = rep.0.padata.take().unwrap_or_default();
            replace_fx_fast(&mut padata, wrap_fast_rep(&akey, &fast));
            rep.0.padata = Some(padata);
            encode(&rep).unwrap()
        }),
    );
    let err = fast_exchange(&kdc, &armor, false).expect_err("finished cname != request");
    assert!(
        err.to_string().contains("AS-REP cname mismatch"),
        "want KRB5_KDCREP_MODIFIED on the finished client, got {err}"
    );
}

/// `fast.c:445-458`: under an armor key, an error whose e_data carries no
/// PA-FX-FAST is "the fatal error indicated by the KDC" with `retry = 0`;
/// nothing outer is trusted — not the plaintext ETYPE-INFO2, not an outer
/// FX-COOKIE — and no second AS-REQ is sent (`get_in_tkt.c:1721-1724`
/// continues only on `PREAUTH_REQUIRED && retry`).
#[test]
fn z1_fast_error_without_fx_fast_is_the_fatal_outer_error() {
    let (store, _) = bootstrap_documented().unwrap();
    let armor = armor_tgt(&store, 1204);
    let session = armor.session.clone();
    let (kdc, count) = mitm(
        store,
        Box::new(move |req, reply| {
            if reply.first() != Some(&0x7e) {
                return reply;
            }
            let akey = armor_key_of(req, &session);
            let mut e: KrbError = decode(&reply).expect("KRB-ERROR");
            let method: MethodData = decode(e.e_data.as_ref().unwrap().as_ref()).unwrap();
            let fast = unwrap_fast_rep(&akey, &Some(method.clone())).expect("FAST error");
            // Tempt the client: the protected hints in the clear, plus an
            // outer cookie, and no PA-FX-FAST at all.
            let mut outer: Vec<PaData> = fast
                .padata
                .iter()
                .filter(|p| p.padata_type != pa::FX_ERROR && p.padata_type != pa::FX_COOKIE)
                .cloned()
                .collect();
            outer.push(PaData {
                padata_type: pa::FX_COOKIE,
                padata_value: b"outer-cookie".to_vec().into(),
            });
            e.e_data = Some(encode(&outer).unwrap().into());
            encode(&e).unwrap()
        }),
    );
    let err = fast_exchange(&kdc, &armor, false).expect_err("stripped FAST error");
    match err {
        Error::KrbError { code, .. } => assert_eq!(code, err::PREAUTH_REQUIRED),
        other => panic!("want the outer KRB-ERROR 25, got {other:?}"),
    }
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "no second AS-REQ after an error that did not unwrap"
    );
}

/// The same for a PA-FX-FAST that does not decrypt (a flipped ciphertext
/// byte): `decrypt_fast_reply` fails → outer error, `retry = 0`.
#[test]
fn z1_fast_error_with_a_corrupt_fx_fast_is_the_fatal_outer_error() {
    let (store, _) = bootstrap_documented().unwrap();
    let armor = armor_tgt(&store, 1205);
    let (kdc, count) = mitm(
        store,
        Box::new(|_, reply| {
            if reply.first() != Some(&0x7e) {
                return reply;
            }
            let mut e: KrbError = decode(&reply).expect("KRB-ERROR");
            let mut method: MethodData = decode(e.e_data.as_ref().unwrap().as_ref()).unwrap();
            let fx = method
                .iter_mut()
                .find(|p| p.padata_type == pa::FX_FAST)
                .expect("PA-FX-FAST");
            let mut v = fx.padata_value.to_vec();
            let last = v.len() - 1;
            v[last] ^= 0xff;
            fx.padata_value = v.into();
            e.e_data = Some(encode(&method).unwrap().into());
            encode(&e).unwrap()
        }),
    );
    let err = fast_exchange(&kdc, &armor, false).expect_err("corrupt FAST error");
    match err {
        Error::KrbError { code, .. } => assert_eq!(code, err::PREAUTH_REQUIRED),
        other => panic!("want the outer KRB-ERROR 25, got {other:?}"),
    }
    assert_eq!(count.load(Ordering::SeqCst), 1, "no second AS-REQ");
}

/// `fast.c:462-469`: a FAST response that unwraps but carries no FX-ERROR is
/// `KRB5KDC_ERR_PREAUTH_FAILED` "Expecting FX_ERROR pa-data inside FAST
/// container" — an error, not a synthesized retry.
#[test]
fn z1_fast_error_without_inner_fx_error_is_preauth_failed() {
    let (store, _) = bootstrap_documented().unwrap();
    let armor = armor_tgt(&store, 1206);
    let session = armor.session.clone();
    let (kdc, count) = mitm(
        store,
        Box::new(move |req, reply| {
            if reply.first() != Some(&0x7e) {
                return reply;
            }
            let akey = armor_key_of(req, &session);
            let mut e: KrbError = decode(&reply).expect("KRB-ERROR");
            let mut method: MethodData = decode(e.e_data.as_ref().unwrap().as_ref()).unwrap();
            let mut fast = unwrap_fast_rep(&akey, &Some(method.clone())).expect("FAST error");
            fast.padata.retain(|p| p.padata_type != pa::FX_ERROR);
            replace_fx_fast(&mut method, wrap_fast_rep(&akey, &fast));
            e.e_data = Some(encode(&method).unwrap().into());
            encode(&e).unwrap()
        }),
    );
    let err = fast_exchange(&kdc, &armor, false).expect_err("no FX-ERROR inside");
    match err {
        Error::KrbError { code, text } => {
            assert_eq!(code, err::PREAUTH_FAILED);
            assert_eq!(
                text.as_deref(),
                Some("Expecting FX_ERROR pa-data inside FAST container")
            );
        }
        other => panic!("want PREAUTH_FAILED, got {other:?}"),
    }
    assert_eq!(count.load(Ordering::SeqCst), 1, "no second AS-REQ");
}

/// `gc_via_tkt.c:190-194`: the TGS path runs `krb5int_fast_process_error`
/// too — the authenticated FX-ERROR inside the FAST envelope is the error
/// the client reports; the outer code and e_text are unauthenticated. A man
/// in the middle turns the outer 7 into a 60 "mitm" and leaves the envelope:
/// the client still sees `S_PRINCIPAL_UNKNOWN`. With the envelope stripped
/// the outer error stands (fast.c:445-458).
#[test]
fn z1_fast_tgs_error_is_the_inner_fx_error() {
    let (store, _) = bootstrap_documented().unwrap();
    let strip = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let strip_in = strip.clone();
    let (kdc, _count) = mitm(
        store,
        Box::new(move |req, reply| {
            // Only TGS-REQ (APPLICATION 12) errors are touched; the AS that
            // fetches the TGT goes through untouched.
            if req.first() != Some(&0x6c) || reply.first() != Some(&0x7e) {
                return reply;
            }
            let mut e: KrbError = decode(&reply).expect("KRB-ERROR");
            assert_eq!(
                e.error_code,
                err::S_PRINCIPAL_UNKNOWN,
                "the KDC's own answer"
            );
            e.error_code = err::GENERIC;
            e.e_text = Some(ascii("mitm"));
            if strip_in.load(Ordering::SeqCst) {
                e.e_data = None;
            }
            encode(&e).unwrap()
        }),
    );
    krb5_config::isolate_test_krb5();
    let tgt = as_exchange(&AsRequest {
        cname: user(),
        realm: TEST_REALM,
        password: TEST_USER_PASSWORD,
        kdc: &kdc,
        want_spake: false,
        fast_armor: None,
        pkinit: None,
        canonicalize: false,
        sname: None,
        etypes: None,
        ticket: AsTicketOpts::default(),
    })
    .expect("TGT");
    let nosuch = PrincipalName::new(PrincipalName::NT_SRV_INST, ["nosuch", "service"]);
    let err = krb5_protocol::tgs_exchange(&kdc, &tgt, nosuch.clone(), TEST_REALM)
        .expect_err("unknown service");
    match err {
        Error::KrbError { code, text } => {
            assert_eq!(code, err::S_PRINCIPAL_UNKNOWN, "the inner FX-ERROR's code");
            assert_ne!(
                text.as_deref(),
                Some("mitm"),
                "the outer e_text is not trusted"
            );
        }
        other => panic!("want the inner KRB-ERROR 7, got {other:?}"),
    }
    strip.store(true, Ordering::SeqCst);
    let err = krb5_protocol::tgs_exchange(&kdc, &tgt, nosuch, TEST_REALM)
        .expect_err("unknown service, envelope stripped");
    match err {
        Error::KrbError { code, text } => {
            assert_eq!(
                code,
                err::GENERIC,
                "no envelope: the outer error as received"
            );
            assert_eq!(text.as_deref(), Some("mitm"));
        }
        other => panic!("want the outer KRB-ERROR 60, got {other:?}"),
    }
}
