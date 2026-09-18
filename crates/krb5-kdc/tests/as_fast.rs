//! A′-4 item 16 units that compile at `e483047` and fail there.
//! Phase 5–8 protocol tests: kpasswd, FAST, SPAKE, PKINIT, PAC, S4U, U2U.
//!
//! These call shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry
//! points from a bootstrapped realm. They fail if those paths are type-only.
//! Old-kvno cookie arm: a cookie minted under krbtgt kvno N still opens
//! after a keepold rollover (`fast_util.c:545-611` `first_key_at_kvno`).
//! Z6.1: FAST armor-TGT decrypt is MIT `krb5_ktkdb_get_entry`
//! (`lib/kdb/keytab.c:157`) — `krb5_dbe_find_enctype(entry, xrealm ? etype : -1,
//! -1, kvno)` pins the ticket kvno and skips non-permitted enctypes; a local
//! TGS whose first permitted key is not similar to the ticket etype is
//! `KRB5_KDB_NO_PERMITTED_KEY` → wire 60 `FIND_FAST` (`fast_util.c:52-59`,
//! `errcode_to_protocol`). Compiles at the parent and fails there:
//! `armor_key_from_ap` iterated every krbtgt key unfiltered.

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    EncryptionType, KeyUsage, ProtocolKey, checksum, decrypt, encrypt, krb_fx_cf2, string_to_key,
};
use krb5_kdc::{
    Error, KeyEntry, NamedPolicy, PrincipalStore, S2K_ITERS, TEST_REALM, TEST_USER,
    TEST_USER_PASSWORD, as_req, bootstrap_documented, decrypt_ticket_part, documented_host,
    pa_enc_timestamp, random_key, tgs_req,
};
use krb5_protocol::{
    apply_strengthen, armor_key, as_req_sname, attach_fast, attach_fast_with_options,
    build_fast_armor, pa_spake_response, pa_spake_support, unwrap_fast_rep,
};
use krb5_testkit::{issue_tgt_password, password_key};
use krb5_types::{
    Checksum, EncKdcRepPart, EncTicketPart, EncryptedData, KerberosTime, KrbError, MethodData,
    PaData, PaEncTsEnc, PrincipalName, Ticket, ascii, err, flag_bit, ku, pa,
};

#[test]
fn fast_hide_as_error_client() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let armor_as = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 223);
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x38u8; 32])
        .expect("subkey");
    let armor_ap = build_fast_armor(
        armor_as.rep.0.ticket.clone(),
        &armor_as.session_key,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .expect("armor AP-REQ");
    let akey = armor_key(&armor_as.session_key, Some(&sub)).expect("armor key");
    let mut opts = krb5_types::fast::fast_options_none();
    opts.set(1, true);
    let mut req = as_req(cname, TEST_REALM, 224, None).unwrap();
    attach_fast_with_options(&mut req, &armor_ap, &akey, Vec::new(), &opts).expect("FAST wrap");
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).unwrap()).expect("reply");
    let kerr: KrbError = decode(&bytes).expect("KRB-ERROR");
    assert_eq!(kerr.error_code, err::PREAUTH_REQUIRED);
    assert_eq!(
        kerr.cname
            .as_ref()
            .map(PrincipalName::components_joined)
            .as_deref(),
        Some("WELLKNOWN/ANONYMOUS")
    );
    assert_eq!(
        kerr.crealm
            .as_ref()
            .map(|r| String::from_utf8_lossy(r.as_bytes()).into_owned())
            .as_deref(),
        Some("WELLKNOWN:ANONYMOUS")
    );
}

fn user_key() -> ProtocolKey {
    password_key(TEST_USER, TEST_USER_PASSWORD)
}

fn decode_enc_part(plain: &[u8]) -> EncKdcRepPart {
    krb5_asn1::decode_enc_kdc_rep_part(plain).expect("enc-part")
}

fn issue_code(err: Error) -> i32 {
    match err {
        Error::Protocol { code, .. } => code,
        other => panic!("expected protocol error, got {other:?}"),
    }
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

fn challenge_pa(long_term: &ProtocolKey, armor_key: &ProtocolKey, ts: &KerberosTime) -> PaData {
    let chal = krb_fx_cf2(
        armor_key,
        long_term,
        b"clientchallengearmor",
        b"challengelongterm",
    )
    .expect("cf2");
    let der = encode(&PaEncTsEnc {
        patimestamp: ts.clone(),
        pausec: None,
    })
    .expect("ts");
    let usage = KeyUsage::new(ku::ENC_CHALLENGE_CLIENT).unwrap();
    let cipher = encrypt(&chal, usage, &der).expect("enc");
    let enc = EncryptedData {
        etype: chal.etype().to_iana(),
        kvno: None,
        cipher: cipher.into(),
    };
    PaData {
        padata_type: pa::ENCRYPTED_CHALLENGE,
        padata_value: encode(&enc).expect("ed").into(),
    }
}

struct ArmorTgt {
    ticket: krb5_types::Ticket,
    session: ProtocolKey,
    sub: ProtocolKey,
}

fn armor_tgt(store: &PrincipalStore, armor_nonce: u32) -> ArmorTgt {
    let armor_as = issue_tgt_password(store, TEST_USER, TEST_USER_PASSWORD, armor_nonce);
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x51u8; 32])
        .expect("subkey");
    ArmorTgt {
        ticket: armor_as.rep.0.ticket,
        session: armor_as.session_key,
        sub,
    }
}

fn armor_ap_key(armor: &ArmorTgt, salt: u8) -> (krb5_types::ApReq, ProtocolKey) {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let mut bytes = armor.sub.as_bytes().to_vec();
    bytes[0] ^= salt;
    let sub = ProtocolKey::from_bytes(armor.sub.etype(), &bytes).expect("sub");
    let armor_ap = build_fast_armor(
        armor.ticket.clone(),
        &armor.session,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .expect("armor");
    let akey = armor_key(&armor.session, Some(&sub)).expect("akey");
    (armor_ap, akey)
}

fn fast_challenge_req_with(
    armor_ap: &krb5_types::ApReq,
    akey: &ProtocolKey,
    long_term: &ProtocolKey,
    ts: &KerberosTime,
    nonce: u32,
) -> krb5_types::AsReq {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let inner = vec![challenge_pa(long_term, akey, ts)];
    let mut req = as_req(cname, TEST_REALM, nonce, None).unwrap();
    attach_fast(&mut req, armor_ap, akey, inner).expect("FAST wrap");
    req
}

fn fast_challenge_req(
    store: &PrincipalStore,
    long_term: &ProtocolKey,
    ts: &KerberosTime,
    nonce: u32,
    armor_nonce: u32,
) -> krb5_types::AsReq {
    let (armor_ap, akey) = armor_ap_key(&armor_tgt(store, armor_nonce), 0);
    fast_challenge_req_with(&armor_ap, &akey, long_term, ts, nonce)
}

fn e_data_has_fx_fast(err: &Error) -> bool {
    let ed = match err {
        Error::Protocol {
            e_data: Some(ed), ..
        }
        | Error::PreauthRequired { e_data: ed } => ed.as_slice(),
        _ => return false,
    };
    decode::<MethodData>(ed).is_ok_and(|m| m.iter().any(|p| p.padata_type == pa::FX_FAST))
}

fn wrap_as_fast_bit(
    store: &PrincipalStore,
    nonce: u32,
    bit: usize,
) -> Result<krb5_kdc::IssuedAs, Error> {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = user_key();
    let armor_as = issue_tgt_password(store, TEST_USER, TEST_USER_PASSWORD, nonce);
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x45u8; 32])
        .expect("subkey");
    let armor_ap = build_fast_armor(
        armor_as.rep.0.ticket.clone(),
        &armor_as.session_key,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .expect("armor");
    let akey = armor_key(&armor_as.session_key, Some(&sub)).expect("akey");
    let mut req = as_req(cname, TEST_REALM, nonce + 1, None).unwrap();
    let inner = req.0.req_body.clone();
    let mut opts = krb5_types::fast::fast_options_none();
    opts.set(bit, true);
    wrap_fast_split_opts(
        &mut req,
        &armor_ap,
        &akey,
        vec![pa_enc_timestamp(&key).expect("pa")],
        inner,
        opts,
    )
    .expect("FAST wrap");
    krb5_kdc::issue_as(store, &req)
}

fn map_fx_fast_as(
    req: &mut krb5_types::AsReq,
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

fn fast_as_prepared(store: &PrincipalStore, nonce: u32) -> (krb5_types::AsReq, ProtocolKey) {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = user_key();
    let armor_as = issue_tgt_password(store, TEST_USER, TEST_USER_PASSWORD, nonce);
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x47u8; 32])
        .expect("subkey");
    let armor_ap = build_fast_armor(
        armor_as.rep.0.ticket.clone(),
        &armor_as.session_key,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .expect("armor AP-REQ");
    let akey = armor_key(&armor_as.session_key, Some(&sub)).expect("armor key");
    let mut req = as_req(cname, TEST_REALM, nonce + 1, None).unwrap();
    attach_fast(
        &mut req,
        &armor_ap,
        &akey,
        vec![pa_enc_timestamp(&key).expect("pa")],
    )
    .expect("FAST wrap");
    (req, akey)
}

fn fast_as_prepared_etype(
    store: &PrincipalStore,
    nonce: u32,
    etype: EncryptionType,
) -> (krb5_types::AsReq, ProtocolKey) {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = {
        let salt = cname.default_salt(TEST_REALM);
        string_to_key(
            etype,
            TEST_USER_PASSWORD,
            &salt,
            Some(&S2K_ITERS.to_be_bytes()),
        )
        .expect("s2k")
    };
    let armor_as = {
        let req = as_req_sname(
            cname.clone(),
            TEST_REALM,
            nonce,
            Some(vec![pa_enc_timestamp(&key).expect("pa")]),
            PrincipalName::krbtgt(TEST_REALM),
            vec![etype.to_iana()],
        )
        .unwrap();
        krb5_kdc::issue_as(store, &req).expect("AS")
    };
    let sub = ProtocolKey::from_bytes(etype, &vec![0x47u8; etype.key_len()]).expect("subkey");
    let armor_ap = build_fast_armor(
        armor_as.rep.0.ticket.clone(),
        &armor_as.session_key,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .expect("armor AP-REQ");
    let akey = armor_key(&armor_as.session_key, Some(&sub)).expect("armor key");
    let mut req = as_req_sname(
        cname,
        TEST_REALM,
        nonce + 1,
        None,
        PrincipalName::krbtgt(TEST_REALM),
        vec![etype.to_iana()],
    )
    .unwrap();
    attach_fast(
        &mut req,
        &armor_ap,
        &akey,
        vec![pa_enc_timestamp(&key).expect("pa")],
    )
    .expect("FAST wrap");
    (req, akey)
}

fn der_take(input: &[u8]) -> Option<(u8, usize, &[u8], &[u8])> {
    let tag = *input.first()?;
    let first = *input.get(1)?;
    let (hlen, ln) = if first < 128 {
        (1usize, usize::from(first))
    } else if first == 0x81 && input.len() >= 3 {
        (2, usize::from(input[2]))
    } else if first == 0x82 && input.len() >= 4 {
        (3, usize::from(u16::from_be_bytes([input[2], input[3]])))
    } else {
        return None;
    };
    let start = 1 + hlen;
    let end = start.checked_add(ln)?;
    let inner = input.get(start..end)?;
    let rest = input.get(end..)?;
    Some((tag, start, inner, rest))
}

fn bump_der_len(buf: &mut [u8], tag_off: usize) -> Option<()> {
    let first = *buf.get(tag_off + 1)?;
    if first < 128 {
        buf[tag_off + 1] = first + 1;
        return Some(());
    }
    if first == 0x81 {
        buf[tag_off + 2] += 1;
        return Some(());
    }
    if first == 0x82 {
        let n = u16::from_be_bytes([buf[tag_off + 2], buf[tag_off + 3]]) + 1;
        buf[tag_off + 2..tag_off + 4].copy_from_slice(&n.to_be_bytes());
        return Some(());
    }
    None
}

fn long_form_kdc_body(raw: &[u8]) -> Option<Vec<u8>> {
    let (tag, app_hdr, app, _) = der_take(raw)?;
    if tag != 0x6a {
        return None;
    }
    let (t, seq_hdr, seq, _) = der_take(app)?;
    if t != 0x30 {
        return None;
    }
    let seq_abs = app_hdr;
    let mut off = seq_abs + seq_hdr;
    let mut cur = seq;
    while !cur.is_empty() {
        let (tag, h, inner, rest) = der_take(cur)?;
        if tag == 0xa4 {
            if inner.len() < 2 || inner[0] != 0x30 || inner[1] >= 128 {
                return None;
            }
            let a4_abs = off;
            let seq30_abs = off + h;
            let mut out = raw.to_vec();
            let old_ln = out[seq30_abs + 1];
            out.splice(seq30_abs + 1..seq30_abs + 2, [0x81, old_ln]);
            bump_der_len(&mut out, a4_abs)?;
            bump_der_len(&mut out, seq_abs)?;
            bump_der_len(&mut out, 0)?;
            return Some(out);
        }
        off += h + inner.len();
        cur = rest;
    }
    None
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

fn wrap_fast_split_opts(
    req: &mut krb5_types::AsReq,
    armor: &krb5_types::ApReq,
    armor_key: &ProtocolKey,
    inner_padata: Vec<krb5_types::PaData>,
    inner_body: krb5_types::KdcReqBody,
    fast_options: krb5_types::fast::FastOptions,
) -> Result<(), krb5_protocol::Error> {
    let outer = encode(&req.0.req_body).map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?;
    let ck_usage = KeyUsage::new(ku::FAST_REQ_CHKSUM)?;
    let mic = checksum(armor_key, ck_usage, &outer)?;
    let inner = krb5_types::fast::KrbFastReq {
        fast_options,
        padata: inner_padata,
        req_body: inner_body,
    };
    let inner_der = encode(&inner).map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?;
    let enc_usage = KeyUsage::new(ku::FAST_ENC)?;
    let cipher = encrypt(armor_key, enc_usage, &inner_der)?;
    let armored = krb5_types::fast::KrbFastArmoredReq {
        armor: Some(krb5_types::fast::KrbFastArmor {
            armor_type: krb5_types::fast::ARMOR_AP_REQUEST,
            armor_value: encode(armor)
                .map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?
                .into(),
        }),
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
    req.0.padata = Some(vec![krb5_types::PaData {
        padata_type: pa::FX_FAST,
        padata_value: encode(&krb5_types::fast::PaFxFast::ArmoredData(armored))
            .map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?
            .into(),
    }]);
    Ok(())
}

#[test]
fn fast_as_exchange_strengthen_and_finished() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = user_key();
    let armor_as = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 201);
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x42u8; 32])
        .expect("subkey");
    let armor_ap = build_fast_armor(
        armor_as.rep.0.ticket.clone(),
        &armor_as.session_key,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .expect("armor AP-REQ");
    let akey = armor_key(&armor_as.session_key, Some(&sub)).expect("armor key");
    let inner = vec![pa_enc_timestamp(&key).expect("pa")];
    let mut req = as_req(cname.clone(), TEST_REALM, 202, None).unwrap();
    attach_fast(&mut req, &armor_ap, &akey, inner).expect("FAST wrap");
    let issued = krb5_kdc::issue_as(&store, &req).expect("FAST AS");
    let fast = unwrap_fast_rep(&akey, &issued.rep.0.padata).expect("FAST rep");
    assert!(fast.finished.is_some(), "FAST finished required on AS-REP");
    let sk = fast.strengthen_key.expect("strengthen-key");
    let reply = apply_strengthen(&sk, &key).expect("CF2");
    assert_eq!(reply.as_bytes(), issued.as_rep_key.as_bytes());
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = decrypt(&reply, usage, issued.rep.0.enc_part.cipher.as_ref()).expect("AS enc");
    assert_eq!(plain.first().copied(), Some(0x7a));
    let enc = decode_enc_part(&plain);
    assert_eq!(enc.nonce, 202);
    assert!(enc.flags.pre_authent());
    let finished = fast.finished.expect("finished");
    krb5_protocol::verify_fast_finished(&akey, &issued.rep.0.ticket, &finished)
        .expect("FAST finished");
    let mut bad = finished.clone();
    let mut mac = bad.ticket_checksum.checksum.to_vec();
    mac[0] ^= 0xff;
    bad.ticket_checksum.checksum = mac.into();
    match krb5_protocol::verify_fast_finished(&akey, &issued.rep.0.ticket, &bad) {
        Err(e) => assert!(
            e.to_string().contains("Ticket modified"),
            "tampered finished: {e}"
        ),
        Ok(()) => panic!("tampered FAST finished must fail"),
    }
}

#[test]
fn fast_hide_client_names_returns_the_anonymous_outer_client() {
    // MIT kdc_fast_hide_client (fast_util.c:444) + do_as_req.c:324: a FAST
    // request that sets KRB5_FAST_OPTION_HIDE_CLIENT_NAMES (RFC 6113 bit 1) is
    // answered with the anonymous principal WELLKNOWN/ANONYMOUS@WELLKNOWN:
    // ANONYMOUS as the outer reply client; the real client stays inside the
    // FAST-armored reply, which still strengthens and finishes. Before R2-P4
    // the KDC refused the option as UNKNOWN_CRITICAL_FAST_OPTION.
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = user_key();
    let armor_as = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 221);
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x37u8; 32])
        .expect("subkey");
    let armor_ap = build_fast_armor(
        armor_as.rep.0.ticket.clone(),
        &armor_as.session_key,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .expect("armor AP-REQ");
    let akey = armor_key(&armor_as.session_key, Some(&sub)).expect("armor key");
    let inner = vec![pa_enc_timestamp(&key).expect("pa")];
    let mut opts = krb5_types::fast::fast_options_none();
    opts.set(1, true); // hide-client-names
    let mut req = as_req(cname.clone(), TEST_REALM, 222, None).unwrap();
    attach_fast_with_options(&mut req, &armor_ap, &akey, inner, &opts).expect("FAST wrap");
    let issued = krb5_kdc::issue_as(&store, &req).expect("FAST AS with hide-client-names");
    assert_eq!(
        issued.rep.0.cname.components_joined(),
        "WELLKNOWN/ANONYMOUS",
        "outer cname hidden"
    );
    assert_eq!(
        String::from_utf8_lossy(issued.rep.0.crealm.as_bytes()),
        "WELLKNOWN:ANONYMOUS",
        "outer crealm hidden"
    );
    let fast = unwrap_fast_rep(&akey, &issued.rep.0.padata).expect("FAST rep");
    assert!(
        fast.finished.is_some(),
        "FAST finished still present when hiding"
    );
}

#[test]
fn fast_as_forged_armor_realm_is_not_us() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = user_key();
    let armor_as = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 210);
    let mut ticket = armor_as.rep.0.ticket.clone();
    ticket.realm = ascii("OTHER.TEST");
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x42u8; 32])
        .expect("subkey");
    let armor_ap = build_fast_armor(
        ticket,
        &armor_as.session_key,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .expect("armor AP-REQ");
    let akey = armor_key(&armor_as.session_key, Some(&sub)).expect("armor key");
    let inner = vec![pa_enc_timestamp(&key).expect("pa")];
    let mut req = as_req(cname, TEST_REALM, 211, None).unwrap();
    attach_fast(&mut req, &armor_ap, &akey, inner).expect("FAST wrap");
    let err = krb5_kdc::issue_as(&store, &req).expect_err("forged armor realm");
    assert_find_fast(err, err::NOT_US, "FAST armor TGT");
}

#[test]
fn encrypted_challenge_wrong_key_locks_at_max_fail() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store.put_policy(NamedPolicy {
        name: "chalock".into(),
        min_length: 0,
        min_classes: 0,
        history: 0,
        max_fail: 2,
        pw_failcnt_interval: 0,
        pw_lockout_duration: 0,
        pw_min_life: 0,
        pw_max_life: 0,
        allowed_keysalts: None,
    });
    store
        .set_principal_policy(&user, Some("chalock".into()))
        .unwrap();
    let armor = armor_tgt(&store, 800);
    let zeros = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0u8; 32]).unwrap();
    let now = KerberosTime::now();
    let bad = |nonce: u32| {
        let (ap, akey) = armor_ap_key(&armor, u8::try_from(nonce).unwrap_or(1));
        fast_challenge_req_with(&ap, &akey, &zeros, &now, nonce)
    };
    let e1 = krb5_kdc::issue_as(&store, &bad(801)).expect_err("wrong key");
    assert_eq!(issue_code(e1), err::PREAUTH_FAILED);
    assert_eq!(store.fail_auth_of(store.get_name(&user).unwrap()), 1);
    let e2 = krb5_kdc::issue_as(&store, &bad(803)).expect_err("second fail");
    assert_eq!(issue_code(e2), err::PREAUTH_FAILED);
    assert_eq!(store.fail_auth_of(store.get_name(&user).unwrap()), 2);
    let e3 = krb5_kdc::issue_as(&store, &bad(805)).expect_err("locked");
    assert_eq!(issue_code(e3), err::CLIENT_REVOKED);
}

#[test]
fn encrypted_challenge_stale_ts_is_skew() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let key = user_key();
    let stale = KerberosTime::now().add_seconds(-10_000).unwrap();
    let err = krb5_kdc::issue_as(&store, &fast_challenge_req(&store, &key, &stale, 811, 810))
        .expect_err("skew");
    assert_eq!(issue_code(err), err::SKEW);
}

#[test]
fn encrypted_challenge_replayed_blob_is_repeat() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let key = user_key();
    let now = KerberosTime::now();
    let req = fast_challenge_req(&store, &key, &now, 821, 820);
    krb5_kdc::issue_as(&store, &req).expect("first challenge");
    let err = krb5_kdc::issue_as(&store, &req).expect_err("replay");
    assert_eq!(issue_code(err), err::REPEAT);
}

#[test]
fn encrypted_challenge_skew_is_fast_wrapped() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let key = user_key();
    let stale = KerberosTime::now().add_seconds(-10_000).unwrap();
    let err = krb5_kdc::issue_as(&store, &fast_challenge_req(&store, &key, &stale, 831, 830))
        .expect_err("skew");
    assert_eq!(issue_code(err.clone()), err::SKEW);
    assert!(
        e_data_has_fx_fast(&err),
        "post-armor SKEW must be FAST-wrapped"
    );
}

#[test]
fn unknown_critical_fast_option_is_refused() {
    // MIT UNSUPPORTED_CRITICAL_FAST_OPTIONS = 0xbfff0000: RFC bits 0 and 2..15
    // are refused; only bit 1 (hide-client-names) is honoured (R2-P4).
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let err = wrap_as_fast_bit(&store, 840, 2).expect_err("critical option");
    assert_eq!(issue_code(err), err::UNKNOWN_CRITICAL_FAST_OPTION);
    let err0 = wrap_as_fast_bit(&store, 848, 0).expect_err("bit 0 reserved critical");
    assert_eq!(issue_code(err0), err::UNKNOWN_CRITICAL_FAST_OPTION);
}

#[test]
fn noncritical_fast_option_bit_16_is_ignored() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    wrap_as_fast_bit(&store, 842, 16).expect("bit 16 is not unknown-critical");
}

#[test]
fn explicit_as_armor_invalid_tgt_is_tkt_nyv() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = user_key();
    let from = KerberosTime::now().add_seconds(2).unwrap();
    let mut req = as_req(
        cname.clone(),
        TEST_REALM,
        846,
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
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x46u8; 32])
        .expect("subkey");
    let armor_ap = build_fast_armor(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .expect("armor");
    let akey = armor_key(&issued.session_key, Some(&sub)).expect("akey");
    let mut fast_req = as_req(cname, TEST_REALM, 847, None).unwrap();
    let inner = fast_req.0.req_body.clone();
    wrap_fast_split_opts(
        &mut fast_req,
        &armor_ap,
        &akey,
        vec![pa_enc_timestamp(&key).expect("pa")],
        inner,
        krb5_types::fast::fast_options_none(),
    )
    .expect("FAST wrap");
    let err = krb5_kdc::issue_as(&store, &fast_req).expect_err("INVALID armor");
    assert_eq!(issue_code(err), err::TKT_NYV);
}

#[test]
fn fast_as_armor_for_host_ticket_is_server_nomatch() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = user_key();
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 853);
    let tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        854,
    )
    .expect("TGS-REQ");
    let svc = krb5_kdc::issue_tgs(&store, &tgs).expect("TGS");
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x49u8; 32])
        .expect("subkey");
    let armor_ap = build_fast_armor(
        svc.rep.0.ticket.clone(),
        &svc.session_key,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .expect("armor");
    let akey = armor_key(&svc.session_key, Some(&sub)).expect("akey");
    let mut fast_req = as_req(cname, TEST_REALM, 855, None).unwrap();
    let inner = fast_req.0.req_body.clone();
    wrap_fast_split_opts(
        &mut fast_req,
        &armor_ap,
        &akey,
        vec![pa_enc_timestamp(&key).expect("pa")],
        inner,
        krb5_types::fast::fast_options_none(),
    )
    .expect("FAST wrap");
    let err = krb5_kdc::issue_as(&store, &fast_req).expect_err("host armor");
    assert_find_fast(err, err::SERVER_NOMATCH, "FAST armor TGT");
}

#[test]
fn explicit_as_armor_expired_tgt_is_tkt_expired() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = user_key();
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 851);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &issued.rep.0.ticket).expect("TGT");
    part.endtime = KerberosTime::now().add_seconds(-120).unwrap();
    let plain = encode(&part).expect("enc-tkt");
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let cipher = encrypt(&krbtgt.key, usage, &plain).expect("ticket");
    let mut ticket = issued.rep.0.ticket.clone();
    ticket.enc_part.cipher = cipher.into();
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x48u8; 32])
        .expect("subkey");
    let armor_ap = build_fast_armor(
        ticket,
        &issued.session_key,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .expect("armor");
    let akey = armor_key(&issued.session_key, Some(&sub)).expect("akey");
    let mut fast_req = as_req(cname, TEST_REALM, 852, None).unwrap();
    let inner = fast_req.0.req_body.clone();
    wrap_fast_split_opts(
        &mut fast_req,
        &armor_ap,
        &akey,
        vec![pa_enc_timestamp(&key).expect("pa")],
        inner,
        krb5_types::fast::fast_options_none(),
    )
    .expect("FAST wrap");
    let err = krb5_kdc::issue_as(&store, &fast_req).expect_err("expired armor");
    assert_eq!(issue_code(err), err::TKT_EXPIRED);
}

#[test]
fn explicit_as_armor_future_starttime_is_tkt_nyv() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = user_key();
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 856);
    let krbtgt = store.krbtgt().unwrap().first_current_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &issued.rep.0.ticket).expect("TGT");
    part.starttime = Some(KerberosTime::now().add_seconds(3600).unwrap());
    let plain = encode(&part).expect("enc-tkt");
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let cipher = encrypt(&krbtgt.key, usage, &plain).expect("ticket");
    let mut ticket = issued.rep.0.ticket.clone();
    ticket.enc_part.cipher = cipher.into();
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x4au8; 32])
        .expect("subkey");
    let armor_ap = build_fast_armor(
        ticket,
        &issued.session_key,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .expect("armor");
    let akey = armor_key(&issued.session_key, Some(&sub)).expect("akey");
    let mut fast_req = as_req(cname, TEST_REALM, 857, None).unwrap();
    let inner = fast_req.0.req_body.clone();
    wrap_fast_split_opts(
        &mut fast_req,
        &armor_ap,
        &akey,
        vec![pa_enc_timestamp(&key).expect("pa")],
        inner,
        krb5_types::fast::fast_options_none(),
    )
    .expect("FAST wrap");
    let err = krb5_kdc::issue_as(&store, &fast_req).expect_err("future starttime armor");
    assert_find_fast(err, err::TKT_NYV, "FAST armor NYV");
}

#[test]
fn fast_as_armor_without_subkey_is_policy() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let armor_as = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 880);
    let armor_ap = build_fast_armor(
        armor_as.rep.0.ticket.clone(),
        &armor_as.session_key,
        &ascii(TEST_REALM),
        &cname,
        None,
    )
    .expect("armor AP-REQ");
    let akey = armor_key(&armor_as.session_key, None).expect("armor key");
    let mut req = as_req(cname, TEST_REALM, 881, None).unwrap();
    attach_fast(&mut req, &armor_ap, &akey, Vec::new()).expect("FAST wrap");
    let err = krb5_kdc::issue_as(&store, &req).expect_err("no subkey");
    assert_find_fast(err, err::POLICY, "ap-request armor without subkey");
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).expect("der")).expect("reply");
    assert_krb_error(&bytes, err::POLICY, "FIND_FAST");
}

#[test]
fn fast_as_corrupt_enc_fast_req_is_bad_integrity_find_fast() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let (mut req, _) = fast_as_prepared(&store, 916);
    map_fx_fast_as(&mut req, |a| {
        let mut c = a.enc_fast_req.cipher.to_vec();
        c[0] ^= 0xff;
        a.enc_fast_req.cipher = c.into();
    });
    let err = krb5_kdc::issue_as(&store, &req).expect_err("corrupt enc_fast_req");
    assert_find_fast(err, err::BAD_INTEGRITY, "integrity check failed");
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).expect("der")).expect("reply");
    assert_krb_error(&bytes, err::BAD_INTEGRITY, "FIND_FAST");
}

#[test]
fn fast_as_corrupt_enc_and_bad_checksum_is_bad_integrity() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let (mut req, _) = fast_as_prepared(&store, 950);
    map_fx_fast_as(&mut req, |a| {
        let mut c = a.enc_fast_req.cipher.to_vec();
        c[0] ^= 0xff;
        a.enc_fast_req.cipher = c.into();
        let mut ck = a.req_checksum.checksum.to_vec();
        ck[0] ^= 0xff;
        a.req_checksum.checksum = ck.into();
    });
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).expect("der")).expect("reply");
    assert_krb_error(&bytes, err::BAD_INTEGRITY, "FIND_FAST");
}

#[test]
fn fast_as_malformed_krbfastreq_is_generic_find_fast() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let (mut req, akey) = fast_as_prepared(&store, 918);
    let enc_usage = KeyUsage::new(ku::FAST_ENC).unwrap();
    let cipher = encrypt(&akey, enc_usage, &[0x30, 0x01, 0x00]).expect("enc");
    map_fx_fast_as(&mut req, |a| {
        a.enc_fast_req.cipher = cipher.into();
    });
    let err = krb5_kdc::issue_as(&store, &req).expect_err("malformed KrbFastReq");
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).expect("der")).expect("reply");
    assert_krb_error(&bytes, err::GENERIC, "FIND_FAST");
    match err {
        Error::Protocol {
            code,
            text,
            detail: d,
            ..
        } => {
            assert_eq!(code, err::GENERIC);
            assert_eq!(text.as_deref(), Some("FIND_FAST"));
            let d = d.expect("detail");
            assert!(
                d.starts_with("DER decode failed"),
                "detail {d:?} is not an ASN.1 decode"
            );
        }
        other => panic!("expected 60 FIND_FAST ASN.1, got {other:?}"),
    }
}

#[test]
fn fast_as_arcfour_hmac_type_over_aes_key_wrong_bytes_is_modified() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let (mut req, _) = fast_as_prepared(&store, 922);
    map_fx_fast_as(&mut req, |a| {
        a.req_checksum.cksumtype = -138;
        a.req_checksum.checksum = vec![0xff; 16].into();
    });
    let err = krb5_kdc::issue_as(&store, &req).expect_err("-138 over aes");
    assert_find_fast(err, err::MODIFIED, "modified checksum");
}

#[test]
fn fast_as_same_provider_type_wrong_bytes_is_modified() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let (mut req, _) = fast_as_prepared_etype(&store, 924, EncryptionType::Aes128CtsHmacSha196);
    map_fx_fast_as(&mut req, |a| {
        a.req_checksum.cksumtype = 19;
        a.req_checksum.checksum = vec![0xff; 16].into();
    });
    let err = krb5_kdc::issue_as(&store, &req).expect_err("type 19 over aes128-sha1");
    assert_find_fast(err, err::MODIFIED, "modified checksum");
}

#[test]
fn fast_as_cross_provider_type_is_generic() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let (mut req, _) = fast_as_prepared(&store, 926);
    map_fx_fast_as(&mut req, |a| a.req_checksum.cksumtype = 15);
    let err = krb5_kdc::issue_as(&store, &req).expect_err("type 15 over aes256");
    assert_find_fast(err, err::GENERIC, "Bad encryption type");
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).expect("der")).expect("reply");
    assert_krb_error(&bytes, err::GENERIC, "FIND_FAST");
}

#[test]
fn fast_as_provider_mismatch_detail_is_bad_enctype() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let (mut req, _) = fast_as_prepared(&store, 952);
    map_fx_fast_as(&mut req, |a| a.req_checksum.cksumtype = 15);
    let err = krb5_kdc::issue_as(&store, &req).expect_err("type 15 over aes256");
    assert_find_fast(err, err::GENERIC, "Bad encryption type");
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).expect("der")).expect("reply");
    assert_krb_error(&bytes, err::GENERIC, "FIND_FAST");
}

#[test]
fn fast_as_cksumtype_zero_valid_mac_is_policy() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let (mut req, akey) = fast_as_prepared(&store, 928);
    let body = encode(&req.0.req_body).expect("body");
    let ck_usage = KeyUsage::new(ku::FAST_REQ_CHKSUM).unwrap();
    let mic = checksum(&akey, ck_usage, &body).expect("mic");
    map_fx_fast_as(&mut req, |a| {
        a.req_checksum.cksumtype = 0;
        a.req_checksum.checksum = mic.into();
    });
    let err = krb5_kdc::issue_as(&store, &req).expect_err("cksumtype 0");
    assert_find_fast(err, err::POLICY, "Unkeyed checksum used in fast_req");
}

#[test]
fn fast_as_bad_req_checksum_is_modified() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let (mut req, _) = fast_as_prepared(&store, 890);
    map_fx_fast_as(&mut req, |a| {
        let mut ck = a.req_checksum.checksum.to_vec();
        ck[0] ^= 0xff;
        a.req_checksum.checksum = ck.into();
    });
    let err = krb5_kdc::issue_as(&store, &req).expect_err("bad FAST checksum");
    assert_find_fast(err, err::MODIFIED, "modified checksum");
}

#[test]
fn fast_as_crc32_checksum_is_generic() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let (mut req, _) = fast_as_prepared(&store, 894);
    map_fx_fast_as(&mut req, |a| a.req_checksum.cksumtype = 1);
    let err = krb5_kdc::issue_as(&store, &req).expect_err("CRC32 FAST checksum");
    assert_find_fast(err, err::GENERIC, "unknown checksum type");
}

#[test]
fn fast_as_short_mac_is_generic() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let (mut req, _) = fast_as_prepared(&store, 1035);
    map_fx_fast_as(&mut req, |a| {
        a.req_checksum.cksumtype = 7;
        let mut ck = a.req_checksum.checksum.to_vec();
        ck.truncate(12);
        a.req_checksum.checksum = ck.into();
    });
    let err = krb5_kdc::issue_as(&store, &req).expect_err("short MAC on type 7");
    assert_find_fast(err, err::GENERIC, "checksum length");
}

#[test]
fn fast_as_rsa_md5_unkeyed_is_policy() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let (mut req, _) = fast_as_prepared(&store, 1070);
    let body = encode(&req.0.req_body).expect("body");
    let digest = krb5_crypto::unkeyed_checksum(7, &body).expect("md5");
    map_fx_fast_as(&mut req, |a| {
        a.req_checksum.cksumtype = 7;
        a.req_checksum.checksum = digest.into();
    });
    let err = krb5_kdc::issue_as(&store, &req).expect_err("RSA-MD5 unkeyed");
    assert_find_fast(err, err::POLICY, "Unkeyed checksum used in fast_req");
}

#[test]
fn fast_as_unkeyed_type_with_bad_bytes_is_modified() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let (mut req, _) = fast_as_prepared(&store, 908);
    map_fx_fast_as(&mut req, |a| {
        a.req_checksum.cksumtype = 7;
        a.req_checksum.checksum = vec![0xff; 16].into();
    });
    let err = krb5_kdc::issue_as(&store, &req).expect_err("unkeyed + bad bytes");
    assert_find_fast(err, err::MODIFIED, "modified checksum");
}

#[test]
fn fast_as_unknown_cksumtype_matches_mit() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let (mut req, _) = fast_as_prepared(&store, 912);
    map_fx_fast_as(&mut req, |a| a.req_checksum.cksumtype = 99);
    let err = krb5_kdc::issue_as(&store, &req).expect_err("unknown cksumtype");
    assert_find_fast(err, err::GENERIC, "unknown checksum type");
}

#[test]
fn fast_as_unknown_armor_type_is_preauth_failed() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let (mut req, _) = fast_as_prepared(&store, 898);
    map_fx_fast_as(&mut req, |a| {
        a.armor.as_mut().expect("armor").armor_type = 99;
    });
    let err = krb5_kdc::issue_as(&store, &req).expect_err("unknown armor");
    assert_find_fast(err, err::PREAUTH_FAILED, "Unknown FAST armor type 99");
}

#[test]
fn fast_as_checksum_ignores_pa_tgs_req() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let (mut req, akey) = fast_as_prepared(&store, 900);
    let dummy = b"dummy-pa-tgs-req-not-the-body";
    let ck_usage = KeyUsage::new(ku::FAST_REQ_CHKSUM).unwrap();
    let mic = checksum(&akey, ck_usage, dummy).expect("mic");
    map_fx_fast_as(&mut req, |a| {
        a.req_checksum.checksum = mic.into();
    });
    req.0.padata.as_mut().unwrap().insert(
        0,
        PaData {
            padata_type: pa::TGS_REQ,
            padata_value: dummy.to_vec().into(),
        },
    );
    let err = krb5_kdc::issue_as(&store, &req).expect_err("body-only FAST checksum");
    assert_find_fast(err, err::MODIFIED, "modified checksum");
}

#[test]
fn fast_as_checksum_binds_wire_body() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let (req, akey) = fast_as_prepared(&store, 914);
    let raw = encode(&req).expect("der");
    let Some(mut wire) = long_form_kdc_body(&raw) else {
        panic!("could not expand KDC-REQ-BODY length");
    };
    let decoded = decode::<krb5_types::AsReq>(&wire);
    assert!(
        decoded.is_ok(),
        "decoder must accept the expanded body (shape of the wire-bind test): {decoded:?}"
    );
    let canon = encode(&decoded.unwrap().0.req_body).expect("re-encode");
    let (tag, _, app, _) = der_take(&wire).expect("app");
    assert_eq!(tag, 0x6a);
    let (t, _, seq, _) = der_take(app).expect("seq");
    let body_seq = if t == 0x30 { seq } else { app };
    let mut cur = body_seq;
    let mut body = None;
    while let Some((tag, _, inner, rest)) = der_take(cur) {
        if tag == 0xa4 {
            body = Some(inner.to_vec());
            break;
        }
        cur = rest;
    }
    let body = body.expect("body");
    assert_ne!(
        body, canon,
        "wire body must differ from canonical re-encode"
    );
    let ck_usage = KeyUsage::new(ku::FAST_REQ_CHKSUM).unwrap();
    let mic = checksum(&akey, ck_usage, &body).expect("mic");
    let old = {
        let armored = {
            let pa = req
                .0
                .padata
                .as_ref()
                .unwrap()
                .iter()
                .find(|p| p.padata_type == pa::FX_FAST)
                .expect("FAST");
            let krb5_types::fast::PaFxFast::ArmoredData(a) =
                decode(pa.padata_value.as_ref()).expect("fast");
            a
        };
        armored.req_checksum.checksum.to_vec()
    };
    assert_eq!(old.len(), mic.len());
    let pos = wire
        .windows(old.len())
        .position(|w| w == old.as_slice())
        .expect("old mic");
    wire[pos..pos + mic.len()].copy_from_slice(&mic);
    let bytes = krb5_kdc::handle_request(&store, &wire).expect("reply");
    assert_ne!(
        bytes.first(),
        Some(&0x7e),
        "FAST wire checksum must not be KRB-ERROR"
    );
}

#[test]
fn cookie_survives_krbtgt_kvno_rollover() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = store
        .get_name(&cname)
        .expect("user")
        .key_for(EncryptionType::Aes256CtsHmacSha196)
        .expect("aes256-sha1 key")
        .key
        .clone();
    let support = pa_spake_support();
    let req1 = as_req(cname.clone(), TEST_REALM, 701, Some(vec![support.clone()])).unwrap();
    let err = krb5_kdc::issue_as(&store, &req1).unwrap_err();
    let e_data = match err {
        Error::Protocol {
            code,
            e_data: Some(e_data),
            ..
        } if code == err::MORE_PREAUTH_DATA_REQUIRED => e_data,
        other => panic!("expected SPAKE 91, got {other:?}"),
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    assert!(
        method.iter().any(|p| p.padata_type == pa::ETYPE_INFO2),
        "91 without cookie carries ETYPE-INFO2: {:?}",
        method.iter().map(|p| p.padata_type).collect::<Vec<_>>()
    );
    let spa = method
        .iter()
        .find(|p| p.padata_type == pa::SPAKE)
        .expect("PA-SPAKE");
    let cookie = method
        .iter()
        .find(|p| p.padata_type == pa::FX_COOKIE)
        .expect("cookie")
        .padata_value
        .as_ref()
        .to_vec();
    assert!(cookie.starts_with(b"MIT1") && cookie.len() > 8);
    let old_kvno = u32::from_be_bytes([cookie[4], cookie[5], cookie[6], cookie[7]]);
    let msg: krb5_types::spake::PaSpake = decode(spa.padata_value.as_ref()).expect("PaSpake");
    let chal = match msg {
        krb5_types::spake::PaSpake::Challenge(c) => c,
        other => panic!("expected SPAKE challenge, got {other:?}"),
    };

    let krbtgt = PrincipalName::krbtgt(TEST_REALM);
    store.chrand_keepold_n(&krbtgt, 1).expect("keepold");
    let new_kvno = store
        .get_name(&krbtgt)
        .expect("krbtgt")
        .first_current_key()
        .expect("current")
        .kvno;
    assert_ne!(old_kvno, new_kvno, "rollover must advance kvno");
    assert!(
        store
            .get_name(&krbtgt)
            .expect("krbtgt")
            .first_key_at_kvno(old_kvno)
            .is_some(),
        "keepold retains the minting key"
    );

    let mut req2 = as_req(cname, TEST_REALM, 702, None).unwrap();
    let body_der = encode(&req2.0.req_body).expect("body");
    let (resp, spake_key) = pa_spake_response(
        &key,
        support.padata_value.as_ref(),
        spa.padata_value.as_ref(),
        chal.pubkey.as_ref(),
        &body_der,
    )
    .expect("resp");
    req2.0.padata = Some(vec![
        resp,
        krb5_types::PaData {
            padata_type: pa::FX_COOKIE,
            padata_value: cookie.into(),
        },
    ]);
    let issued = krb5_kdc::issue_as(&store, &req2).expect("old-kvno cookie still opens");
    assert_eq!(issued.as_rep_key.as_bytes(), spake_key.as_bytes());
}

const AES128: EncryptionType = EncryptionType::Aes128CtsHmacSha196;

const AES256: EncryptionType = EncryptionType::Aes256CtsHmacSha196;

fn user_name() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
}

fn store_permitting_aes256() -> PrincipalStore {
    krb5_config::isolate_test_krb5();
    let (mut store, _) = bootstrap_documented().unwrap();
    let kdc = krb5_config::KdcConf::parse(
        "[libdefaults]\n permitted_enctypes = aes256-cts-hmac-sha1-96\n",
    )
    .unwrap();
    store.apply_kdc_conf(&kdc).unwrap();
    assert!(store.policy().etype_permitted(AES256));
    assert!(!store.policy().etype_permitted(AES128));
    store
}

fn set_krbtgt_keys(store: &mut PrincipalStore, keys: Vec<KeyEntry>, keepold: u32) {
    store
        .set_keys(&PrincipalName::krbtgt(TEST_REALM), keys, keepold)
        .unwrap();
}

fn issue_user_tgt(store: &PrincipalStore, nonce: u32) -> krb5_kdc::IssuedAs {
    let key = store
        .get_name(&user_name())
        .unwrap()
        .keys
        .iter()
        .find(|k| k.etype == AES256)
        .expect("user aes256")
        .key
        .clone();
    let req = as_req(
        user_name(),
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).expect("AS issues")
}

fn reseal_ticket(ticket: &Ticket, old: &ProtocolKey, new: &ProtocolKey) -> Ticket {
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let plain = decrypt(old, usage, ticket.enc_part.cipher.as_ref()).expect("decrypt tkt");
    let part: EncTicketPart = decode(&plain).expect("enc-tkt");
    let der = encode(&part).expect("re-encode");
    let cipher = encrypt(new, usage, &der).expect("reseal");
    let mut out = ticket.clone();
    out.enc_part.cipher = cipher.into();
    out.enc_part.etype = new.etype().to_iana();
    out
}

fn fast_as_with_armor_ticket(
    store: &PrincipalStore,
    ticket: Ticket,
    session: &ProtocolKey,
    nonce: u32,
) -> Result<krb5_kdc::IssuedAs, krb5_kdc::Error> {
    let sub = ProtocolKey::from_bytes(AES256, &[0x61u8; 32]).unwrap();
    let armor_ap = build_fast_armor(
        ticket,
        session,
        &ascii(TEST_REALM),
        &user_name(),
        Some(&sub),
    )
    .expect("armor AP-REQ");
    let akey = armor_key(session, Some(&sub)).expect("armor key");
    let user_key = store
        .get_name(&user_name())
        .unwrap()
        .keys
        .iter()
        .find(|k| k.etype == AES256)
        .expect("user aes256")
        .key
        .clone();
    let mut req = as_req(user_name(), TEST_REALM, nonce, None).unwrap();
    attach_fast(
        &mut req,
        &armor_ap,
        &akey,
        vec![pa_enc_timestamp(&user_key).unwrap()],
    )
    .expect("FAST wrap");
    krb5_kdc::issue_as(store, &req)
}

fn assert_find_fast_z6_armor_enctype(err: krb5_kdc::Error, code: i32) {
    match err {
        krb5_kdc::Error::Protocol {
            code: got,
            text,
            detail,
            ..
        } => {
            assert_eq!(got, code, "wire code, detail={detail:?}");
            assert_eq!(text.as_deref(), Some("FIND_FAST"));
            assert_eq!(detail.as_deref(), Some("FAST armor TGT"));
        }
        other => panic!("expected {code} FIND_FAST, got {other:?}"),
    }
}

#[test]
fn armor_tgt_under_a_non_permitted_etype_is_generic_find_fast() {
    let mut store = store_permitting_aes256();
    set_krbtgt_keys(
        &mut store,
        vec![
            KeyEntry::new(AES128, random_key(AES128).unwrap(), 0),
            KeyEntry::new(AES256, random_key(AES256).unwrap(), 0),
        ],
        0,
    );
    let tgt = issue_user_tgt(&store, 0x2600_0061);
    assert_eq!(tgt.rep.0.ticket.enc_part.etype, AES256.to_iana());
    let krbtgt = store.get_name(&PrincipalName::krbtgt(TEST_REALM)).unwrap();
    let aes128 = krbtgt.keys.iter().find(|k| k.etype == AES128).unwrap();
    let aes256 = krbtgt.keys.iter().find(|k| k.etype == AES256).unwrap();
    let forged = reseal_ticket(&tgt.rep.0.ticket, &aes256.key, &aes128.key);
    assert_eq!(forged.enc_part.etype, AES128.to_iana());
    let err = fast_as_with_armor_ticket(&store, forged, &tgt.session_key, 0x2600_0062)
        .expect_err("non-permitted armor etype");
    assert_find_fast_z6_armor_enctype(err, err::GENERIC);
}

#[test]
fn armor_tgt_labelled_n_sealed_under_n_plus_1_is_bad_integrity() {
    let (mut store, _) = bootstrap_documented().unwrap();
    set_krbtgt_keys(
        &mut store,
        vec![KeyEntry::new(AES256, random_key(AES256).unwrap(), 0)],
        0,
    );
    set_krbtgt_keys(
        &mut store,
        vec![KeyEntry::new(AES256, random_key(AES256).unwrap(), 0)],
        1,
    );
    let tgt = issue_user_tgt(&store, 0x2600_0065);
    let krbtgt = store.get_name(&PrincipalName::krbtgt(TEST_REALM)).unwrap();
    let top = krbtgt.keys.iter().map(|k| k.kvno).max().unwrap();
    assert!(top >= 2, "keepold must leave two kvnos, top={top}");
    let mut mislabelled = tgt.rep.0.ticket.clone();
    mislabelled.enc_part.kvno = Some(top - 1);
    let err = fast_as_with_armor_ticket(&store, mislabelled, &tgt.session_key, 0x2600_0066)
        .expect_err("mislabelled kvno");
    assert_find_fast_z6_armor_enctype(err, err::BAD_INTEGRITY);
}
