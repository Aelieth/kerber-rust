//! A′-4 item 16 units that compile at `e483047` and fail there.

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    EncryptionType, KeyUsage, ProtocolKey, checksum, decrypt, encrypt, krb_fx_cf2, string_to_key,
};
use krb5_kdc::{
    Error, PrincipalStore, S2K_ITERS, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, as_req,
    bootstrap_documented, documented_host, pa_enc_timestamp, tgs_req,
};
use krb5_protocol::{armor_key, attach_fast_with_options, build_fast_armor, unwrap_fast_rep};
use krb5_types::{
    ApReq, Checksum, EncryptedData, EncryptionKey, KrbError, PrincipalName, ascii, err, flag_bit,
    ku, pa,
};

fn password_key(name: &str, password: &[u8]) -> ProtocolKey {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]);
    string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        password,
        &cname.default_salt(TEST_REALM),
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .expect("s2k")
}

fn issue_tgt(
    store: &PrincipalStore,
    name: &str,
    password: &[u8],
    nonce: u32,
) -> krb5_kdc::IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]);
    let key = password_key(name, password);
    let req = as_req(
        cname,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).expect("AS")
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
fn a4_16_named_anon_without_preauth_is_still_13() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let mut req = as_req(cname, TEST_REALM, 57, None).unwrap();
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::ANONYMOUS, true);
    let (code, text) = match krb5_kdc::issue_as(&store, &req).unwrap_err() {
        Error::Protocol { code, text, .. } => (code, text),
        other => panic!("want Protocol 13 before preauth, got {other:?}"),
    };
    assert_eq!(code, err::BADOPTION);
    assert_eq!(text.as_deref(), Some("VALIDATE_ANONYMOUS_PRINCIPAL"));
}

#[test]
fn a4_16_fast_hide_as_error_client() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let armor_as = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 223);
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

#[test]
fn a4_16_tgs_fast_hide_outer_tgs_rep() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 851);
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
