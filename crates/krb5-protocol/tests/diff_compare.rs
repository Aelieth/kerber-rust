//! Fail-red fixture for the shipped differential compare path.

use crate::diff::{compare_krb_error, compare_preauth_e_data, compare_stable_rep};
use krb5_asn1::encode;
use krb5_types::{
    EncKdcRepPart, EncTicketPart, EncryptedData, EncryptionKey, EtypeInfo2, EtypeInfo2Entry,
    KdcRep, KerberosTime, KrbError, MethodData, Microseconds, PaData, PrincipalName, Ticket,
    TicketFlags, TransitedEncoding, err, flag_bit, pa,
};

fn sample_error(code: i32, stime_off: i64, text: &str) -> KrbError {
    let stime = KerberosTime::now()
        .add_seconds(stime_off)
        .unwrap_or_else(|_| KerberosTime::now());
    KrbError {
        pvno: KrbError::PVNO,
        msg_type: KrbError::MSG_TYPE,
        ctime: None,
        cusec: None,
        stime,
        susec: Microseconds::ZERO,
        error_code: code,
        crealm: None,
        cname: None,
        realm: krb5_types::try_ascii("KERBER.TEST").unwrap(),
        sname: PrincipalName::krbtgt("KERBER.TEST"),
        e_text: krb5_types::try_ascii(text).ok(),
        e_data: None,
    }
}

fn sample_parts(
    cname: &str,
    key_byte: u8,
    time_off: i64,
) -> (KdcRep, EncKdcRepPart, EncTicketPart) {
    let now = KerberosTime::now()
        .add_seconds(time_off)
        .unwrap_or_else(|_| KerberosTime::now());
    let cname_p = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [cname]);
    let sname = PrincipalName::krbtgt("KERBER.TEST");
    let key = EncryptionKey {
        keytype: 18,
        keyvalue: vec![key_byte; 32].into(),
    };
    let enc = EncKdcRepPart {
        key,
        last_req: vec![],
        nonce: 1,
        key_expiration: None,
        flags: TicketFlags::initial_preauth(),
        authtime: now.clone(),
        starttime: Some(now.clone()),
        endtime: now.add_hours(10).unwrap_or_else(|_| now.clone()),
        renew_till: None,
        srealm: krb5_types::try_ascii("KERBER.TEST").unwrap(),
        sname: sname.clone(),
        caddr: None,
        encrypted_pa_data: None,
    };
    let tkt = EncTicketPart {
        flags: TicketFlags::initial_preauth(),
        key: EncryptionKey {
            keytype: 18,
            keyvalue: vec![key_byte; 32].into(),
        },
        crealm: krb5_types::try_ascii("KERBER.TEST").unwrap(),
        cname: cname_p.clone(),
        transited: TransitedEncoding::empty(),
        authtime: now.clone(),
        starttime: Some(now.clone()),
        endtime: now.add_hours(10).unwrap_or_else(|_| now.clone()),
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let rep = KdcRep {
        pvno: KdcRep::PVNO,
        msg_type: KdcRep::MSG_AS_REP,
        padata: None,
        crealm: krb5_types::try_ascii("KERBER.TEST").unwrap(),
        cname: cname_p,
        ticket: Ticket {
            tkt_vno: Ticket::VNO,
            realm: krb5_types::try_ascii("KERBER.TEST").unwrap(),
            sname,
            enc_part: EncryptedData {
                etype: 18,
                kvno: Some(1),
                cipher: vec![key_byte, 1, 2].into(),
            },
        },
        enc_part: EncryptedData {
            etype: 18,
            kvno: Some(1),
            cipher: vec![9, 9, 9].into(),
        },
    };
    (rep, enc, tkt)
}

#[test]
fn krb_error_volatile_only_passes_stable_mismatch_fails() {
    let rust = sample_error(err::C_PRINCIPAL_UNKNOWN, 0, "CLIENT_NOT_FOUND");
    let mit = sample_error(err::C_PRINCIPAL_UNKNOWN, 7, "CLIENT_NOT_FOUND");
    compare_krb_error(&rust, &mit).expect("times must be masked");
    let other = sample_error(err::C_PRINCIPAL_UNKNOWN, 0, "unknown client");
    compare_krb_error(&rust, &other).expect_err("e_text mismatch must fail");

    let bad = sample_error(err::S_PRINCIPAL_UNKNOWN, 0, "x");
    let err = compare_krb_error(&rust, &bad).expect_err("error_code mismatch must fail");
    assert!(
        err.0.contains("stable mismatch"),
        "shipped compare must name the stable mismatch: {}",
        err.0
    );
}

#[test]
fn success_volatile_only_passes_cname_mismatch_fails() {
    let (r_rep, r_enc, r_tkt) = sample_parts("user", 0xaa, 0);
    let (m_rep, m_enc, m_tkt) = sample_parts("user", 0xbb, 11);
    compare_stable_rep(&r_rep, &r_enc, &r_tkt, &m_rep, &m_enc, &m_tkt)
        .expect("session key/times/cipher must be nulled");

    let (bad_rep, bad_enc, bad_tkt) = sample_parts("other", 0xbb, 11);
    let err = compare_stable_rep(&r_rep, &r_enc, &r_tkt, &bad_rep, &bad_enc, &bad_tkt)
        .expect_err("cname mismatch must fail");
    assert!(
        err.0.contains("stable-rep mismatch"),
        "shipped compare must name the stable mismatch: {}",
        err.0
    );
}

fn method_edata(etypes: &[i32]) -> Vec<u8> {
    let info: EtypeInfo2 = etypes
        .iter()
        .map(|&etype| EtypeInfo2Entry {
            etype,
            salt: None,
            s2kparams: None,
        })
        .collect();
    let info_der = encode(&info).expect("ETYPE-INFO2");
    let md: MethodData = vec![
        PaData {
            padata_type: pa::FX_FAST,
            padata_value: vec![].into(),
        },
        PaData {
            padata_type: pa::ENC_TIMESTAMP,
            padata_value: vec![].into(),
        },
        PaData {
            padata_type: pa::ETYPE_INFO2,
            padata_value: info_der.into(),
        },
        PaData {
            padata_type: pa::FX_COOKIE,
            padata_value: b"MIT".to_vec().into(),
        },
    ];
    encode(&md).expect("METHOD-DATA")
}

fn method_edata_hw(etypes: &[i32]) -> Vec<u8> {
    let info: EtypeInfo2 = etypes
        .iter()
        .map(|&etype| EtypeInfo2Entry {
            etype,
            salt: None,
            s2kparams: None,
        })
        .collect();
    let info_der = encode(&info).expect("ETYPE-INFO2");
    let md: MethodData = vec![
        PaData {
            padata_type: pa::FX_FAST,
            padata_value: vec![].into(),
        },
        PaData {
            padata_type: pa::ETYPE_INFO2,
            padata_value: info_der.into(),
        },
        PaData {
            padata_type: pa::FX_COOKIE,
            padata_value: b"MIT".to_vec().into(),
        },
    ];
    encode(&md).expect("METHOD-DATA")
}

fn method_edata_no_cookie(etypes: &[i32]) -> Vec<u8> {
    let info: EtypeInfo2 = etypes
        .iter()
        .map(|&etype| EtypeInfo2Entry {
            etype,
            salt: None,
            s2kparams: None,
        })
        .collect();
    let info_der = encode(&info).expect("ETYPE-INFO2");
    let md: MethodData = vec![
        PaData {
            padata_type: pa::FX_FAST,
            padata_value: vec![].into(),
        },
        PaData {
            padata_type: pa::ETYPE_INFO2,
            padata_value: info_der.into(),
        },
    ];
    encode(&md).expect("METHOD-DATA")
}

#[test]
fn etype_info2_requires_exact_etype_set() {
    // MIT's hint (get_preauth_hint_list) and Rust's both list one entry for
    // the selected client key, so the etype sets must be equal.
    let one = method_edata(&[18]);
    compare_preauth_e_data(Some(&one), Some(&one)).expect("equal etype sets pass");

    // Rust listing every key (a superset) no longer passes.
    let rust_super = method_edata(&[17, 18, 19, 20]);
    let mit_one = method_edata(&[18]);
    let err = compare_preauth_e_data(Some(&rust_super), Some(&mit_one))
        .expect_err("a Rust superset must now fail");
    assert!(
        err.0.contains("ETYPE-INFO2"),
        "shipped compare must name the etype mismatch: {}",
        err.0
    );

    // MIT etype outside the Rust set still fails.
    let rust_one = method_edata(&[18]);
    let mit_extra = method_edata(&[18, 23]);
    compare_preauth_e_data(Some(&rust_one), Some(&mit_extra))
        .expect_err("MIT etype outside the Rust set must fail");

    let hw = method_edata_hw(&[18]);
    compare_preauth_e_data(Some(&hw), Some(&hw)).expect("hw_only both omit ENC_TIMESTAMP");
    compare_preauth_e_data(Some(&one), Some(&hw))
        .expect_err("ENC_TIMESTAMP present on only one side");
}

#[test]
fn preauth_edata_requires_fx_cookie_and_fx_fast() {
    let with = method_edata_hw(&[18]);
    compare_preauth_e_data(Some(&with), Some(&with)).expect("[136, 19, 133] both legs");
    let no_cookie = method_edata_no_cookie(&[18]);
    let err = compare_preauth_e_data(Some(&with), Some(&no_cookie))
        .expect_err("as-hw-preauth without 133 must fail");
    assert!(
        err.0.contains("133") || err.0.contains(&pa::FX_COOKIE.to_string()),
        "compare must name the missing cookie: {}",
        err.0
    );
}

#[test]
fn ticket_flag_bit_differences_fail_red() {
    let (r_rep, r_enc, r_tkt) = sample_parts("user", 0xaa, 0);

    // The enc-pa-rep bit (== CANONICALIZE bit 15) is compared: MIT sets it on
    // every ticket, so a divergence must fail red (W1-J L3a).
    let (m_rep, mut m_enc, mut m_tkt) = sample_parts("user", 0xbb, 11);
    m_enc.flags = m_enc.flags.with_bit(flag_bit::ENC_PA_REP, true);
    m_tkt.flags = m_tkt.flags.with_bit(flag_bit::ENC_PA_REP, true);
    let err = compare_stable_rep(&r_rep, &r_enc, &r_tkt, &m_rep, &m_enc, &m_tkt)
        .expect_err("enc-pa-rep bit is compared, not masked");
    assert!(err.0.contains("stable-rep mismatch"), "{}", err.0);

    let (b_rep, mut b_enc, mut b_tkt) = sample_parts("user", 0xbb, 11);
    b_enc.flags = b_enc.flags.with_bit(flag_bit::PROXY, true);
    b_tkt.flags = b_tkt.flags.with_bit(flag_bit::PROXY, true);
    let err = compare_stable_rep(&r_rep, &r_enc, &r_tkt, &b_rep, &b_enc, &b_tkt)
        .expect_err("PROXY is compared like every bit");
    assert!(
        err.0.contains("stable-rep mismatch"),
        "any flag-bit difference must fail red: {}",
        err.0
    );

    // With the whitelist mechanism deleted (W1-K M2b), the RENEWABLE bit is no
    // longer masked; a renewable divergence must also fail red.
    let (n_rep, mut n_enc, mut n_tkt) = sample_parts("user", 0xbb, 11);
    n_enc.flags = n_enc.flags.with_bit(flag_bit::RENEWABLE, true);
    n_tkt.flags = n_tkt.flags.with_bit(flag_bit::RENEWABLE, true);
    let err = compare_stable_rep(&r_rep, &r_enc, &r_tkt, &n_rep, &n_enc, &n_tkt)
        .expect_err("RENEWABLE is compared, not masked");
    assert!(err.0.contains("stable-rep mismatch"), "{}", err.0);
}
