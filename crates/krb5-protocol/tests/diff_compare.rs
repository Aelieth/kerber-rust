//! Fail-red fixture for the shipped differential compare path.

use crate::diff::{Whitelist, compare_krb_error, compare_preauth_e_data, compare_stable_rep};
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
    let rust = sample_error(err::C_PRINCIPAL_UNKNOWN, 0, "rust-text");
    let mit = sample_error(err::C_PRINCIPAL_UNKNOWN, 7, "mit-text");
    compare_krb_error(&rust, &mit).expect("time/e_text must be masked");

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
    let wl = Whitelist::default();
    let (r_rep, r_enc, r_tkt) = sample_parts("user", 0xaa, 0);
    let (m_rep, m_enc, m_tkt) = sample_parts("user", 0xbb, 11);
    compare_stable_rep(&r_rep, &r_enc, &r_tkt, &m_rep, &m_enc, &m_tkt, &wl)
        .expect("session key/times/cipher must be nulled");

    let (bad_rep, bad_enc, bad_tkt) = sample_parts("other", 0xbb, 11);
    let err = compare_stable_rep(&r_rep, &r_enc, &r_tkt, &bad_rep, &bad_enc, &bad_tkt, &wl)
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
            padata_type: pa::ENC_TIMESTAMP,
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
fn etype_info2_mit_subset_of_rust_passes_superset_fails() {
    let rust = method_edata(&[17, 18, 19, 20]);
    let mit = method_edata(&[18]);
    compare_preauth_e_data(Some(&rust), Some(&mit)).expect("MIT ⊆ Rust must pass");

    let mit_extra = method_edata(&[18, 23]);
    let rust_chosen = method_edata(&[18]);
    let err = compare_preauth_e_data(Some(&rust_chosen), Some(&mit_extra))
        .expect_err("MIT etype outside the Rust set must fail");
    assert!(
        err.0.contains("ETYPE-INFO2"),
        "shipped compare must name the etype mismatch: {}",
        err.0
    );
}

#[test]
fn unwhitelisted_ticket_flag_bit_fails_canonicalize_is_masked() {
    let wl = Whitelist::default();
    let (r_rep, r_enc, r_tkt) = sample_parts("user", 0xaa, 0);

    let (m_rep, mut m_enc, mut m_tkt) = sample_parts("user", 0xbb, 11);
    m_enc.flags = m_enc.flags.with_bit(flag_bit::CANONICALIZE, true);
    m_tkt.flags = m_tkt.flags.with_bit(flag_bit::CANONICALIZE, true);
    let ok = compare_stable_rep(&r_rep, &r_enc, &r_tkt, &m_rep, &m_enc, &m_tkt, &wl)
        .expect("canonicalize is a named whitelist bit");
    assert!(
        ok.whitelisted.contains(&"mit-extra-ticket-flags"),
        "canonicalize divergence must hit the named whitelist: {:?}",
        ok.whitelisted
    );

    let (b_rep, mut b_enc, mut b_tkt) = sample_parts("user", 0xbb, 11);
    b_enc.flags = b_enc.flags.with_bit(flag_bit::PROXY, true);
    b_tkt.flags = b_tkt.flags.with_bit(flag_bit::PROXY, true);
    let err = compare_stable_rep(&r_rep, &r_enc, &r_tkt, &b_rep, &b_enc, &b_tkt, &wl)
        .expect_err("PROXY is not a named whitelist bit");
    assert!(
        err.0.contains("stable-rep mismatch"),
        "un-whitelisted flag bit must fail red: {}",
        err.0
    );
}
