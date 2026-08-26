//! Fail-red fixture for the shipped differential compare path.

use krb5_protocol::{compare_krb_error, compare_stable_rep, Whitelist};
use krb5_types::{
    err, EncKdcRepPart, EncTicketPart, EncryptedData, EncryptionKey, KdcRep, KerberosTime,
    KrbError, Microseconds, PrincipalName, Ticket, TicketFlags, TransitedEncoding,
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
