use super::*;
use krb5_types::{
    EncAsRepPart, EncTgsRepPart, EncryptionKey, OctetString, TicketFlags, ascii,
    kerberos_time_from_utc_z,
};

fn sample_part() -> EncKdcRepPart {
    let t = kerberos_time_from_utc_z("20260819120000Z").expect("sample time");
    EncKdcRepPart {
        key: EncryptionKey {
            keytype: 18,
            keyvalue: OctetString::from(vec![1u8; 32]),
        },
        last_req: vec![],
        nonce: 7,
        key_expiration: None,
        flags: TicketFlags::none(),
        authtime: t.clone(),
        starttime: None,
        endtime: t,
        renew_till: None,
        srealm: ascii("KERBER.TEST"),
        sname: PrincipalName::krbtgt("KERBER.TEST"),
        caddr: None,
        encrypted_pa_data: None,
    }
}

#[test]
fn application_26_and_rfc_25_and_untagged() {
    let part = sample_part();
    let der26 = encode(&EncTgsRepPart(part.clone())).expect("encode 26");
    assert_eq!(der26.first().copied(), Some(0x7a), "APPLICATION 26");
    assert_eq!(decode_enc_as(&der26).expect("decode 26"), part);
    let der25 = encode(&EncAsRepPart(part.clone())).expect("encode 25");
    assert_eq!(der25.first().copied(), Some(0x79), "APPLICATION 25");
    assert_eq!(decode_enc_as(&der25).expect("decode 25"), part);
    let untagged = encode(&part).expect("untagged");
    assert_eq!(decode_enc_as(&untagged).expect("untagged"), part);
    let other = [0x62, 0x03, 0x02, 0x01, 0x00];
    assert!(decode_enc_as(&other).is_err());
}

#[test]
fn authtime_outside_skew_is_rejected() {
    let mut part = sample_part();
    let now_t = KerberosTime::now();
    let now = i64::from(now_t.unix_seconds());
    part.authtime = now_t.clone();
    part.endtime = now_t
        .clone()
        .add_hours(10)
        .unwrap_or_else(|_| now_t.clone());
    super::check_as_rep_times_sync(&part, now, 300, false).unwrap();
    part.authtime = kerberos_time_from_utc_z("20000101000000Z").expect("old");
    part.starttime = Some(part.authtime.clone());
    part.endtime = now_t.clone().add_hours(10).unwrap_or(now_t);
    let err = super::check_as_rep_times_sync(&part, now, 300, false).unwrap_err();
    assert!(
        err.to_string()
            .contains("Clock skew too great in KDC reply"),
        "MIT get_in_tkt.c:266-269, got {err}"
    );
    super::check_as_rep_times_sync(&part, now, 300, true).unwrap();
    part.endtime = kerberos_time_from_utc_z("20000101010000Z").expect("old end");
    super::check_as_rep_times_sync(&part, now, 300, true).unwrap();
    assert!(super::check_as_rep_times_sync(&part, now, 300, false).is_err());
}
