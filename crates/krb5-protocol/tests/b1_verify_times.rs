//! W1-B B1: `verify_as_reply` request times.
//! MIT `get_in_tkt.c:243-255`. Live oracle: `client-differential-gate.sh`.

use krb5_protocol::verify_as_reply_req_times;
use krb5_types::{
    EncKdcRepPart, EncryptionKey, KdcOptions, OctetString, PrincipalName, TicketFlags, ascii,
    flag_bit, kerberos_time_from_utc_z,
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
fn b1_verify_times_endtime_after_till_is_kdcrep_modified() {
    let enc = sample_part();
    let till = kerberos_time_from_utc_z("20260819110000Z").expect("earlier till");
    let err = verify_as_reply_req_times(&enc, &till, None, None, &KdcOptions::none()).unwrap_err();
    assert!(
        err.to_string().contains("endtime after request till"),
        "{err}"
    );
}

#[test]
fn b1_verify_times_endtime_at_till_is_ok() {
    let enc = sample_part();
    verify_as_reply_req_times(&enc, &enc.endtime, None, None, &KdcOptions::none())
        .expect("ts_after is strict >");
}

#[test]
fn b1_verify_times_renew_till_after_rtime_is_kdcrep_modified() {
    let mut enc = sample_part();
    enc.renew_till = Some(kerberos_time_from_utc_z("20260820120000Z").expect("later rtime"));
    let rtime = kerberos_time_from_utc_z("20260819180000Z").expect("rtime");
    let opts = KdcOptions::none().with_bit(flag_bit::RENEWABLE, true);
    let err = verify_as_reply_req_times(&enc, &enc.endtime, Some(&rtime), None, &opts).unwrap_err();
    assert!(
        err.to_string().contains("renew-till after request rtime"),
        "{err}"
    );
}

#[test]
fn b1_verify_times_renewable_ok_renew_till_after_till_is_kdcrep_modified() {
    let mut enc = sample_part();
    enc.flags = TicketFlags::from_u32(0x0080_0000);
    enc.renew_till = Some(kerberos_time_from_utc_z("20260826120000Z").expect("7d"));
    let opts = KdcOptions::none().with_bit(flag_bit::RENEWABLE_OK, true);
    let err = verify_as_reply_req_times(&enc, &enc.endtime, None, None, &opts).unwrap_err();
    assert!(
        err.to_string().contains("renew-till after request till"),
        "{err}"
    );
}

#[test]
fn b1_verify_times_postdated_from_mismatch_is_kdcrep_modified() {
    let enc = sample_part();
    let from = kerberos_time_from_utc_z("20260819130000Z").expect("from");
    let opts = KdcOptions::none().with_bit(flag_bit::POSTDATED, true);
    let err = verify_as_reply_req_times(&enc, &enc.endtime, None, Some(&from), &opts).unwrap_err();
    assert!(
        err.to_string().contains("starttime != request from"),
        "{err}"
    );
}
