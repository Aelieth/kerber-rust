//! `verify_as_reply` server principals.
//! MIT `get_in_tkt.c:227-239`. Live oracle: `client-differential-gate.sh`.

use krb5_config::set_test_krb5_paths;
use krb5_protocol::{check_as_rep_times, verify_as_reply_req_times, verify_as_reply_server};
use krb5_types::{
    EncKdcRepPart, EncryptionKey, KdcOptions, KerberosTime, OctetString, PrincipalName,
    TicketFlags, ascii, flag_bit, kerberos_time_from_utc_z,
};

#[test]
fn verify_as_srealm_vs_ticket_is_kdcrep_modified() {
    let sname = PrincipalName::krbtgt("KERBER.TEST");
    let enc_realm = ascii("KERBER.TEST");
    let tkt_realm = ascii("FORGED.TEST");
    let err = verify_as_reply_server(
        &sname,
        &enc_realm,
        &sname,
        &tkt_realm,
        &sname,
        "KERBER.TEST",
        false,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("sname/ticket"),
        "ticket.server realm must match enc srealm: {err}"
    );
}

#[test]
fn verify_as_srealm_vs_request_is_kdcrep_modified() {
    let sname = PrincipalName::krbtgt("KERBER.TEST");
    let realm = ascii("OTHER.TEST");
    let err = verify_as_reply_server(&sname, &realm, &sname, &realm, &sname, "KERBER.TEST", false)
        .unwrap_err();
    assert!(
        err.to_string().contains("sname mismatch"),
        "enc srealm must match the requested realm: {err}"
    );
}

#[test]
fn verify_as_canon_ok_allows_tgs_rename() {
    let asked = PrincipalName::krbtgt("SHORT");
    let issued = PrincipalName::krbtgt("KERBER.TEST");
    let realm = ascii("KERBER.TEST");
    verify_as_reply_server(
        &issued,
        &realm,
        &issued,
        &realm,
        &asked,
        "KERBER.TEST",
        true,
    )
    .expect("get_in_tkt.c:230-234 canon_ok when both are TGS");
}

#[test]
fn verify_as_canon_without_tgs_is_still_mismatch() {
    let asked = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "a.kerber.test"]);
    let issued = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "b.kerber.test"]);
    let realm = ascii("KERBER.TEST");
    let err = verify_as_reply_server(
        &issued,
        &realm,
        &issued,
        &realm,
        &asked,
        "KERBER.TEST",
        true,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("sname mismatch"),
        "canon_ok requires both names to be TGS: {err}"
    );
}

#[test]
fn verify_as_matching_tgt_is_ok() {
    let sname = PrincipalName::krbtgt("KERBER.TEST");
    let realm = ascii("KERBER.TEST");
    verify_as_reply_server(&sname, &realm, &sname, &realm, &sname, "KERBER.TEST", false)
        .expect("default AS TGT");
}

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
fn verify_times_endtime_after_till_is_kdcrep_modified() {
    let enc = sample_part();
    let till = kerberos_time_from_utc_z("20260819110000Z").expect("earlier till");
    let err = verify_as_reply_req_times(&enc, &till, None, None, &KdcOptions::none()).unwrap_err();
    assert!(
        err.to_string().contains("endtime after request till"),
        "{err}"
    );
}

#[test]
fn verify_times_endtime_at_till_is_ok() {
    let enc = sample_part();
    verify_as_reply_req_times(&enc, &enc.endtime, None, None, &KdcOptions::none())
        .expect("ts_after is strict >");
}

#[test]
fn verify_times_renew_till_after_rtime_is_kdcrep_modified() {
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
fn verify_times_renewable_ok_renew_till_after_till_is_kdcrep_modified() {
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
fn verify_times_postdated_from_mismatch_is_kdcrep_modified() {
    let enc = sample_part();
    let from = kerberos_time_from_utc_z("20260819130000Z").expect("from");
    let opts = KdcOptions::none().with_bit(flag_bit::POSTDATED, true);
    let err = verify_as_reply_req_times(&enc, &enc.endtime, None, Some(&from), &opts).unwrap_err();
    assert!(
        err.to_string().contains("starttime != request from"),
        "{err}"
    );
}

fn pin_timesync(on: bool) {
    let dir = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("CARGO_TARGET_DIR")
                .map(|p| std::path::PathBuf::from(p).join("test-krb5"))
        })
        .unwrap_or_else(|| {
            std::path::PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../target/test-krb5"
            ))
        });
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!(
        "b1-timesync-{}-{}.conf",
        std::process::id(),
        if on { "on" } else { "off" }
    ));
    let flag = if on { "yes" } else { "no" };
    std::fs::write(&path, format!("[libdefaults]\n    kdc_timesync = {flag}\n"))
        .expect("write timesync conf");
    set_test_krb5_paths(Some(vec![path]));
}

#[test]
fn kdc_timesync_accepts_authtime_outside_skew() {
    pin_timesync(true);
    let mut part = sample_part();
    let now_t = KerberosTime::now();
    let now = i64::from(now_t.unix_seconds());
    part.authtime = kerberos_time_from_utc_z("20000101000000Z").expect("old");
    part.starttime = Some(part.authtime.clone());
    part.endtime = now_t.add_hours(10).unwrap_or(now_t);
    check_as_rep_times(&part, now, 300).expect("MIT default kdc_timesync skips starttime");
}

#[test]
fn kdc_timesync_off_is_kdcrep_skew() {
    pin_timesync(false);
    let mut part = sample_part();
    let now_t = KerberosTime::now();
    let now = i64::from(now_t.unix_seconds());
    part.authtime = kerberos_time_from_utc_z("20000101000000Z").expect("old");
    part.starttime = Some(part.authtime.clone());
    part.endtime = now_t.add_hours(10).unwrap_or(now_t);
    let err = check_as_rep_times(&part, now, 300).expect_err("timesync=0");
    assert!(
        err.to_string()
            .contains("Clock skew too great in KDC reply"),
        "MIT get_in_tkt.c:266-269, got {err}"
    );
}

/// `set_request_times` clamps `rtime` to `till`
/// (`get_in_tkt.c:718-722`). Source pin so the inject compiles at the
/// parent (no public rtime getter there) and still fails.
#[test]
fn rtime_is_clamped_up_to_till() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/as_ex.rs"));
    assert!(
        src.contains("till.unix_seconds() > rt.unix_seconds()") || src.contains("if till > rtime"),
        "get_in_tkt.c:718-722 rtime = max(from+renew_life, till)"
    );
}
