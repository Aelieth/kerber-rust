//! W1-B B1: `verify_as_reply` server principals.
//! MIT `get_in_tkt.c:227-239`. Live oracle: `client-differential-gate.sh`.

use krb5_protocol::verify_as_reply_server;
use krb5_types::{PrincipalName, ascii};

#[test]
fn b1_verify_as_srealm_vs_ticket_is_kdcrep_modified() {
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
fn b1_verify_as_srealm_vs_request_is_kdcrep_modified() {
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
fn b1_verify_as_canon_ok_allows_tgs_rename() {
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
fn b1_verify_as_canon_without_tgs_is_still_mismatch() {
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
fn b1_verify_as_matching_tgt_is_ok() {
    let sname = PrincipalName::krbtgt("KERBER.TEST");
    let realm = ascii("KERBER.TEST");
    verify_as_reply_server(&sname, &realm, &sname, &realm, &sname, "KERBER.TEST", false)
        .expect("default AS TGT");
}
