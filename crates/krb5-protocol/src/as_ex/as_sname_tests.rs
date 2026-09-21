use super::*;

#[test]
fn flat_krbtgt_is_reply_mismatch() {
    let two = PrincipalName::krbtgt("KERBER.TEST");
    let flat = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["krbtgt/KERBER.TEST"]);
    assert_eq!(two.components_joined(), flat.components_joined());
    let err = as_sname_eq(&flat, &two, "AS-REP sname mismatch").unwrap_err();
    assert!(matches!(err, Error::ReplyMismatch(s) if s == "AS-REP sname mismatch"));
    let err = as_sname_eq(&two, &flat, "AS-REP sname mismatch").unwrap_err();
    assert!(matches!(err, Error::ReplyMismatch(_)));
}

#[test]
fn krbtgt_requested_service_sname_is_reply_mismatch() {
    let tgt = PrincipalName::krbtgt("KERBER.TEST");
    let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "testhost.kerber.test"]);
    let err = as_sname_eq(&host, &tgt, "AS-REP sname mismatch").unwrap_err();
    assert!(matches!(err, Error::ReplyMismatch(_)));
}

#[test]
fn changepw_sname_is_accepted() {
    let cpw = PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "changepw"]);
    as_sname_eq(&cpw, &cpw, "AS-REP sname mismatch").unwrap();
}
