//! R9: U2U missing second-ticket server is 7 `2ND_TKT_SERVER`
//! (`do_tgs_req.c:280-289` via `kdc_get_server_key(stkt)`).

use krb5_kdc::{
    TEST_ADMIN, TEST_ADMIN_PASSWORD, TEST_REALM, TEST_USER, TEST_USER_PASSWORD,
    bootstrap_documented, documented_host,
};
use krb5_testkit::{TgsReqBuilder, issue_tgt_password, pref_etypes, status};
use krb5_types::{KdcOptions, PrincipalName, err, flag_bit};

#[test]
fn u2u_missing_second_ticket_server_is_2nd_tkt_server() {
    let (store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 741);
    let admin_tgt = issue_tgt_password(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 742);
    let mut second = admin_tgt.rep.0.ticket.clone();
    // Outer sname does not exist; MIT `kdc_get_server_key` → 7 `2ND_TKT_SERVER`.
    second.sname = PrincipalName::new(PrincipalName::NT_SRV_INST, ["no-such-2ndtkt", TEST_REALM]);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::ENC_TKT_IN_SKEY, true);
    let tgs = TgsReqBuilder::new(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        743,
    )
    .options(opts)
    .additional_tickets(Some(vec![second]))
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    let (code, text) = status(&err);
    assert_eq!(code, err::S_PRINCIPAL_UNKNOWN);
    assert_eq!(text, Some("2ND_TKT_SERVER"));
}
