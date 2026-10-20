//! GSS acceptor kvno pinning.
//! MIT `try_one_princ` (`rd_req_dec.c:325-347`): a fully specified acceptor name fetches the
//! keytab entry by the exact ticket kvno; a key labelled M != N is not tried for a kvno-N
//! ticket. The plain `accept_sec_context` keeps MIT's wildcard/no-kvno iteration.

use krb5_gss::GssContext;
use krb5_kdc::S2K_ITERS;
use krb5_kdc::testrealm::{
    TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented, documented_admin_id,
    documented_host,
};
use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req};

use krb5_protocol::{AcceptorConfig, ReplayCache};
use krb5_types::{PrincipalName, ascii};

/// Build a real host/… GSS AP-REQ token and return it with the ticket-enc key
/// and its kvno.
fn host_token() -> (Vec<u8>, krb5_crypto::ProtocolKey, u32) {
    krb5_config::isolate_test_krb5();
    let (store, acl) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = krb5_crypto::string_to_key(
        krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
        TEST_USER_PASSWORD,
        cname.default_salt(TEST_REALM),
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .expect("s2k");
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        0x2500_0001,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &req).expect("AS");
    let tgs = tgs_req(
        as_out.rep.0.ticket,
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        0x2500_0002,
    )
    .expect("TGS-REQ");
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).expect("TGS");
    let (_init, token) = GssContext::init_sec_context(
        tgs_out.rep.0.ticket,
        &tgs_out.session_key,
        &ascii(TEST_REALM),
        &cname,
        krb5_gss::GSS_C_REPLAY | krb5_gss::GSS_C_SEQUENCE,
        None,
        None,
    )
    .expect("init token");
    let kt = store
        .export_keytab(&acl, &documented_admin_id(), &documented_host())
        .expect("keytab");
    let ent = kt.entries.into_iter().next().expect("host key");
    (token, ent.key, ent.kvno)
}

#[test]
fn gss_accept_kt_pins_ticket_kvno() {
    let (token, skey, kvno) = host_token();
    assert_eq!(kvno, 1);
    let host = documented_host();

    // Plain accept keeps MIT's no-kvno iteration: the ticket opens under the key
    // regardless of the (here mismatched) keytab label.
    GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(&skey),
        None,
        Some(&host),
        Some(TEST_REALM),
        &ReplayCache::new(),
        &AcceptorConfig::default(),
    )
    .expect("plain accept ignores kvno labels");

    // With kvnos + a fully specified server, a key labelled kvno 2 is not tried
    // for the kvno-1 ticket (try_one_princ get_entry(kvno=1) finds nothing) —
    // MIT keytab_fetch_error: KRB5KRB_AP_ERR_BADKEYVER (44) "Cannot find key for
    // host/… kvno 1 in keytab".
    match GssContext::accept_sec_context_kt(
        &token,
        std::slice::from_ref(&skey),
        Some(&[2u32]),
        None,
        Some(&host),
        Some(TEST_REALM),
        &ReplayCache::new(),
        &AcceptorConfig::default(),
    ) {
        Ok(_) => panic!("kt accept must pin the ticket kvno"),
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("44") && msg.contains("Cannot find key for host/"),
                "expected MIT's BADKEYVER refusal, got {msg}"
            );
        }
    }
}

#[test]
fn gss_accept_kt_matching_kvno_verifies() {
    let (token, skey, kvno) = host_token();
    let host = documented_host();
    GssContext::accept_sec_context_kt(
        &token,
        std::slice::from_ref(&skey),
        Some(&[kvno]),
        None,
        Some(&host),
        Some(TEST_REALM),
        &ReplayCache::new(),
        &AcceptorConfig::default(),
    )
    .expect("matching kvno verifies");
}

/// An acceptor over a keytab it cannot walk, the KDB's, asks for the key by principal: for the server
/// the ticket names when it holds no name (`GSS_C_NO_NAME`), for the name it holds otherwise, and the
/// context's acceptor is then that principal, whatever server the ticket's cleartext names.
/// MIT `kg_accept_krb5` (`accept_sec_context.c:829-831`): `krb5_rd_req_decoded` with `acceptor_mprinc`, NULL for no name.
/// MIT `try_one_entry` (`rd_req_dec.c:315-317`): the keytab principal becomes the ticket's server.
#[test]
fn gss_accept_kdb_asks_for_the_tickets_server_or_the_name_it_holds() {
    let (token, skey, kvno) = host_token();
    let host = documented_host();
    let asked = std::cell::RefCell::new(Vec::new());
    let lookup = |n: &PrincipalName, r: &str, k: u32, e: i32| {
        asked.borrow_mut().push((n.clone(), r.to_owned(), k, e));
        Ok(skey.clone())
    };
    let (ctx, _) = GssContext::accept_sec_context_kdb(
        &token,
        None,
        TEST_REALM,
        &lookup,
        None,
        &ReplayCache::new(),
        &AcceptorConfig::default(),
    )
    .expect("no name: the ticket's server");
    assert_eq!(ctx.acceptor.as_ref(), Some(&host));
    let named = PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "admin"]);
    let (ctx, _) = GssContext::accept_sec_context_kdb(
        &token,
        Some(&named),
        TEST_REALM,
        &lookup,
        None,
        &ReplayCache::new(),
        &AcceptorConfig::default(),
    )
    .expect("a name: its key decrypts the ticket");
    assert_eq!(ctx.acceptor.as_ref(), Some(&named));
    assert_eq!(
        *asked.borrow(),
        [
            (host, TEST_REALM.to_owned(), kvno, 18),
            (named, TEST_REALM.to_owned(), kvno, 18)
        ]
    );
}

/// A lookup that finds no such principal is NOT_US where no name is held, which an acceptor with
/// several names goes on from, and NOKEY where the name is explicit.
/// MIT `keytab_fetch_error` (`rd_req_dec.c:118-148`): `KRB5_KT_NOTFOUND` is `explicit_server ? NOKEY : NOT_US`.
#[test]
fn gss_accept_kdb_with_no_such_principal_is_not_us_unless_the_name_is_explicit() {
    let (token, _, _) = host_token();
    let none =
        |_: &PrincipalName, _: &str, _: u32, _: i32| Err(krb5_protocol::KeytabLookup::NotFound);
    let refused = GssContext::accept_sec_context_kdb(
        &token,
        None,
        TEST_REALM,
        &none,
        None,
        &ReplayCache::new(),
        &AcceptorConfig::default(),
    )
    .map(|_| ());
    assert!(
        matches!(refused, Err(krb5_gss::Error::NotUs(_))),
        "{refused:?}"
    );
    let named = PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "admin"]);
    let refused = GssContext::accept_sec_context_kdb(
        &token,
        Some(&named),
        TEST_REALM,
        &none,
        None,
        &ReplayCache::new(),
        &AcceptorConfig::default(),
    )
    .map(|_| ());
    assert!(
        matches!(refused, Err(krb5_gss::Error::Inner(_))),
        "{refused:?}"
    );
}
