//! kpropd `authorized_principal` (MIT `kpropd.c:1298-1348`) on the
//! wire. The ACL is a list of exact unparsed principals with an optional
//! enctype restriction; there are no wildcards; the check runs after
//! `recvauth` has sent the AP-REP, and a refused peer just sees the socket
//! close (`kpropd.c:528-546`). Live oracle: MIT kpropd in
//! `scripts/prop-acl-gate.sh` (`acl-*` cells).

use krb5_admin::{Error, KpropAuth, kprop_send_dump, kprop_sendauth, kpropd_recvauth};
use krb5_crypto::ProtocolKey;
use krb5_kdc::testrealm::{TEST_HOST, TEST_REALM, bootstrap_documented, documented_host};
use krb5_kdc::{PrincipalStore, issue_as, issue_tgs};

use krb5_protocol::{ReplayCache, as_req, pa_enc_timestamp, tgs_req};
use krb5_types::Ticket;
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};

const CLIENT: &str = "host/testhost.kerber.test@KERBER.TEST";

fn host_ticket(store: &PrincipalStore) -> (Ticket, ProtocolKey, i32) {
    let host = documented_host();
    let key = store
        .get_name(&host)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let pa = pa_enc_timestamp(&key).unwrap();
    let as_out = issue_as(
        store,
        &as_req(host.clone(), TEST_REALM, 1, Some(vec![pa])).unwrap(),
    )
    .unwrap();
    let tgs = tgs_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        2,
    )
    .unwrap();
    let out = issue_tgs(store, &tgs).unwrap();
    let etype = out.rep.0.ticket.enc_part.etype;
    (out.rep.0.ticket, out.session_key, etype)
}

fn spawn_kpropd(
    store: &PrincipalStore,
    acl: Option<Vec<String>>,
) -> (std::net::SocketAddr, JoinHandle<Result<KpropAuth, Error>>) {
    let host_keys: Vec<_> = store
        .get_name(&documented_host())
        .unwrap()
        .keys
        .iter()
        .map(|k| k.key.clone())
        .collect();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = documented_host();
    let join = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        kpropd_recvauth(
            &mut stream,
            &host_keys,
            Some(&server),
            Some(TEST_REALM),
            acl.as_deref(),
            ReplayCache::new(),
        )
    });
    (addr, join)
}

fn kprop_against(acl: Option<Vec<String>>) -> (Result<KpropAuth, Error>, Result<KpropAuth, Error>) {
    let (store, _) = bootstrap_documented().unwrap();
    let (ticket, session, _) = host_ticket(&store);
    let (addr, join) = spawn_kpropd(&store, acl);
    let mut client = TcpStream::connect(addr).unwrap();
    let cname = documented_host();
    let client_auth = kprop_sendauth(
        &mut client,
        ticket,
        &session,
        &krb5_types::ascii(TEST_REALM),
        &cname,
        7,
    );
    let server_auth = join.join().expect("kpropd thread");
    (server_auth, client_auth)
}

fn shown(r: &Result<KpropAuth, Error>) -> Result<(), String> {
    r.as_ref().map(|_| ()).map_err(ToString::to_string)
}

fn refused(r: &Result<KpropAuth, Error>) -> bool {
    r.as_ref().err().map(ToString::to_string)
        == Some(format!(
            "Rejected connection from unauthorized principal {CLIENT}"
        ))
}

#[test]
fn kpropd_acl_exact_line_authorizes_and_wildcards_never_do() {
    let (ok, client) = kprop_against(Some(vec![CLIENT.to_owned()]));
    assert!(ok.is_ok(), "exact line: {:?}", shown(&ok));
    assert!(client.is_ok(), "client sendauth: {:?}", shown(&client));
    // kadm5.acl-style globs are not kpropd.acl syntax (`strncmp` on the
    // unparsed name): MIT refuses `*@KERBER.TEST` and `host/*@KERBER.TEST`.
    let (star, _) = kprop_against(Some(vec![
        "*@KERBER.TEST".to_owned(),
        "host/*@KERBER.TEST".to_owned(),
        "*".to_owned(),
    ]));
    assert!(
        refused(&star),
        "wildcard lines must not authorize: {:?}",
        shown(&star)
    );
}

#[test]
fn kpropd_acl_enctype_suffix_must_name_the_ticket_enctype() {
    let (store, _) = bootstrap_documented().unwrap();
    let (_, _, tkt_etype) = host_ticket(&store);
    let tkt_name = krb5_crypto::EncryptionType::known(tkt_etype)
        .unwrap()
        .to_mit_name();
    // Another supported enctype than the one the ticket was issued with.
    let other = if tkt_etype == 18 {
        "aes128-cts"
    } else {
        "aes256-cts"
    };
    let (m, _) = kprop_against(Some(vec![format!("{CLIENT} {tkt_name}")]));
    assert!(m.is_ok(), "matching enctype restriction: {:?}", shown(&m));
    // strcasecmp: the alias in upper case is the same enctype.
    let (upper, _) = kprop_against(Some(vec![format!("{CLIENT}\t{}", tkt_name.to_uppercase())]));
    assert!(
        upper.is_ok(),
        "upper-case enctype alias: {:?}",
        shown(&upper)
    );
    let (mismatch, _) = kprop_against(Some(vec![format!("{CLIENT} {other}")]));
    assert!(
        refused(&mismatch),
        "enctype mismatch must refuse: {:?}",
        shown(&mismatch)
    );
    // krb5_string_to_enctype EINVAL (unknown name, a number, two names, a
    // trailing CR) skips the line rather than ignoring the token.
    for bad in [
        "nosuch",
        "18",
        &format!("{tkt_name} {other}"),
        &format!("{tkt_name}\r"),
    ] {
        let (r, _) = kprop_against(Some(vec![format!("{CLIENT} {bad}")]));
        assert!(
            refused(&r),
            "invalid enctype token {bad:?} must refuse: {:?}",
            shown(&r)
        );
    }
}

#[test]
fn kpropd_acl_is_a_prefix_match_ended_by_whitespace_or_eol() {
    // Trailing whitespace (and a bare CR, which fgets keeps) is fine …
    let (tail, _) = kprop_against(Some(vec![format!("{CLIENT}\t "), String::new()]));
    assert!(tail.is_ok(), "trailing whitespace: {:?}", shown(&tail));
    let (cr, _) = kprop_against(Some(vec![format!("{CLIENT}\r")]));
    assert!(cr.is_ok(), "trailing CR: {:?}", shown(&cr));
    // … but the name must start the line and must end there.
    let (longer, _) = kprop_against(Some(vec![format!("{CLIENT}X")]));
    assert!(
        refused(&longer),
        "longer principal must refuse: {:?}",
        shown(&longer)
    );
    let (lead, _) = kprop_against(Some(vec![format!("  {CLIENT}")]));
    assert!(
        refused(&lead),
        "leading whitespace must refuse: {:?}",
        shown(&lead)
    );
    let (norealm, _) = kprop_against(Some(vec![format!("host/{TEST_HOST}")]));
    assert!(
        refused(&norealm),
        "realm-less line must refuse: {:?}",
        shown(&norealm)
    );
    let (comment, _) = kprop_against(Some(vec![format!("# {CLIENT}")]));
    assert!(
        refused(&comment),
        "commented line must refuse: {:?}",
        shown(&comment)
    );
    // No file / empty file: nobody.
    let (none, _) = kprop_against(None);
    assert!(
        refused(&none),
        "no ACL file must refuse: {:?}",
        shown(&none)
    );
    let (empty, _) = kprop_against(Some(Vec::new()));
    assert!(
        refused(&empty),
        "empty ACL must refuse: {:?}",
        shown(&empty)
    );
}

#[test]
fn kpropd_refuses_after_the_ap_rep_so_kprop_fails_on_the_dump_not_sendauth() {
    // kpropd.c:526-546: authorized_principal runs after kerberos_authenticate;
    // MIT kprop completes sendauth (gets the AP-REP) and then dies with
    // `Broken pipe while sending database block starting at 0`.
    let (store, _) = bootstrap_documented().unwrap();
    let (ticket, session, _) = host_ticket(&store);
    let (addr, join) = spawn_kpropd(&store, Some(vec!["host/other@KERBER.TEST".to_owned()]));
    let mut client = TcpStream::connect(addr).unwrap();
    let mut auth = kprop_sendauth(
        &mut client,
        ticket,
        &session,
        &krb5_types::ascii(TEST_REALM),
        &documented_host(),
        7,
    )
    .expect("sendauth (AP-REP) succeeds before the ACL check, like MIT");
    let server = join.join().expect("kpropd thread");
    assert!(refused(&server), "{:?}", shown(&server));
    let sent = kprop_send_dump(&mut client, &mut auth, b"kdb5_util load_dump version 7\n");
    assert!(
        sent.is_err(),
        "the dump cannot be delivered to a refusing kpropd"
    );
}
