//! kadmind's :749 acceptor reads its key from the database as MIT's GSS acceptor does: with
//! `GSS_C_NO_NAME` (RPCSEC_GSS) the first permitted key at the ticket's kvno of the server the ticket
//! names, and with AUTH_GSSAPI's two names (`kadmin/admin`, then `kadmin/changepw`) the same for
//! each, the next tried only for a ticket that is not for the first. Every case goes through the
//! daemon's loop over a socket, so it is the public path an operator's `kadmin` takes.
//! MIT `setup_kdb_keytab` (`kadmin/server/ovsec_kadmd.c:178-190`): the GSS acceptor reads the `KDB:` keytab.
//! MIT `krb5_ktkdb_get_entry` (`lib/kdb/keytab.c:117-185`): the first permitted key at the kvno, of an enctype similar to the ticket's.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;
use std::time::Duration;

use krb5_admin::{Kadmind, serve_kadmind_until};
use krb5_crypto::{KeyUsage, ProtocolKey, encrypt};
use krb5_gss::GssContext;
use krb5_kdc::net_server::Sockets;
use krb5_kdc::principals::{kadmin_admin, kadmin_changepw, kadmin_history};
use krb5_kdc::testrealm::{
    TEST_ADMIN, TEST_ADMIN_PASSWORD, TEST_REALM, TEST_USER, TEST_USER_PASSWORD,
    documented_admin_id, documented_host,
};
use krb5_kdc::{KeyEntry, PrincipalStore, bootstrap_realm_with_kdc_conf, decrypt_ticket_part};
use krb5_protocol::{as_req_sname, pa_enc_timestamp};
use krb5_types::{OctetString, PrincipalName, Ticket, ascii, ku};

/// RPC words: AUTH_REJECTEDCRED, AUTH_TOOWEAK, GSS_S_FAILURE.
const AUTH_REJECTEDCRED: u32 = 2;
const AUTH_TOOWEAK: u32 = 5;
const GSS_S_FAILURE: u32 = 13 << 16;

/// The documented realm with four enctypes, so that each kadm5 service principal has four keys
/// and the first (aes256-cts-hmac-sha384-192) is not the second.
fn realm() -> (Arc<RwLock<PrincipalStore>>, krb5_kdc::Acl) {
    krb5_config::isolate_test_krb5();
    let kdc = krb5_config::KdcConf::parse(
        r"
[realms]
    KERBER.TEST = {
        supported_enctypes = aes256-cts-hmac-sha384-192:normal aes128-cts-hmac-sha256-128:normal aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
    }
",
    )
    .unwrap();
    let (mut store, acl) = bootstrap_realm_with_kdc_conf(
        TEST_REALM,
        TEST_USER,
        TEST_USER_PASSWORD,
        TEST_ADMIN,
        TEST_ADMIN_PASSWORD,
        Some(&kdc),
    )
    .unwrap();
    // `kadmin/history` exists once a policy has been used; here from the start.
    store
        .create_host(&acl, &documented_admin_id(), &kadmin_history())
        .unwrap();
    (krb5_kdc::shared_dump(store), acl)
}

struct Served {
    rpc: SocketAddr,
    store: Arc<RwLock<PrincipalStore>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Served {
    fn new() -> Self {
        let (store, acl) = realm();
        let served_store = Arc::clone(&store);
        let rpc = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = rpc.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            let mut kadmind = Kadmind::new(served_store, acl, None);
            let rpc = [rpc];
            let sockets = Sockets {
                rpc: &rpc,
                ..Sockets::default()
            };
            serve_kadmind_until(&mut kadmind, &sockets, &flag, Duration::from_millis(20)).unwrap();
        });
        Self {
            rpc: addr,
            store,
            stop,
            thread: Some(thread),
        }
    }

    fn connect(&self) -> TcpStream {
        let c = TcpStream::connect(self.rpc).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        c
    }

    /// The service ticket the documented admin gets from this realm's KDC for `service`, and its
    /// session key.
    fn ticket_for(&self, service: &PrincipalName) -> (Ticket, ProtocolKey) {
        let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
        let g = self.store.read().unwrap();
        let key = g.get_name(&admin).unwrap().best_key().unwrap().key.clone();
        let req = as_req_sname(
            admin,
            TEST_REALM,
            7,
            Some(vec![pa_enc_timestamp(&key).unwrap()]),
            service.clone(),
            krb5_crypto::EncryptionType::preferred()
                .iter()
                .map(|e| e.to_iana())
                .collect(),
        )
        .unwrap();
        let out = krb5_kdc::issue_as(&*g, &req).unwrap();
        (out.rep.0.ticket.clone(), out.session_key)
    }

    /// The keys of `name` as the database holds them, in order.
    fn keys_of(&self, name: &PrincipalName) -> Vec<KeyEntry> {
        self.store
            .read()
            .unwrap()
            .get_name(name)
            .unwrap()
            .keys
            .clone()
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// `ticket` with its enc-part sealed under `to` instead of `from`, labelled with `to`'s enctype and
/// kvno.
fn resealed(ticket: &Ticket, from: &KeyEntry, to: &KeyEntry) -> Ticket {
    let part = decrypt_ticket_part(&from.key, ticket).unwrap();
    let mut t = ticket.clone();
    t.enc_part.etype = to.etype.to_iana();
    t.enc_part.kvno = Some(to.kvno);
    t.enc_part.cipher = OctetString::from(
        encrypt(
            &to.key,
            KeyUsage::new(ku::TICKET).unwrap(),
            &krb5_asn1::encode(&part).unwrap(),
        )
        .unwrap(),
    );
    t
}

/// The first token of a context on `ticket` for the documented admin.
fn token(ticket: Ticket, session: &ProtocolKey) -> (GssContext, Vec<u8>) {
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    GssContext::init_sec_context(
        ticket,
        session,
        &ascii(TEST_REALM),
        &admin,
        true,
        None,
        None,
    )
    .unwrap()
}

fn record(body: &[u8]) -> Vec<u8> {
    let mut v = (u32::try_from(body.len()).unwrap() | 0x8000_0000)
        .to_be_bytes()
        .to_vec();
    v.extend_from_slice(body);
    v
}

fn opaque(b: &[u8]) -> Vec<u8> {
    let mut v = u32::try_from(b.len()).unwrap().to_be_bytes().to_vec();
    v.extend_from_slice(b);
    v.resize(v.len() + (4 - b.len() % 4) % 4, 0);
    v
}

fn words(ws: &[u32]) -> Vec<u8> {
    ws.iter().flat_map(|w| w.to_be_bytes()).collect()
}

/// One reply record's body.
fn reply(c: &mut TcpStream) -> Vec<u8> {
    let mut mark = [0u8; 4];
    c.read_exact(&mut mark).unwrap();
    let mut body = vec![0u8; usize::try_from(u32::from_be_bytes(mark) & 0x7fff_ffff).unwrap()];
    c.read_exact(&mut body).unwrap();
    body
}

struct Words<'a>(&'a [u8]);

impl Words<'_> {
    fn u32(&mut self) -> u32 {
        let (w, rest) = self.0.split_at(4);
        self.0 = rest;
        u32::from_be_bytes(w.try_into().unwrap())
    }

    fn opaque(&mut self) -> Vec<u8> {
        let n = usize::try_from(self.u32()).unwrap();
        let v = self.0[..n].to_vec();
        self.0 = &self.0[n + (4 - n % 4) % 4..];
        v
    }
}

/// What an INIT call got.
#[derive(Debug, PartialEq, Eq)]
enum Init {
    /// The RPC layer refused it with this `auth_stat`.
    Denied(u32),
    /// The flavor answered: the GSS major status, and the context handle with the reply's token.
    Answered(u32, Vec<u8>, Vec<u8>),
}

/// An RPCSEC_GSS INIT carrying `token`, as MIT's client sends it: program 2112 version 2, procedure 0.
fn rpcsec_init(c: &mut TcpStream, xid: u32, token: &[u8]) -> Init {
    // RPCSEC_GSS_VERS_1, RPCSEC_GSS_INIT, seq 0, rpc_gss_svc_none, no handle.
    let cred = [words(&[1, 1, 0, 1]), opaque(&[])].concat();
    let call = [
        words(&[xid, 0, 2, 2112, 2, 0, 6]),
        opaque(&cred),
        words(&[0]),
        opaque(&[]),
        opaque(token),
    ]
    .concat();
    c.write_all(&record(&call)).unwrap();
    let body = reply(c);
    let mut r = Words(&body);
    assert_eq!(r.u32(), xid);
    assert_eq!(r.u32(), 1, "a reply");
    if r.u32() == 1 {
        assert_eq!(r.u32(), 1, "an auth error");
        return Init::Denied(r.u32());
    }
    assert_eq!(r.u32(), 6, "under an RPCSEC_GSS verifier");
    let _verifier = r.opaque();
    assert_eq!(r.u32(), 0, "SUCCESS");
    let handle = r.opaque();
    let (major, _minor, _window) = (r.u32(), r.u32(), r.u32());
    Init::Answered(major, handle, r.opaque())
}

/// An AUTH_GSSAPI INIT carrying `token` (version 4, as MIT's client sends it).
fn agss_init(c: &mut TcpStream, xid: u32, token: &[u8]) -> Init {
    // Credential version 2, an auth message, no client handle.
    let cred = [words(&[2, 1]), opaque(&[])].concat();
    let call = [
        words(&[xid, 0, 2, 2112, 2, 1, 300_001]),
        opaque(&cred),
        words(&[0]),
        opaque(&[]),
        words(&[4]),
        opaque(token),
    ]
    .concat();
    c.write_all(&record(&call)).unwrap();
    let body = reply(c);
    let mut r = Words(&body);
    assert_eq!([r.u32(), r.u32(), r.u32(), r.u32()], [xid, 1, 0, 0]);
    let _verifier = r.opaque();
    assert_eq!([r.u32(), r.u32()], [0, 4], "SUCCESS, init_res version 4");
    let handle = r.opaque();
    let (major, _minor) = (r.u32(), r.u32());
    Init::Answered(major, handle, r.opaque())
}

/// The reply to a kadm5 data call on an RPCSEC_GSS context: the `auth_stat` of a refusal.
fn weak_call(c: &mut TcpStream, ctx: &mut GssContext, handle: &[u8], xid: u32) -> u32 {
    // RPCSEC_GSS_DATA, sequence number `xid`, rpc_gss_svc_none, the context's handle.
    let cred = [words(&[1, 0, xid, 1]), opaque(handle)].concat();
    let header = [words(&[xid, 0, 2, 2112, 2, 12, 6]), opaque(&cred)].concat();
    let mic = ctx.get_mic(&header).unwrap();
    let call = [header, words(&[6]), opaque(&mic)].concat();
    c.write_all(&record(&call)).unwrap();
    let body = reply(c);
    let mut r = Words(&body);
    assert_eq!([r.u32(), r.u32(), r.u32(), r.u32()], [xid, 1, 1, 1]);
    r.u32()
}

fn init_rpcsec(served: &Served, ticket: Ticket, session: &ProtocolKey) -> Init {
    let (_ctx, tok) = token(ticket, session);
    rpcsec_init(&mut served.connect(), 1, &tok)
}

fn init_agss(served: &Served, ticket: Ticket, session: &ProtocolKey) -> Init {
    let (_ctx, tok) = token(ticket, session);
    agss_init(&mut served.connect(), 1, &tok)
}

fn completes(i: &Init) -> bool {
    matches!(i, Init::Answered(0, ..))
}

/// A ticket for `kadmin/admin` sealed in the first key of the principal is accepted, one sealed in
/// any other key of it is not: the KDB keytab gives the first permitted key at the ticket's kvno and
/// a ticket of another enctype finds none (`KRB5_KDB_NO_PERMITTED_KEY`). RPCSEC_GSS accepts with
/// no name, so the key is the ticket's server's.
/// MIT `krb5_ktkdb_get_entry` (`lib/kdb/keytab.c:152-180`): the first permitted key, then the enctype must be similar.
#[test]
fn rpcsec_gss_refuses_a_ticket_sealed_in_a_later_key() {
    let served = Served::new();
    let keys = served.keys_of(&kadmin_admin());
    let (ticket, session) = served.ticket_for(&kadmin_admin());
    assert!(completes(&init_rpcsec(&served, ticket.clone(), &session)));
    assert!(keys.len() >= 3);
    for later in &keys[1..] {
        let t = resealed(&ticket, &keys[0], later);
        assert_eq!(
            init_rpcsec(&served, t, &session),
            Init::Denied(AUTH_REJECTEDCRED),
            "a ticket in the {} key",
            later.etype.to_iana()
        );
    }
}

/// The same for AUTH_GSSAPI, which tries `kadmin/admin` and then `kadmin/changepw`, each the
/// first permitted key.
#[test]
fn auth_gssapi_refuses_a_ticket_sealed_in_a_later_key() {
    let served = Served::new();
    let keys = served.keys_of(&kadmin_admin());
    let (ticket, session) = served.ticket_for(&kadmin_admin());
    assert!(completes(&init_agss(&served, ticket.clone(), &session)));
    for later in &keys[1..] {
        let t = resealed(&ticket, &keys[0], later);
        assert!(
            matches!(
                init_agss(&served, t, &session),
                Init::Answered(GSS_S_FAILURE, ..)
            ),
            "a ticket in the {} key",
            later.etype.to_iana()
        );
    }
}

/// A ticket whose kvno the principal has no key at is refused (`KRB5KRB_AP_ERR_BADKEYVER`), where a
/// walk of every key would take it whatever it is labelled.
/// MIT `keytab_fetch_error` (`rd_req_dec.c:118-148`): `KRB5_KT_KVNONOTFOUND` is BADKEYVER.
#[test]
fn a_ticket_labelled_with_a_kvno_the_principal_lacks_is_refused() {
    let served = Served::new();
    let (mut ticket, session) = served.ticket_for(&kadmin_admin());
    ticket.enc_part.kvno = Some(99);
    assert_eq!(
        init_rpcsec(&served, ticket.clone(), &session),
        Init::Denied(AUTH_REJECTEDCRED)
    );
    assert!(matches!(
        init_agss(&served, ticket, &session),
        Init::Answered(GSS_S_FAILURE, ..)
    ));
}

/// With no name the database serves every principal in it: a ticket for a service kadmind does not
/// run, `host/...`, completes the context, and its first call is AUTH_TOOWEAK. So does a ticket for
/// `kadmin/history`, which the service check refuses by name.
/// MIT `svcauth_gss_acquire_cred` (`lib/rpc/svc_auth_gss.c:149-157`): no service name, so any principal of the KDB.
/// MIT `check_rpcsec_auth` (`kadmin/server/kadm_rpc_svc.c:333-337`): the name is then checked and `svcerr_weakauth` answers.
#[test]
fn rpcsec_gss_for_any_principal_of_the_database_completes_and_is_then_too_weak() {
    let served = Served::new();
    for service in [documented_host(), kadmin_history()] {
        let (ticket, session) = served.ticket_for(&service);
        let (mut ctx, tok) = token(ticket, &session);
        let mut c = served.connect();
        let Init::Answered(0, handle, out_tok) = rpcsec_init(&mut c, 1, &tok) else {
            panic!("the context for {service:?} does not complete");
        };
        if !out_tok.is_empty() {
            ctx.process_ap_rep(&out_tok, &session).unwrap();
        }
        ctx.allow_rpcsec_init_window();
        assert_eq!(weak_call(&mut c, &mut ctx, &handle, 2), AUTH_TOOWEAK);
    }
}

/// A ticket whose cleartext names a server the database lacks is refused by RPCSEC_GSS, which looks
/// the cleartext server up (`KRB5_KT_NOTFOUND` is NOT_US for the ticket's server), though its
/// enc-part is sealed in `kadmin/admin`'s key.
/// MIT `decrypt_try_server` (`rd_req_dec.c:379-386`): `try_one_princ(tkt_server, FALSE)`.
#[test]
fn rpcsec_gss_looks_the_cleartext_server_up() {
    let served = Served::new();
    let (mut ticket, session) = served.ticket_for(&kadmin_admin());
    ticket.sname = PrincipalName::new(PrincipalName::NT_SRV_INST, ["nosuch", "service"]);
    assert_eq!(
        init_rpcsec(&served, ticket, &session),
        Init::Denied(AUTH_REJECTEDCRED)
    );
}

/// AUTH_GSSAPI names its servers, so a ticket that decrypts in the key of `kadmin/admin` is
/// `kadmin/admin`'s whatever server its cleartext names, as with kpasswd; one for `kadmin/changepw`
/// is taken by the second name after the first finds it is not for it.
/// MIT `try_one_entry` (`rd_req_dec.c:315-317`): the keytab principal becomes the ticket's server.
/// MIT `gssrpc__svcauth_gssapi` (`svc_auth_gssapi.c:391-436`): the next name is tried on NOT_US.
#[test]
fn auth_gssapi_takes_the_key_of_the_name_whatever_the_cleartext_server() {
    let served = Served::new();
    let (mut ticket, session) = served.ticket_for(&kadmin_admin());
    ticket.sname = documented_host();
    assert!(
        completes(&init_agss(&served, ticket, &session)),
        "admin's key, a host cleartext"
    );
    let (mut ticket, session) = served.ticket_for(&kadmin_changepw());
    assert!(
        completes(&init_agss(&served, ticket.clone(), &session)),
        "changepw's key"
    );
    ticket.sname = documented_host();
    assert!(
        completes(&init_agss(&served, ticket, &session)),
        "changepw's key, a host cleartext"
    );
    let (ticket, session) = served.ticket_for(&kadmin_history());
    assert!(matches!(
        init_agss(&served, ticket, &session),
        Init::Answered(GSS_S_FAILURE, ..)
    ));
}

/// kadmind starts only when the KDB keytab has a key for both names AUTH_GSSAPI accepts, as MIT's
/// `svcauth_gssapi_set_names` needs a credential for each: a database without `kadmin/changepw`
/// (or whose `kadmin/admin` may not be a service) is refused, one with both is served.
/// MIT `check_keytab` (`lib/gssapi/krb5/acquire_cred.c:126-138`): a name that is not host-based needs `krb5_kt_get_entry(kt, princ, 0, 0)` to find it.
/// MIT `main` (`kadmin/server/ovsec_kadmd.c:476-477`): "Cannot set GSSAPI authentication names".
#[test]
fn kadmind_starts_only_when_both_authentication_names_are_served() {
    use krb5_kdc::{AdminFields, KDB_DISALLOW_SVR};

    krb5_config::isolate_test_krb5();
    let (store, acl) = realm();
    let actor = documented_admin_id();
    {
        let mut g = store.write().unwrap();
        assert!(krb5_admin::acceptor_names_served(&g));
        g.apply_admin_fields_in(
            &kadmin_changepw(),
            TEST_REALM,
            AdminFields {
                attributes: Some(KDB_DISALLOW_SVR),
                ..AdminFields::default()
            },
            &actor,
        )
        .unwrap();
        assert!(
            !krb5_admin::acceptor_names_served(&g),
            "kadmin/changepw may not be a service"
        );
    }
    drop(acl);
}
