//! kadmind's one loop ([`krb5_admin::serve_kadmind_until`]) serves kpasswd's TCP streams and the
//! kadm5 RPC connections as MIT's net-server serves kadmind's: a kpasswd length past the buffer
//! is answered with MIT's KRB-ERROR, and an RPC connection stays open between its calls, a call
//! that does not decode getting no reply and a call whose credential or verifier does not check
//! out MIT's RPC auth error, as MIT's.
//! MIT `make_toolong_error` (`kadmin/server/misc.c:139-161`): `KRB_ERR_FIELD_TOOLONG` from `kadmin/changepw` in the realm.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use krb5_admin::{Kadmind, serve_kadmind_until};
use krb5_asn1::decode;
use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_gss::GssContext;
use krb5_kdc::SharedDump;
use krb5_kdc::net_server::Sockets;
use krb5_kdc::principals::{kadmin_admin, kadmin_changepw};
use krb5_kdc::testrealm::{TEST_REALM, bootstrap_documented};
use krb5_protocol::{as_req_sname, pa_enc_timestamp};
use krb5_types::{KrbError, PrincipalName, ascii, err};

/// kadmind's loop over the documented realm on a thread, kpasswd's TCP listener and the RPC
/// listener on 127.0.0.1, until the flag is set.
fn serving() -> (SocketAddr, SocketAddr, Arc<AtomicBool>, JoinHandle<()>) {
    let (kpasswd, rpc, _, stop, served) = serving_with_store();
    (kpasswd, rpc, stop, served)
}

/// [`serving`], with the store the loop serves.
fn serving_with_store() -> (
    SocketAddr,
    SocketAddr,
    SharedDump,
    Arc<AtomicBool>,
    JoinHandle<()>,
) {
    let (store, acl) = bootstrap_documented().unwrap();
    let key = store
        .get_name(&kadmin_changepw())
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let shared = krb5_kdc::shared_dump(store);
    let served_store = Arc::clone(&shared);
    let kpasswd = TcpListener::bind("127.0.0.1:0").unwrap();
    let rpc = TcpListener::bind("127.0.0.1:0").unwrap();
    let addrs = (kpasswd.local_addr().unwrap(), rpc.local_addr().unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let served = std::thread::spawn(move || {
        let mut kadmind = Kadmind::new(served_store, acl, Some(key));
        let (tcp, rpc) = ([kpasswd], [rpc]);
        let sockets = Sockets {
            tcp: &tcp,
            rpc: &rpc,
            ..Sockets::default()
        };
        serve_kadmind_until(&mut kadmind, &sockets, &flag, Duration::from_millis(20)).unwrap();
    });
    (addrs.0, addrs.1, shared, stop, served)
}

fn stop(flag: &AtomicBool, served: JoinHandle<()>) {
    flag.store(true, Ordering::SeqCst);
    served.join().unwrap();
}

fn connect(addr: SocketAddr) -> TcpStream {
    let c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    c
}

/// The bytes of a record in one fragment.
fn record(body: &[u8]) -> Vec<u8> {
    let mut v = (u32::try_from(body.len()).unwrap() | 0x8000_0000)
        .to_be_bytes()
        .to_vec();
    v.extend_from_slice(body);
    v
}

/// A kadm5 call (program 2112, version 2) to procedure 99 with AUTH_NONE.
fn auth_none_call(xid: u32) -> Vec<u8> {
    [xid, 0, 2, 2112, 2, 99, 0, 0, 0, 0]
        .iter()
        .flat_map(|w| w.to_be_bytes())
        .collect()
}

/// One reply record's words.
fn reply_words(c: &mut TcpStream) -> Vec<u32> {
    let mut mark = [0u8; 4];
    c.read_exact(&mut mark).unwrap();
    let n = usize::try_from(u32::from_be_bytes(mark) & 0x7fff_ffff).unwrap();
    let mut body = vec![0u8; n];
    c.read_exact(&mut body).unwrap();
    body.chunks(4)
        .map(|w| u32::from_be_bytes(w.try_into().unwrap()))
        .collect()
}

fn closed(c: &mut TcpStream) -> bool {
    matches!(c.read(&mut [0u8; 1]), Ok(0))
}

/// A kpasswd TCP length past the 1 MiB buffer is logged and answered before any body with
/// `KRB_ERR_FIELD_TOOLONG` from `kadmin/changepw`, not framed as a kpasswd reply, then the
/// stream closes; the length of the buffer less its length word is taken.
#[test]
fn a_kpasswd_length_past_the_buffer_is_mits_field_toolong() {
    let (kpasswd, _, flag, served) = serving();
    let mut c = connect(kpasswd);
    c.write_all(&1_048_573_u32.to_be_bytes()).unwrap();
    let mut len = [0u8; 4];
    c.read_exact(&mut len).unwrap();
    let mut body = vec![0u8; usize::try_from(u32::from_be_bytes(len)).unwrap()];
    c.read_exact(&mut body).unwrap();
    let e: KrbError = decode(&body).unwrap();
    assert_eq!(e.error_code, err::FIELD_TOOLONG);
    assert_eq!(e.sname.unparse(), "kadmin/changepw");
    assert_eq!(std::str::from_utf8(e.realm.as_bytes()).unwrap(), TEST_REALM);
    assert!(e.cname.is_none() && e.e_text.is_none() && e.e_data.is_none());
    assert!(closed(&mut c), "then the stream closes");
    let mut taken = connect(kpasswd);
    taken.write_all(&1_048_572_u32.to_be_bytes()).unwrap();
    taken
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    assert!(taken.read(&mut [0u8; 1]).is_err(), "waiting for the body");
    stop(&flag, served);
}

/// An RPC connection answers call after call on the same socket, waiting between them; a call
/// that does not decode gets no reply, and the connection answers the next one, as MIT's did
/// when settled live (a 1-byte record, then AUTH_TOOWEAK for the next call).
/// MIT `svc_do_xprt` (`lib/rpc/svc.c:473-474`): a call that does not decode is not answered.
#[test]
fn a_kadm5_connection_stays_between_calls() {
    let (_, rpc, flag, served) = serving();
    let mut c = connect(rpc);
    for xid in [7, 8] {
        c.write_all(&record(&auth_none_call(xid))).unwrap();
        // xid, REPLY, MSG_DENIED, AUTH_ERROR, AUTH_TOOWEAK
        assert_eq!(reply_words(&mut c), [xid, 1, 1, 1, 5]);
    }
    c.write_all(&record(&[0])).unwrap();
    c.write_all(&record(&auth_none_call(9))).unwrap();
    assert_eq!(
        reply_words(&mut c),
        [9, 1, 1, 1, 5],
        "still open, and the next call answered"
    );
    stop(&flag, served);
}

/// kadmind built on one thread is served on another, as an embedder may run it, with its
/// reporter: the reporter gets the message of the call that does not decode, and of no other.
#[test]
fn kadmind_is_served_from_another_thread_with_its_reporter() {
    let (store, acl) = bootstrap_documented().unwrap();
    let reported = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&reported);
    let mut kadmind = Kadmind::new(krb5_kdc::shared_dump(store), acl, None).report_unhandled(
        Arc::new(move |message: &str| sink.lock().unwrap().push(message.to_owned())),
    );
    let rpc = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = rpc.local_addr().unwrap();
    let flag = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&flag);
    let served = std::thread::spawn(move || {
        let rpc = [rpc];
        let sockets = Sockets {
            rpc: &rpc,
            ..Sockets::default()
        };
        serve_kadmind_until(
            &mut kadmind,
            &sockets,
            &stop_flag,
            Duration::from_millis(20),
        )
        .unwrap();
    });
    let mut c = connect(addr);
    c.write_all(&record(&auth_none_call(7))).unwrap();
    assert_eq!(reply_words(&mut c), [7, 1, 1, 1, 5]);
    c.write_all(&record(&[0])).unwrap();
    c.write_all(&record(&auth_none_call(8))).unwrap();
    assert_eq!(reply_words(&mut c), [8, 1, 1, 1, 5]);
    stop(&flag, served);
    let reported = reported.lock().unwrap();
    assert_eq!(reported.len(), 1, "{reported:?}");
    assert_ne!(reported[0], "");
}

/// XDR's variable-length opaque: its length, its bytes, zeros to the next word.
fn opaque(b: &[u8]) -> Vec<u8> {
    let mut v = u32::try_from(b.len()).unwrap().to_be_bytes().to_vec();
    v.extend_from_slice(b);
    v.resize(v.len() + (4 - b.len() % 4) % 4, 0);
    v
}

/// A kadm5 call (program 2112, version 2) with an AUTH_GSSAPI credential (version 2, `auth_msg`,
/// the handle) and verifier (AUTH_NONE when there is none).
fn agss_call(
    xid: u32,
    proc: u32,
    auth_msg: bool,
    handle: &[u8],
    verf: Option<&[u8]>,
    args: &[u8],
) -> Vec<u8> {
    let mut cred = 2u32.to_be_bytes().to_vec();
    cred.extend_from_slice(&u32::from(auth_msg).to_be_bytes());
    cred.extend_from_slice(&opaque(handle));
    let mut v: Vec<u8> = [xid, 0, 2, 2112, 2, proc, 300_001]
        .iter()
        .flat_map(|w| w.to_be_bytes())
        .collect();
    v.extend_from_slice(&opaque(&cred));
    v.extend_from_slice(&if verf.is_some() { 300_001_u32 } else { 0 }.to_be_bytes());
    v.extend_from_slice(&opaque(verf.unwrap_or_default()));
    v.extend_from_slice(args);
    v
}

/// One reply record's body.
fn reply_body(c: &mut TcpStream) -> Vec<u8> {
    let mut mark = [0u8; 4];
    c.read_exact(&mut mark).unwrap();
    let mut body = vec![0u8; usize::try_from(u32::from_be_bytes(mark) & 0x7fff_ffff).unwrap()];
    c.read_exact(&mut body).unwrap();
    body
}

/// A reader of a reply's words and opaques.
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

/// The documented admin's GSS context for kadmin/admin from the served store's KDC, its token,
/// and the ticket's session key.
fn admin_initiator(store: &SharedDump) -> (GssContext, Vec<u8>, ProtocolKey) {
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["admin"]);
    let g = store.read().unwrap();
    let key = g.get_name(&admin).unwrap().best_key().unwrap().key.clone();
    let req = as_req_sname(
        admin.clone(),
        TEST_REALM,
        7,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
        kadmin_admin(),
        EncryptionType::preferred()
            .iter()
            .map(|e| e.to_iana())
            .collect(),
    )
    .unwrap();
    let out = krb5_kdc::issue_as(&*g, &req).unwrap();
    let (ctx, token) = GssContext::init_sec_context(
        out.rep.0.ticket.clone(),
        &out.session_key,
        &ascii(TEST_REALM),
        &admin,
        true,
        None,
        None,
    )
    .unwrap();
    (ctx, token, out.session_key)
}

/// A call whose AUTH_GSSAPI verifier or credential does not check out is answered at once with
/// MIT's RPC auth error, and the connection and its record go on: a verifier that does not
/// unseal is AUTH_BADVERF, a handle that names no record AUTH_BADCRED, and then the call under
/// the next sequence number is answered under its reply verifier. MIT's kadmind answered MIT's
/// kadmin so when settled live (a verifier with a flipped byte, a changed handle).
/// MIT `svc_do_xprt` (`lib/rpc/svc.c:487-493`): `svcerr_auth` with the flavor's `auth_stat`.
/// MIT `svc_do_xprt` (`lib/rpc/svc.c:523-531`): the transport stays for the next call.
#[test]
fn an_auth_error_is_answered_and_the_connection_goes_on() {
    krb5_config::isolate_test_krb5();
    let (_, rpc, store, flag, served) = serving_with_store();
    let (mut ctx, token, session) = admin_initiator(&store);
    let mut c = connect(rpc);
    let init_arg = [4u32.to_be_bytes().as_slice(), &opaque(&token)].concat();
    c.write_all(&record(&agss_call(1, 1, true, &[], None, &init_arg)))
        .unwrap();
    let body = reply_body(&mut c);
    let mut r = Words(&body);
    assert_eq!([r.u32(), r.u32(), r.u32(), r.u32()], [1, 1, 0, 0]);
    assert_eq!(r.opaque(), [] as [u8; 0]);
    assert_eq!([r.u32(), r.u32()], [0, 4], "SUCCESS, init_res version 4");
    let handle = r.opaque();
    assert_eq!([r.u32(), r.u32()], [0, 0], "GSS_S_COMPLETE");
    let (tok, isn) = (r.opaque(), r.opaque());
    ctx.process_ap_rep(&tok, &session).unwrap();
    let seq = u32::from_be_bytes(ctx.unwrap(&isn).unwrap().try_into().unwrap());
    // kadm5 INIT (13), then a verifier that does not unseal and a handle that names no record,
    // each answered at once, then GET_PRIVS (12) under the next sequence number.
    agss_data_call(&mut c, &mut ctx, &handle, 2, 13, seq.wrapping_add(1));
    let mut bad = ctx.wrap_integ(&seq.wrapping_add(3).to_be_bytes()).unwrap();
    *bad.last_mut().unwrap() ^= 1;
    c.write_all(&record(&agss_call(3, 12, false, &handle, Some(&bad), &[])))
        .unwrap();
    // xid, REPLY, MSG_DENIED, AUTH_ERROR, AUTH_BADVERF
    assert_eq!(reply_words(&mut c), [3, 1, 1, 1, 3]);
    let verf = ctx.wrap_integ(&seq.wrapping_add(3).to_be_bytes()).unwrap();
    c.write_all(&record(&agss_call(
        4,
        12,
        false,
        &[9, 0, 0, 0],
        Some(&verf),
        &[],
    )))
    .unwrap();
    // AUTH_BADCRED
    assert_eq!(reply_words(&mut c), [4, 1, 1, 1, 1]);
    agss_data_call(&mut c, &mut ctx, &handle, 5, 12, seq.wrapping_add(3));
    stop(&flag, served);
}

/// A kadm5 call to `proc` under the record's next sequence number `seq` (its verifier, and the
/// API version sealed after it), answered SUCCESS under the reply verifier sealing `seq` + 1.
fn agss_data_call(
    c: &mut TcpStream,
    ctx: &mut GssContext,
    handle: &[u8],
    xid: u32,
    proc: u32,
    seq: u32,
) {
    let verf = ctx.wrap_integ(&seq.to_be_bytes()).unwrap();
    let args = [seq.to_be_bytes(), 0x1234_5702_u32.to_be_bytes()].concat();
    let sealed = ctx.wrap_with_rrc(&args, 0).unwrap();
    c.write_all(&record(&agss_call(
        xid,
        proc,
        false,
        handle,
        Some(&verf),
        &opaque(&sealed),
    )))
    .unwrap();
    let body = reply_body(c);
    let mut r = Words(&body);
    assert_eq!([r.u32(), r.u32(), r.u32(), r.u32()], [xid, 1, 0, 300_001]);
    let reply_verf = r.opaque();
    assert_eq!(
        ctx.unwrap(&reply_verf).unwrap(),
        seq.wrapping_add(1).to_be_bytes(),
        "the reply verifier of call {xid}"
    );
    assert_eq!(r.u32(), 0, "call {xid}: SUCCESS");
}
