//! kadmind's one loop ([`krb5_admin::Kadmind::serve`]) serves kpasswd's TCP streams and the kadm5 RPC connections as MIT's net-server serves kadmind's: a kpasswd length past the buffer is answered with MIT's KRB-ERROR, and an RPC connection stays open between its calls, a call that does not decode getting no reply and a call whose credential or verifier does not check out MIT's RPC auth error, as MIT's.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use krb5_admin::{
    Kadmind, KadmindConfig, KlogAdmin, Listeners, Programs, ServeLimits, Services, Shutdown,
};
use krb5_asn1::decode;
use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_gss::GssContext;
use krb5_kdc::SharedDump;
use krb5_kdc::principals::kadmin_admin;
use krb5_kdc::testrealm::{TEST_REALM, bootstrap_documented};
use krb5_protocol::{as_req_sname, pa_enc_timestamp};
use krb5_types::{KrbError, PrincipalName, ascii, err};

fn test_cfg(acl: krb5_kdc::Acl, services: Services) -> KadmindConfig {
    KadmindConfig {
        profile: Arc::new(krb5_config::ProfileSet {
            realm: TEST_REALM.into(),
            krb5: krb5_config::Krb5Conf::default(),
            kdc: None,
            kdc_context: krb5_config::Krb5Conf::default(),
        }),
        services,
        listen: krb5_config::KadmindListen::for_realm(None, TEST_REALM, None),
        limits: ServeLimits::default(),
        acl,
        auth_modules: Vec::new(),
        log: Arc::new(KlogAdmin),
        pwqual: Vec::new(),
        hooks: Vec::new(),
        iprop: None,
    }
}

fn serving() -> (SocketAddr, SocketAddr, Shutdown, JoinHandle<()>) {
    let (kpasswd, rpc, _, stop, served) = serving_with_store();
    (kpasswd, rpc, stop, served)
}

fn serving_with_store() -> (SocketAddr, SocketAddr, SharedDump, Shutdown, JoinHandle<()>) {
    let (store, acl) = bootstrap_documented().unwrap();
    let shared = krb5_kdc::shared_dump(store);
    let served_store = Arc::clone(&shared);
    let kpasswd = TcpListener::bind("127.0.0.1:0").unwrap();
    let rpc = TcpListener::bind("127.0.0.1:0").unwrap();
    let addrs = (kpasswd.local_addr().unwrap(), rpc.local_addr().unwrap());
    let stop = Shutdown::new();
    let flag = stop.clone();
    let served = std::thread::spawn(move || {
        let mut kadmind = Kadmind::new(served_store, test_cfg(acl, Services::DAEMON)).unwrap();
        let listeners =
            Listeners::from_sockets(Vec::new(), vec![kpasswd], vec![rpc], Programs::BOTH);
        kadmind.serve(&listeners, &flag).unwrap();
    });
    (addrs.0, addrs.1, shared, stop, served)
}

fn stop(flag: &Shutdown, served: JoinHandle<()>) {
    flag.trigger();
    served.join().unwrap();
}

fn connect(addr: SocketAddr) -> TcpStream {
    let c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    c
}

fn record(body: &[u8]) -> Vec<u8> {
    let mut v = (u32::try_from(body.len()).unwrap() | 0x8000_0000)
        .to_be_bytes()
        .to_vec();
    v.extend_from_slice(body);
    v
}

fn auth_none_call(xid: u32) -> Vec<u8> {
    [xid, 0, 2, 2112, 2, 99, 0, 0, 0, 0]
        .iter()
        .flat_map(|w| w.to_be_bytes())
        .collect()
}

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

#[test]
fn a_kadm5_connection_stays_between_calls() {
    let (_, rpc, flag, served) = serving();
    let mut c = connect(rpc);
    for xid in [7, 8] {
        c.write_all(&record(&auth_none_call(xid))).unwrap();
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

fn opaque(b: &[u8]) -> Vec<u8> {
    let mut v = u32::try_from(b.len()).unwrap().to_be_bytes().to_vec();
    v.extend_from_slice(b);
    v.resize(v.len() + (4 - b.len() % 4) % 4, 0);
    v
}

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

fn reply_body(c: &mut TcpStream) -> Vec<u8> {
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
        krb5_gss::GSS_C_MUTUAL | krb5_gss::GSS_C_REPLAY | krb5_gss::GSS_C_SEQUENCE,
        None,
        None,
        None,
        0,
    )
    .unwrap();
    (ctx, token, out.session_key)
}

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
    agss_data_call(&mut c, &mut ctx, &handle, 2, 13, seq.wrapping_add(1));
    let mut bad = ctx.wrap_integ(&seq.wrapping_add(3).to_be_bytes()).unwrap();
    *bad.last_mut().unwrap() ^= 1;
    c.write_all(&record(&agss_call(3, 12, false, &handle, Some(&bad), &[])))
        .unwrap();
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
    assert_eq!(reply_words(&mut c), [4, 1, 1, 1, 1]);
    agss_data_call(&mut c, &mut ctx, &handle, 5, 12, seq.wrapping_add(3));
    stop(&flag, served);
}

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
