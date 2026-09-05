//! AUTH_GSSAPI INIT on IPROP_PROG is auth-layer SUCCESS (`no_dispatch`).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use krb5_admin::serve_kadm5_conn;
use krb5_kdc::{bootstrap_documented, shared_dump};
use krb5_protocol::ReplayCache;

const LAST_FRAG: u32 = 0x8000_0000;
const MSG_CALL: u32 = 0;
const MSG_REPLY: u32 = 1;
const MSG_ACCEPTED: u32 = 0;
const RPC_VERSION: u32 = 2;
const IPROP_PROG: u32 = 100_423;
const IPROP_VERS: u32 = 1;
const AUTH_GSSAPI_INIT: u32 = 1;
const FLAVOR_AUTH_GSSAPI: u32 = 300_001;
const AUTH_GSSAPI_CREDS_VERS: u32 = 2;
const SUCCESS: u32 = 0;

fn push_u32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_be_bytes());
}

fn words(buf: &[u8]) -> Vec<u32> {
    buf.as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_be_bytes(*c))
        .collect()
}

#[test]
fn auth_gssapi_on_iprop_init_is_success() {
    let (store, acl) = bootstrap_documented().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let store = shared_dump(store);
    thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        let _ = serve_kadm5_conn(
            store,
            acl,
            Vec::new(),
            "KERBER.TEST".into(),
            ReplayCache::new(),
            s,
        );
    });
    let mut cred = Vec::new();
    push_u32(&mut cred, AUTH_GSSAPI_CREDS_VERS);
    push_u32(&mut cred, 1);
    push_u32(&mut cred, 0);
    let mut args = Vec::new();
    push_u32(&mut args, 2);
    push_u32(&mut args, 0);
    let mut body = Vec::new();
    push_u32(&mut body, 12);
    push_u32(&mut body, MSG_CALL);
    push_u32(&mut body, RPC_VERSION);
    push_u32(&mut body, IPROP_PROG);
    push_u32(&mut body, IPROP_VERS);
    push_u32(&mut body, AUTH_GSSAPI_INIT);
    push_u32(&mut body, FLAVOR_AUTH_GSSAPI);
    push_u32(&mut body, u32::try_from(cred.len()).unwrap());
    body.extend_from_slice(&cred);
    push_u32(&mut body, 0);
    push_u32(&mut body, 0);
    body.extend_from_slice(&args);
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let n = u32::try_from(body.len()).unwrap() | LAST_FRAG;
    c.write_all(&n.to_be_bytes()).unwrap();
    c.write_all(&body).unwrap();
    let mut hdr = [0u8; 4];
    c.read_exact(&mut hdr)
        .expect("AUTH_GSSAPI INIT reply kept the connection");
    let len = (u32::from_be_bytes(hdr) & !LAST_FRAG) as usize;
    let mut rec = vec![0u8; len];
    c.read_exact(&mut rec).unwrap();
    let w = words(&rec);
    assert_eq!(w[0], 12);
    assert_eq!(w[1], MSG_REPLY);
    assert_eq!(w[2], MSG_ACCEPTED);
    assert_eq!(w[w.len() - 1], SUCCESS);
}
