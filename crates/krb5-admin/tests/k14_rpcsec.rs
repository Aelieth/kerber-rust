//! RPCSEC DATA without a context is MIT `CREDPROBLEM` (connection kept).

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
const MSG_DENIED: u32 = 1;
const RPC_VERSION: u32 = 2;
const KADM_PROG: u32 = 2112;
const KADM_VERS: u32 = 2;
const FLAVOR_GSS: u32 = 6;
const REJECT_AUTH_ERROR: u32 = 1;
const RPCSEC_GSS_VERS: u32 = 1;
const RPG_DATA: u32 = 0;
const GSS_PRIVACY: u32 = 3;
const RPCSEC_GSS_CREDPROBLEM: u32 = 13;

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
fn rpcsec_data_without_context_is_credproblem() {
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
    push_u32(&mut cred, RPCSEC_GSS_VERS);
    push_u32(&mut cred, RPG_DATA);
    push_u32(&mut cred, 1);
    push_u32(&mut cred, GSS_PRIVACY);
    push_u32(&mut cred, 0);
    let mut body = Vec::new();
    push_u32(&mut body, 14);
    push_u32(&mut body, MSG_CALL);
    push_u32(&mut body, RPC_VERSION);
    push_u32(&mut body, KADM_PROG);
    push_u32(&mut body, KADM_VERS);
    push_u32(&mut body, 12);
    push_u32(&mut body, FLAVOR_GSS);
    push_u32(&mut body, u32::try_from(cred.len()).unwrap());
    body.extend_from_slice(&cred);
    push_u32(&mut body, 0);
    push_u32(&mut body, 0);
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let n = u32::try_from(body.len()).unwrap() | LAST_FRAG;
    c.write_all(&n.to_be_bytes()).unwrap();
    c.write_all(&body).unwrap();
    let mut hdr = [0u8; 4];
    c.read_exact(&mut hdr)
        .expect("CREDPROBLEM reply kept the connection");
    let len = (u32::from_be_bytes(hdr) & !LAST_FRAG) as usize;
    let mut rec = vec![0u8; len];
    c.read_exact(&mut rec).unwrap();
    let w = words(&rec);
    assert_eq!(w[0], 14);
    assert_eq!(w[1], MSG_REPLY);
    assert_eq!(w[2], MSG_DENIED);
    assert_eq!(w[3], REJECT_AUTH_ERROR);
    assert_eq!(w[4], RPCSEC_GSS_CREDPROBLEM);
}
