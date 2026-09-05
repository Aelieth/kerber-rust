//! AUTH_NONE unknown program is MIT `svcerr_prog_unavail` (connection kept).

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
const PROG_UNAVAIL: u32 = 1;

fn be(words: &[u32]) -> Vec<u8> {
    let mut b = Vec::with_capacity(words.len() * 4);
    for w in words {
        b.extend_from_slice(&w.to_be_bytes());
    }
    b
}

fn words(buf: &[u8]) -> Vec<u32> {
    buf.as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_be_bytes(*c))
        .collect()
}

#[test]
fn unknown_program_auth_none_is_prog_unavail() {
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
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let body = be(&[7, MSG_CALL, RPC_VERSION, 99_999, 1, 0, 0, 0, 0, 0]);
    let n = u32::try_from(body.len()).unwrap() | LAST_FRAG;
    c.write_all(&n.to_be_bytes()).unwrap();
    c.write_all(&body).unwrap();
    let mut hdr = [0u8; 4];
    c.read_exact(&mut hdr)
        .expect("PROG_UNAVAIL reply kept the connection");
    let len = (u32::from_be_bytes(hdr) & !LAST_FRAG) as usize;
    let mut rec = vec![0u8; len];
    c.read_exact(&mut rec).unwrap();
    let w = words(&rec);
    assert_eq!(w[0], 7);
    assert_eq!(w[1], MSG_REPLY);
    assert_eq!(w[2], MSG_ACCEPTED);
    assert_eq!(w[3], 0);
    assert_eq!(w[4], 0);
    assert_eq!(w[5], PROG_UNAVAIL);
}
