//! kadm5 framing tests (private-bound; regrouped in place).

use super::*;

#[test]
fn read_record_bounds_the_total_accumulated_size() {
    // LAST_FRAG must not accumulate unbounded memory. Two 600 KiB non-last fragments sum to 1.2 MiB, over the 1 MiB total cap, so read_record errors on the second fragment instead of waiting for more and hitting EOF, a different error kind.
    use std::io::Write as _;
    use std::net::{TcpListener, TcpStream};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let writer = std::thread::spawn(move || {
        if let Ok(mut c) = TcpStream::connect(addr) {
            let frag = vec![0u8; 600 * 1024];
            let hdr = u32::try_from(frag.len()).unwrap().to_be_bytes(); // no LAST_FRAG
            let _ = c.write_all(&hdr);
            let _ = c.write_all(&frag);
            let _ = c.write_all(&hdr);
            let _ = c.write_all(&frag);
        }
    });
    let (mut server, _) = listener.accept().unwrap();
    let err = super::read_record(&mut server).unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidData,
        "total record over 1 MiB is rejected"
    );
    drop(server);
    let _ = writer.join();
}

#[test]
fn bad_program_is_prog_unavail() {
    let (store, acl, _) = setup();
    let rec = rpc_call(8, 99_999, 1, 0, FLAVOR_NONE);
    let mut gss = None;
    let mut agss = None;
    let out = handle_rpc(
        RpcCtx {
            store: &store,
            authcfg: &crate::kadm5::Kadm5AuthConfig::from_acl(acl.clone()),
            expected_realm: "KERBER.TEST",
            conf: &AcceptorConfig::default(),
            programs: Programs::BOTH,
            iprop_resync: None,
        },
        &[],
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &rec,
        &peer(),
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 8);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
    assert_eq!(r.u32().unwrap(), FLAVOR_NONE);
    assert_eq!(r.opaque().unwrap().len(), 0);
    assert_eq!(r.u32().unwrap(), PROG_UNAVAIL);
}

#[test]
fn kadm_vers_99_is_prog_mismatch_2_2() {
    let (store, acl, _) = setup();
    let rec = rpc_call(9, KADM_PROG, 99, 0, FLAVOR_NONE);
    let mut gss = None;
    let mut agss = None;
    let out = handle_rpc(
        RpcCtx {
            store: &store,
            authcfg: &crate::kadm5::Kadm5AuthConfig::from_acl(acl.clone()),
            expected_realm: "KERBER.TEST",
            conf: &AcceptorConfig::default(),
            programs: Programs::BOTH,
            iprop_resync: None,
        },
        &[],
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &rec,
        &peer(),
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 9);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
    assert_eq!(r.u32().unwrap(), FLAVOR_NONE);
    assert_eq!(r.opaque().unwrap().len(), 0);
    assert_eq!(r.u32().unwrap(), PROG_MISMATCH);
    assert_eq!(r.u32().unwrap(), KADM_VERS);
    assert_eq!(r.u32().unwrap(), KADM_VERS);
}

#[test]
fn reply_typed_rpc_is_no_reply() {
    let (store, acl, _) = setup();
    let mut w = XdrW::default();
    w.u32(10);
    w.u32(MSG_REPLY);
    w.u32(RPC_VERSION);
    w.u32(KADM_PROG);
    w.u32(KADM_VERS);
    w.u32(12);
    w.u32(FLAVOR_NONE);
    w.opaque(&[]);
    w.u32(FLAVOR_NONE);
    w.opaque(&[]);
    let mut gss = None;
    let mut agss = None;
    let out = handle_rpc(
        RpcCtx {
            store: &store,
            authcfg: &crate::kadm5::Kadm5AuthConfig::from_acl(acl.clone()),
            expected_realm: "KERBER.TEST",
            conf: &AcceptorConfig::default(),
            programs: Programs::BOTH,
            iprop_resync: None,
        },
        &[],
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &w.b,
        &peer(),
    )
    .unwrap();
    assert_eq!(out, [] as [u8; 0]);
}
