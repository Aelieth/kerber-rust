//! kadm5 framing tests (private-bound; regrouped in place).

use super::*;

#[test]
fn read_record_bounds_the_total_accumulated_size() {
    // A pre-auth client that chains fragments without ever setting
    // LAST_FRAG must not accumulate unbounded memory. Two 600 KiB non-last
    // fragments sum to 1.2 MiB, over the 1 MiB total cap, so read_record
    // errors on the second fragment instead of waiting for more and hitting
    // EOF, a different error kind.
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

/// A record of empty fragments, 300,000 marks with no last one, ends once its marks pass 1 MiB:
/// the blocking reader holds no memory for them and stops reading at the cap.
#[test]
fn empty_fragments_end_the_record_at_the_cap() {
    use std::io::Write as _;
    use std::net::{TcpListener, TcpStream};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let writer = std::thread::spawn(move || {
        if let Ok(mut c) = TcpStream::connect(addr) {
            let _ = c.write_all(&vec![0u8; 4 * 300_000]);
        }
    });
    let (mut server, _) = listener.accept().unwrap();
    let err = super::read_record(&mut server).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
    drop(server);
    let _ = writer.join();
}

/// A kadm5 RPC reply is one write: the record mark (length | LAST_FRAG) and the body together,
/// as MIT's `xdrrec` flushes a record.
#[test]
fn rpc_record_is_one_write() {
    #[derive(Default)]
    struct Writes(Vec<Vec<u8>>);
    impl std::io::Write for Writes {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.push(buf.to_vec());
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut w = Writes::default();
    super::write_record(&mut w, b"reply").unwrap();
    assert_eq!(w.0, [b"\x80\0\0\x05reply".to_vec()]);
}

/// The replies that carry keys, `chrand`'s and `get_principal_keys`'s, are built in one buffer of
/// their size, and so is the RPCSEC_GSS reply that carries one in the clear: no copy of a key is
/// left in a buffer they outgrew. Their callers wipe them.
#[test]
fn the_key_replies_are_built_in_one_buffer() {
    let (store, _, _) = setup();
    let g = store.read().unwrap();
    let p = g.get_name(&krb5_kdc::principals::kadmin_admin()).unwrap();
    assert!(!p.keys.is_empty());
    let chrand = encode_chrand(&p.keys);
    assert_eq!(chrand.capacity(), chrand.len());
    let mut r = XdrR::new(&chrand);
    assert_eq!(
        (r.u32().unwrap(), r.u32().unwrap(), r.u32().unwrap()),
        (API_V2, 0, u32::try_from(p.keys.len()).unwrap())
    );
    for kvno in [0, p.keys[0].kvno] {
        let keys = encode_extract_keys(API_V2, p, kvno);
        assert_eq!(keys.capacity(), keys.len());
    }
    let reply = rpc_reply_gss_verf(7, b"a mic", &chrand);
    assert_eq!(reply.capacity(), reply.len());
    assert!(reply.ends_with(&chrand));
}

#[test]
fn xdr_nullstring_round_trip_shape() {
    let mut w = XdrW::default();
    w.opaque(b"alice@KERBER.TEST\0");
    let mut r = XdrR::new(&w.b);
    let s = r.nullstring().unwrap().unwrap();
    // opaque != nullstring (nullstring writes size then bytes including NUL)
    assert!(!s.is_empty() || w.b.len() >= 4);
    let mut w2 = XdrW::default();
    let s = "alice@KERBER.TEST";
    w2.u32(u32::try_from(s.len() + 1).unwrap());
    w2.b.extend_from_slice(s.as_bytes());
    w2.b.push(0);
    let pad = (4 - ((s.len() + 1) % 4)) % 4;
    w2.b.extend(std::iter::repeat_n(0u8, pad));
    let mut r2 = XdrR::new(&w2.b);
    assert_eq!(
        r2.nullstring().unwrap().as_deref(),
        Some("alice@KERBER.TEST")
    );
    let p = {
        let mut r3 = XdrR::new(&w2.b);
        r3.principal().unwrap()
    };
    assert_eq!(p.components_joined(), "alice");
}

#[test]
fn xdr_principal_parse_name_escapes() {
    let mut w = XdrW::default();
    w.nullstring(Some(r"foo\/admin@KERBER.TEST"));
    let mut r = XdrR::new(&w.b);
    let p = r.principal().unwrap();
    assert_eq!(p.name_string.len(), 1);
    assert_eq!(p.unparse(), r"foo\/admin");
    assert_eq!(p.components_joined(), "foo/admin");
}

#[test]
fn generic_ret_is_eight_bytes() {
    let b = generic_ret(API_V2, 0);
    assert_eq!(b.len(), 8);
    assert_eq!(&b[..4], &API_V2.to_be_bytes());
}

#[test]
fn unknown_proc_is_proc_unavail() {
    let (store, acl, actor) = setup();
    let err = dispatch_kadm5(&store, &acl, &actor, 99, &[]).unwrap_err();
    assert_eq!(err, Error::ProcUnavail);
}

#[test]
fn truncated_getprinc_is_garbage_args() {
    let (store, acl, actor) = setup();
    let err = dispatch_kadm5(&store, &acl, &actor, GET_PRINCIPAL, &[]).unwrap_err();
    assert_eq!(err, Error::GarbageArgs);
}

#[test]
fn auth_none_is_auth_too_weak() {
    let (store, acl, _) = setup();
    let rec = rpc_call(7, KADM_PROG, KADM_VERS, 99, FLAVOR_NONE);
    let mut gss = None;
    let mut agss = None;
    let out = handle_rpc(
        RpcCtx {
            store: &store,
            acl: &acl,
            service_keys: &[],
            expected_realm: "KERBER.TEST",
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
    assert_eq!(r.u32().unwrap(), 7);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_DENIED);
    assert_eq!(r.u32().unwrap(), REJECT_AUTH_ERROR);
    assert_eq!(r.u32().unwrap(), AUTH_TOOWEAK);
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
            acl: &acl,
            service_keys: &[],
            expected_realm: "KERBER.TEST",
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
            acl: &acl,
            service_keys: &[],
            expected_realm: "KERBER.TEST",
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
            acl: &acl,
            service_keys: &[],
            expected_realm: "KERBER.TEST",
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
