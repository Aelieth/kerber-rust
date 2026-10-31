//! kadm5 framing tests (private-bound; regrouped in place).

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
