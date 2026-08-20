//! Live AS/TGS against the MIT 1.22.2 harness when port 88 is reachable.

use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use krb5_client::kinit;
use krb5_protocol::KdcAddr;

fn kdc_up() -> bool {
    let Ok(mut addrs) = "127.0.0.1:88".to_socket_addrs() else {
        return false;
    };
    let Some(sa) = addrs.next() else {
        return false;
    };
    TcpStream::connect_timeout(&sa, Duration::from_millis(300)).is_ok()
}

#[test]
fn kinit_obtains_tgt_from_mit_kdc() {
    let live = std::env::var("KERBER_LIVE").ok().as_deref() == Some("1");
    if !kdc_up() {
        if live {
            panic!("KERBER_LIVE=1 but 127.0.0.1:88 is not reachable");
        }
        eprintln!("skipping live kinit: 127.0.0.1:88 not reachable (set KERBER_LIVE=1 to fail)");
        return;
    }
    let dir = std::env::temp_dir();
    let cc = dir.join("krb5cc_kerber_rust_live");
    let _ = std::fs::remove_file(&cc);
    let mut password = b"userpassword".to_vec();
    let addr = KdcAddr::new("127.0.0.1");
    let result = kinit(
        &addr,
        "user@KERBER.TEST",
        &mut password,
        &cc,
        Some("host/testhost.kerber.test"),
    );
    match result {
        Ok(r) => {
            assert!(!r.as_out.session_key.as_bytes().is_empty());
            assert!(cc.is_file());
            let bytes = std::fs::read(&cc).unwrap();
            assert_eq!(&bytes[..2], &[0x05, 0x04]);
            println!("live kinit tgt ok tgs={}", r.tgs_out.is_some());
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("transport") {
                if live {
                    panic!("KERBER_LIVE=1 transport failure: {e}");
                }
                eprintln!("skipping host-network live kinit ({msg}); use scripts/client-gate.sh");
                return;
            }
            panic!("live kinit failed: {e}");
        }
    }
}
