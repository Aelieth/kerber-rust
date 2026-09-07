//! Round-up R1: `kinit` records `fast_avail` and the selected `pa_type` as
//! ccache config entries keyed by the TGT's server, like MIT
//! `write_out_ccache` (`get_in_tkt.c:1617-1640`, `save_selected_preauth_type`).

use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

use krb5_client::kinit_to_spec;
use krb5_config::CcSpec;
use krb5_kdc::{
    TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented, serve, shared_store,
};
use krb5_protocol::{FileCcache, KdcAddr};

fn config_value(cache: &FileCcache, key: &str, server: &str) -> Option<Vec<u8>> {
    cache
        .creds
        .iter()
        .find(|c| {
            c.is_config()
                && c.server.1.name_string.len() == 3
                && c.server.1.name_string[1].as_bytes() == key.as_bytes()
                && c.server.1.name_string[2].as_bytes() == server.as_bytes()
        })
        .map(|c| c.ticket.clone())
}

#[test]
fn kinit_records_fast_avail_and_pa_type_like_write_out_ccache() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = std::net::TcpListener::bind(addr).unwrap();
    let store = shared_store(store);
    thread::spawn(move || {
        let _ = serve(store, udp, tcp);
    });
    thread::sleep(Duration::from_millis(50));

    let dir = std::env::temp_dir().join(format!("kerber-r1-cc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("cc");
    let mut pw = TEST_USER_PASSWORD.to_vec();
    kinit_to_spec(
        &KdcAddr {
            host: "127.0.0.1".into(),
            port: addr.port(),
        },
        &format!("{TEST_USER}@{TEST_REALM}"),
        &mut pw,
        &CcSpec::File(path.clone()),
        None,
        false,
        None,
        None,
        None,
        false,
    )
    .expect("kinit");
    let cache = FileCcache::parse(&std::fs::read(&path).unwrap()).unwrap();
    let server = format!("krbtgt/{TEST_REALM}@{TEST_REALM}");
    // The Rust KDC echoed PA-FX-FAST; the user requires preauth, so the
    // encrypted-timestamp module (2) produced the reply.
    assert_eq!(
        config_value(&cache, "fast_avail", &server).as_deref(),
        Some(b"yes".as_slice())
    );
    assert_eq!(
        config_value(&cache, "pa_type", &server).as_deref(),
        Some(b"2".as_slice())
    );
    // Config entries precede the credentials, as MIT's memory-cache staging
    // writes them; the realm is the X-CACHECONF: marker.
    let first = &cache.creds[0];
    assert!(first.is_config());
    assert_eq!(first.server.0.as_bytes(), b"X-CACHECONF:");
    let _ = std::fs::remove_dir_all(&dir);
}
