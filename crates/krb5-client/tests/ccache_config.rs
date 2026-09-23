//! Round-up R1: `kinit` records `fast_avail` and the selected `pa_type` as
//! ccache config entries keyed by the TGT's server, like MIT
//! `write_out_ccache` (`get_in_tkt.c:1617-1640`, `save_selected_preauth_type`).

#[path = "common/mod.rs"]
mod common;
use common::isolate_host_krb5;

use std::net::UdpSocket;
use std::thread;

use krb5_client::kinit_to_spec;
use krb5_config::CcSpec;
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented};
use krb5_kdc::{serve, shared_store};

use krb5_protocol::{FileCcache, KdcAddr};
use krb5_testkit::scratch_dir;

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
    isolate_host_krb5();
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = std::net::TcpListener::bind(addr).unwrap();
    let store = shared_store(store);
    thread::spawn(move || {
        let _ = serve(store, udp, tcp);
    });

    let dir = scratch_dir("kerber-r1-cc");
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
        &krb5_client::InitCredsOpt {
            service: None,
            want_spake: false,
            armor_ccache: None,
            pkinit_identity: None,
            pkinit_anchors: None,
            enterprise: false,
        },
    )
    .expect("kinit");
    let cache = FileCcache::parse(&std::fs::read(&path).unwrap()).unwrap();
    let server = format!("krbtgt/{TEST_REALM}@{TEST_REALM}");
    // The Rust KDC echoed PA-FX-FAST and advertises SPAKE; after
    // PREAUTH_REQUIRED, `sort_krb5_padata_sequence` + `k5_preauth`
    // records pa_type 151 like MIT.
    assert_eq!(
        config_value(&cache, "fast_avail", &server).as_deref(),
        Some(b"yes".as_slice())
    );
    let pa_type = config_value(&cache, "pa_type", &server);
    assert_eq!(
        pa_type.as_deref(),
        Some(b"151".as_slice()),
        "write_out_ccache pa_type after the MIT hint walk, got {:?}",
        pa_type.as_deref().map(String::from_utf8_lossy)
    );
    // Config entries precede the credentials, as MIT's memory-cache staging
    // writes them; the realm is the X-CACHECONF: marker.
    let first = &cache.creds[0];
    assert!(first.is_config());
    assert_eq!(first.server.0.as_bytes(), b"X-CACHECONF:");
    let _ = std::fs::remove_dir_all(&dir);
}
