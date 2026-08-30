//! Keytab v2 and FILE ccache round-trips through the shipped serializers.

use krb5_client::{Keytab, parse_principal};
use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_types::{PrincipalName, ascii};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn keytab_v2_round_trip_preserves_key_bytes() {
    let key_bytes = hex("42263c6e89f4fc28b8df68ee09799f15");
    let key = ProtocolKey::from_bytes(EncryptionType::Aes128CtsHmacSha196, &key_bytes).unwrap();
    let kt = Keytab::single(
        ascii("KERBER.TEST"),
        PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        3,
        key,
    );
    let bytes = kt.to_bytes();
    assert_eq!(bytes[0], 0x05);
    assert_eq!(bytes[1], 0x02);
    let parsed = Keytab::parse(&bytes).unwrap();
    assert_eq!(parsed.entries.len(), 1);
    assert_eq!(parsed.entries[0].kvno, 3);
    assert_eq!(parsed.entries[0].key.as_bytes(), key_bytes.as_slice());
    assert_eq!(
        parsed.entries[0].key.etype(),
        EncryptionType::Aes128CtsHmacSha196
    );
}

#[test]
fn parse_principal_splits_realm() {
    let (n, r) = parse_principal("user@KERBER.TEST").unwrap();
    assert_eq!(r, "KERBER.TEST");
    assert_eq!(n.name_type, PrincipalName::NT_PRINCIPAL);
}

#[test]
fn parse_principal_slash_is_srv_inst() {
    let (n, r) = parse_principal("host/slashhost@KERBER.TEST").unwrap();
    assert_eq!(r, "KERBER.TEST");
    assert_eq!(n.name_type, PrincipalName::NT_SRV_INST);
    assert_eq!(n.name_string.len(), 2);
    assert_eq!(n.components_joined(), "host/slashhost");
}

#[test]
fn parse_enterprise_is_one_component() {
    let (n, r) = krb5_protocol::parse_principal_ex("user@KERBER.TEST", true).unwrap();
    assert_eq!(r, "KERBER.TEST");
    assert_eq!(n.name_type, PrincipalName::NT_ENTERPRISE);
    assert_eq!(n.components_joined(), "user");
    let (n2, r2) =
        krb5_protocol::parse_principal_ex("alice@ad.example.com@KERBER.TEST", true).unwrap();
    assert_eq!(r2, "KERBER.TEST");
    assert_eq!(n2.components_joined(), "alice@ad.example.com");
}

#[test]
fn truncated_keytab_is_error() {
    assert!(Keytab::parse(&[0x05, 0x03]).is_err());
    assert!(Keytab::parse(&[0x05, 0x01]).is_ok()); // empty v1 is valid
    let mut truncated = vec![0x05, 0x02];
    truncated.extend_from_slice(&20i32.to_be_bytes());
    truncated.push(0);
    assert!(Keytab::parse(&truncated).is_err());
}

fn ccache_put_data(buf: &mut Vec<u8>, d: &[u8]) {
    buf.extend_from_slice(&(u32::try_from(d.len()).unwrap()).to_be_bytes());
    buf.extend_from_slice(d);
}

fn ccache_put_principal(buf: &mut Vec<u8>, realm: &[u8], parts: &[&[u8]]) {
    buf.extend_from_slice(&1i32.to_be_bytes());
    buf.extend_from_slice(&(u32::try_from(parts.len()).unwrap()).to_be_bytes());
    ccache_put_data(buf, realm);
    for p in parts {
        ccache_put_data(buf, p);
    }
}

#[test]
fn file_ccache_skips_etype_zero_config_and_keeps_tickets() {
    use krb5_client::FileCcache;
    let mut b = vec![0x05, 0x04, 0x00, 0x00];
    ccache_put_principal(&mut b, b"KERBER.TEST", &[b"user"]);
    // X-CACHECONF with etype 0 (MIT kinit).
    ccache_put_principal(&mut b, b"KERBER.TEST", &[b"user"]);
    ccache_put_principal(
        &mut b,
        b"X-CACHECONF:",
        &[b"krb5_ccache_conf_data", b"pa_type", b"krbtgt/KERBER.TEST"],
    );
    b.extend_from_slice(&0u16.to_be_bytes()); // etype 0
    ccache_put_data(&mut b, &[]); // empty key
    for _ in 0..4 {
        b.extend_from_slice(&0u32.to_be_bytes()); // times
    }
    b.push(0); // is_skey
    b.extend_from_slice(&0u32.to_be_bytes()); // flags
    b.extend_from_slice(&0u32.to_be_bytes()); // naddr
    b.extend_from_slice(&0u32.to_be_bytes()); // nauth
    ccache_put_data(&mut b, &[1]); // ticket
    ccache_put_data(&mut b, &[]); // second
    // Real AES256 ticket.
    ccache_put_principal(&mut b, b"KERBER.TEST", &[b"user"]);
    ccache_put_principal(&mut b, b"KERBER.TEST", &[b"host", b"svc"]);
    b.extend_from_slice(&18u16.to_be_bytes());
    ccache_put_data(&mut b, &[0u8; 32]);
    for _ in 0..4 {
        b.extend_from_slice(&0u32.to_be_bytes());
    }
    b.push(0);
    b.extend_from_slice(&0u32.to_be_bytes());
    b.extend_from_slice(&0u32.to_be_bytes());
    b.extend_from_slice(&0u32.to_be_bytes());
    ccache_put_data(&mut b, b"ticket-der");
    ccache_put_data(&mut b, &[]);
    let cc = FileCcache::parse(&b).expect("etype 0 must not fail the FILE");
    assert_eq!(cc.creds.len(), 1);
    assert_eq!(cc.creds[0].server.1.components_joined(), "host/svc");
    assert_eq!(cc.unparsed.len(), 1);
    let out = cc.to_bytes().expect("rewrite");
    assert!(
        out.windows(12).any(|w| w == b"X-CACHECONF:"),
        "rewrite must keep MIT config principal"
    );
}

#[test]
fn destroy_secret_file_unlinks() {
    let path = std::env::temp_dir().join(format!("krb5cc-destroy-{}", std::process::id()));
    std::fs::write(&path, b"secret-cache").unwrap();
    krb5_protocol::destroy_secret_file(&path).unwrap();
    assert!(!path.exists());
    assert!(krb5_protocol::destroy_secret_file(&path).is_err());
}

#[test]
fn destroy_secret_file_refuses_symlink() {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let target = dir.join(format!("krb5cc-destroy-target-{pid}"));
    let link = dir.join(format!("krb5cc-destroy-link-{pid}"));
    let _ = std::fs::remove_file(&target);
    let _ = std::fs::remove_file(&link);
    std::fs::write(&target, b"do-not-zero").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(krb5_protocol::destroy_secret_file(&link).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"do-not-zero");
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    let _ = std::fs::remove_file(&link);
    let _ = std::fs::remove_file(&target);
}

#[test]
fn destroy_secret_file_refuses_fifo_quickly() {
    let path = std::env::temp_dir().join(format!("krb5cc-destroy-fifo-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let st = std::process::Command::new("mkfifo")
        .arg(&path)
        .status()
        .expect("mkfifo");
    assert!(st.success());
    let t0 = std::time::Instant::now();
    assert!(krb5_protocol::destroy_secret_file(&path).is_err());
    assert!(t0.elapsed() < std::time::Duration::from_secs(2));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn destroy_secret_file_refuses_directory() {
    let path = std::env::temp_dir().join(format!("krb5cc-destroy-dir-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir(&path).unwrap();
    assert!(krb5_protocol::destroy_secret_file(&path).is_err());
    assert!(path.is_dir());
    std::fs::remove_dir(&path).unwrap();
}
