#![forbid(unsafe_code)]
#![allow(
    clippy::disallowed_methods,
    reason = "test support: scratch paths from the environment"
)]

mod builders;
pub use builders::{AsReqBuilder, TgsReqBuilder};

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, encrypt, string_to_key};
use krb5_kdc::testrealm::{TEST_ADMIN, TEST_REALM, TEST_USER, documented_host};
use krb5_kdc::{
    IssuedAs, PacTicket, PrincipalStore, S2K_ITERS, sign_reply_pac, ticket_checksum_der,
    wrap_win2k_pac,
};
use krb5_protocol::pa_enc_timestamp;

use krb5_protocol::{pa_for_user, tgs_req};
use krb5_types::AuthorizationData;
use krb5_types::AuthorizationDataValue;
use krb5_types::EncTicketPart;
use krb5_types::EncryptedData;
use krb5_types::KdcOptions;
use krb5_types::KrbError;
use krb5_types::PaData;
use krb5_types::PrincipalName;
use krb5_types::Realm;
use krb5_types::TgsReq;
use krb5_types::Ticket;
use krb5_types::ascii;
use krb5_types::flag_bit;
use krb5_types::ku;
use krb5_types::pa;
use krb5_types::pac::{PAC_CLIENT_INFO, Pac, PacBuffer, PacIdentity, RpcSid, client_info_buffer};

#[must_use]
pub fn user() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
}

#[must_use]
pub fn admin() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN])
}

#[must_use]
pub fn host() -> PrincipalName {
    documented_host()
}

#[must_use]
pub fn foreign() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "OTHER.TEST"])
}

#[must_use]
pub fn krbtgt() -> PrincipalName {
    PrincipalName::krbtgt(TEST_REALM)
}

#[must_use]
pub fn realm() -> &'static str {
    TEST_REALM
}

#[must_use]
pub fn realm_with(name: &str) -> Realm {
    ascii(name)
}

#[must_use]
/// The directory is never host `/tmp`.
pub fn scratch_dir(name: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let scratch = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("CARGO_TARGET_DIR").map(|p| PathBuf::from(p).join("test-krb5"))
        })
        .or_else(|| std::env::var_os("KERBER_SCRATCH").map(PathBuf::from))
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/test-krb5")
        });
    let dir = scratch.join(format!(
        "{name}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch_dir");
    dir
}

/// On Linux the path is `/proc/self/fd` of a descriptor held on `dir`, and it is valid only while this guard lives.
pub struct SocketPath {
    _dir: Option<std::fs::File>,
    path: PathBuf,
}

impl SocketPath {
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

#[must_use]
pub fn socket_path(dir: &std::path::Path, name: &str) -> SocketPath {
    if std::path::Path::new("/proc/self/fd").is_dir() {
        use std::os::fd::AsRawFd;
        let handle =
            std::fs::File::open(dir).unwrap_or_else(|e| panic!("open {}: {e}", dir.display()));
        let path = PathBuf::from(format!("/proc/self/fd/{}/{name}", handle.as_raw_fd()));
        return SocketPath {
            _dir: Some(handle),
            path,
        };
    }
    let path = dir.join(name);
    assert!(
        path.as_os_str().len() < 108,
        "socket path {} is {} bytes; sun_path holds 108 with its NUL, and there is no /proc/self/fd \
         (shorten CARGO_TARGET_DIR or KERBER_SCRATCH)",
        path.display(),
        path.as_os_str().len()
    );
    SocketPath { _dir: None, path }
}

#[must_use]
/// A UDP port the kernel just chose can still be taken for TCP, so a busy pair is bound again.
pub fn loopback_udp_tcp() -> (std::net::UdpSocket, std::net::TcpListener) {
    for _ in 0..64 {
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind UDP 127.0.0.1:0");
        let addr = udp.local_addr().expect("UDP local_addr");
        match std::net::TcpListener::bind(addr) {
            Ok(tcp) => return (udp, tcp),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(e) => panic!("bind TCP {addr}: {e}"),
        }
    }
    panic!("no free loopback UDP + TCP port pair in 64 tries");
}

#[must_use]
pub fn pref_etypes() -> Vec<i32> {
    EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect()
}

#[must_use]
pub fn aes_key(seed: u8) -> ProtocolKey {
    ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[seed; 32]).expect("key")
}

#[must_use]
pub fn password_key(name: &str, password: &[u8]) -> ProtocolKey {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]);
    string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        password,
        cname.default_salt(TEST_REALM),
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .expect("s2k")
}

#[must_use]
pub fn store_key(store: &PrincipalStore, name: &str) -> ProtocolKey {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]);
    store
        .get_name(&cname)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone()
}

fn as_tgt(
    store: &PrincipalStore,
    name: &str,
    nonce: u32,
    key: &ProtocolKey,
    renewable: bool,
) -> IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]);
    let mut req = AsReqBuilder::new(cname, nonce)
        .padata(vec![pa_enc_timestamp(key).unwrap()])
        .build()
        .unwrap();
    if renewable {
        req.0.req_body.kdc_options = req
            .0
            .req_body
            .kdc_options
            .with_bit(flag_bit::RENEWABLE, true);
        req.0.req_body.rtime = Some(req.0.req_body.till.add_hours(48).expect("rtime"));
    }
    krb5_kdc::issue_as(store, &req).unwrap()
}

#[must_use]
pub fn issue_tgt(store: &PrincipalStore, name: &str, nonce: u32) -> IssuedAs {
    let key = store_key(store, name);
    as_tgt(store, name, nonce, &key, false)
}

#[must_use]
pub fn issue_tgt_password(
    store: &PrincipalStore,
    name: &str,
    password: &[u8],
    nonce: u32,
) -> IssuedAs {
    let key = password_key(name, password);
    as_tgt(store, name, nonce, &key, false)
}

#[must_use]
pub fn issue_tgt_renewable(
    store: &PrincipalStore,
    name: &str,
    nonce: u32,
    renewable: bool,
) -> IssuedAs {
    let key = store_key(store, name);
    as_tgt(store, name, nonce, &key, renewable)
}

#[must_use]
pub fn user_as(store: &PrincipalStore, nonce: u32) -> IssuedAs {
    issue_tgt(store, TEST_USER, nonce)
}

#[must_use]
pub fn user_as_bits(store: &PrincipalStore, nonce: u32, bits: &[(usize, bool)]) -> IssuedAs {
    let key = store_key(store, TEST_USER);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let mut req = AsReqBuilder::new(cname, nonce)
        .padata(vec![pa_enc_timestamp(&key).unwrap()])
        .build()
        .unwrap();
    for (bit, on) in bits {
        req.0.req_body.kdc_options = req.0.req_body.kdc_options.with_bit(*bit, *on);
    }
    krb5_kdc::issue_as(store, &req).unwrap()
}

#[must_use]
pub fn host_tgt(store: &PrincipalStore, nonce: u32) -> IssuedAs {
    let host = documented_host();
    let key = store
        .get_name(&host)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = AsReqBuilder::new(host, nonce)
        .padata(vec![pa_enc_timestamp(&key).unwrap()])
        .build()
        .unwrap();
    krb5_kdc::issue_as(store, &req).unwrap()
}

pub fn attach_pac(key: &ProtocolKey, part: &mut EncTicketPart, info_name: &str) {
    let stub = Pac::built(
        0,
        vec![PacBuffer::new(
            PAC_CLIENT_INFO,
            client_info_buffer(part.authtime.unix_seconds(), info_name),
        )],
    )
    .to_bytes();
    part.authorization_data = Some(wrap_win2k_pac(&[0]).unwrap());
    let der = ticket_checksum_der(part).unwrap();
    let ident = PacIdentity {
        sam: part.cname.components_joined(),
        realm: String::new(),
        domain_sid: RpcSid::nt_domain(1, 2, 3),
        rid: 1,
    };
    let pac = sign_reply_pac(
        &part.cname,
        part.authtime.unix_seconds(),
        &PacTicket {
            server: key,
            kdc: key,
            enc_tkt_der: &der,
            is_service_tkt: false,
        },
        &ident,
        None,
        Some(&stub),
    )
    .unwrap();
    part.authorization_data = Some(wrap_win2k_pac(&pac).unwrap());
}

#[must_use]
pub fn status(err: &krb5_kdc::Error) -> (i32, Option<&str>) {
    match err {
        krb5_kdc::Error::Protocol { code, text, .. } => (*code, text.as_deref()),
        other => panic!("expected protocol error, got {other:?}"),
    }
}

#[must_use]
pub fn expect_status(err: krb5_kdc::Error) -> (i32, Option<String>) {
    match err {
        krb5_kdc::Error::Protocol { code, text, .. } => (code, text),
        other => panic!("{other:?}"),
    }
}

#[must_use]
pub fn protocol_code(result: &Result<(), krb5_kdc::Error>) -> Option<i32> {
    match result {
        Err(krb5_kdc::Error::Protocol { code, .. }) => Some(*code),
        _ => None,
    }
}

#[must_use]
pub fn err_of(bytes: &[u8]) -> (i32, String) {
    let e: KrbError = decode(bytes).unwrap();
    let text = e
        .e_text
        .as_ref()
        .and_then(|t| std::str::from_utf8(t.as_bytes()).ok())
        .unwrap_or("")
        .to_owned();
    (e.error_code, text)
}

#[must_use]
pub fn err_of_cname(bytes: &[u8]) -> (i32, String, Option<String>) {
    let e: KrbError = decode(bytes).unwrap();
    let text = e
        .e_text
        .as_ref()
        .and_then(|t| std::str::from_utf8(t.as_bytes()).ok())
        .unwrap_or("")
        .to_owned();
    let cname = e.cname.as_ref().map(PrincipalName::components_joined);
    (e.error_code, text, cname)
}

#[must_use]
pub fn s4u_tgs(
    tgt: &IssuedAs,
    sname: PrincipalName,
    padata: Vec<PaData>,
    nonce: u32,
    opts: KdcOptions,
) -> TgsReq {
    let host = documented_host();
    TgsReqBuilder::new(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &host,
        sname,
        TEST_REALM,
        nonce,
    )
    .options(opts)
    .padata(padata)
    .etypes(pref_etypes())
    .build()
    .unwrap()
}

#[must_use]
pub fn s4u_self(tgt: &IssuedAs, padata: Vec<PaData>, nonce: u32) -> TgsReq {
    s4u_tgs(
        tgt,
        documented_host(),
        padata,
        nonce,
        KdcOptions::forwardable(),
    )
}

#[must_use]
pub fn s4u_admin(tgt: &IssuedAs, nonce: u32, opts: KdcOptions) -> TgsReq {
    let host = documented_host();
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).unwrap();
    TgsReqBuilder::new(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        nonce,
    )
    .options(opts)
    .padata(vec![pa])
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .unwrap()
}

#[must_use]
pub fn evidence_for_user(store: &PrincipalStore, nonce: u32) -> Ticket {
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let admin_tgt = issue_tgt(store, TEST_ADMIN, nonce);
    let req = tgs_req(
        admin_tgt.rep.0.ticket,
        &admin_tgt.session_key,
        TEST_REALM,
        &admin,
        user,
        TEST_REALM,
        nonce + 1,
    )
    .unwrap();
    krb5_kdc::issue_tgs(store, &req).unwrap().rep.0.ticket
}

#[must_use]
pub fn wrap_if_relevant(inner: &[AuthorizationDataValue]) -> AuthorizationData {
    let wrapped = encode(&inner.to_vec()).unwrap();
    vec![AuthorizationDataValue {
        ad_type: pa::AD_IF_RELEVANT,
        ad_data: wrapped.into(),
    }]
}

#[must_use]
pub fn reseal(ticket: &Ticket, part: &EncTicketPart, key: &ProtocolKey) -> Ticket {
    let der = encode(part).unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let mut out = ticket.clone();
    out.enc_part.cipher = encrypt(key, usage, &der).unwrap().into();
    out
}

pub fn reseal_mut(ticket: &mut Ticket, part: &EncTicketPart, key: &ProtocolKey) {
    let der = encode(part).unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    ticket.enc_part.cipher = encrypt(key, usage, &der).unwrap().into();
}

pub fn reseal_store(store: &PrincipalStore, ticket: &mut Ticket, part: &EncTicketPart) {
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    reseal_mut(ticket, part, &krbtgt.key);
}

#[must_use]
pub fn reseal_tgt(store: &PrincipalStore, tgt: &IssuedAs, part: &EncTicketPart) -> Ticket {
    reseal(
        &tgt.rep.0.ticket,
        part,
        &store.krbtgt().unwrap().best_key().unwrap().key,
    )
}

#[must_use]
pub fn reseal_incoming(key: &ProtocolKey, tgt: &IssuedAs, part: &EncTicketPart) -> Ticket {
    let der = encode(part).unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    Ticket {
        tkt_vno: tgt.rep.0.ticket.tkt_vno,
        realm: ascii("OTHER.TEST"),
        sname: PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", TEST_REALM]),
        enc_part: EncryptedData {
            etype: key.etype().to_iana(),
            kvno: Some(1),
            cipher: encrypt(key, usage, &der).unwrap().into(),
        },
    }
}
