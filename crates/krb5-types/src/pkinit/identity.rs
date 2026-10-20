//! A KDC's PKINIT identity and CA certificates, loaded from MIT's option strings as
//! `pkinit_identity.c` and `pkinit_crypto_openssl.c` load them. An error is the message MIT
//! sets, which follows "PKINIT initialization failed: " in the KDC's startup line; where MIT
//! appends OpenSSL's reason, the reason is OpenSSL 3's (a system error has none: "(null)").

use std::path::Path;

use zeroize::Zeroizing;

use super::cms::unbase64;
use super::take_tlv;

const EINVAL: &str = "Invalid argument";
const ENOENT: &str = "No such file or directory";
const ENOTSUP: &str = "Operation not supported";
/// `ERR_reason_error_string` of a system error is NULL, which glibc prints so.
const NO_REASON: &str = "(null)";
/// MIT `MAX_CREDS_ALLOWED` (`pkinit.h`): the most identities a `DIR:` yields.
const MAX_CREDS: usize = 20;
/// id-ecPublicKey 1.2.840.10045.2.1 (OID body).
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// prime256v1 1.2.840.10045.3.1.7 (OID body).
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// A certificate and its P-256 private scalar; the scalar is wiped on drop.
pub struct PkinitIdentity {
    /// The certificate (DER).
    pub cert: Vec<u8>,
    key: Zeroizing<[u8; 32]>,
}

impl PkinitIdentity {
    /// The identity of `cert` and its private scalar `key`.
    #[must_use]
    pub fn new(cert: Vec<u8>, key: Zeroizing<[u8; 32]>) -> Self {
        Self { cert, key }
    }

    /// The identity of `cert` and a copy of `key`.
    #[must_use]
    pub fn from_key(cert: Vec<u8>, key: [u8; 32]) -> Self {
        Self::new(cert, Zeroizing::new(key))
    }

    /// The private scalar.
    #[must_use]
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }
}

impl std::fmt::Debug for PkinitIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PkinitIdentity")
            .field("cert", &self.cert)
            .field("key", &format_args!("<redacted>"))
            .finish()
    }
}

/// The KDC's identity from `pkinit_identity`: `FILE:cert[,key]` (a value with no type is one),
/// `DIR:` holding one `NAME.crt` with its `NAME.key`, or `ENV:VAR` naming another value. Keys
/// are P-256; `PKCS11:` and `PKCS12:` are refused as unsupported types.
/// MIT `process_option_identity` (`plugins/preauth/pkinit/pkinit_identity.c:378-465`): the type before the first colon, else FILE.
/// MIT `crypto_cert_select_default` (`plugins/preauth/pkinit/pkinit_crypto_openssl.c:4986-4991`): the KDC's identity is the only certificate loaded.
///
/// # Errors
///
/// MIT's message for the value that does not load.
pub fn load_identity(value: &str) -> Result<PkinitIdentity, String> {
    let mut found = load_identities(value)?;
    match found.len() {
        1 => found.pop().ok_or_else(|| ENOENT.into()),
        _ => Err(EINVAL.into()),
    }
}

/// Every certificate and key an identity value names, for a client to choose from: one for
/// `FILE:`, each `NAME.crt` with its `NAME.key` (20 at most) for `DIR:`.
/// MIT `crypto_load_certs` (`plugins/preauth/pkinit/pkinit_crypto_openssl.c:4645-4688`): the identity's type decides how its certificates load.
///
/// # Errors
///
/// As [`load_identity`]; a `DIR:` holding no pair that loads is `ENOENT`'s text.
pub fn load_identities(value: &str) -> Result<Vec<PkinitIdentity>, String> {
    load_identities_at(value, 0)
}

fn load_identities_at(value: &str, depth: usize) -> Result<Vec<PkinitIdentity>, String> {
    let (kind, residual) = value.split_once(':').unwrap_or(("FILE", value));
    match kind {
        "FILE" => {
            let (cert, key) = parse_fs_options(residual).ok_or(EINVAL)?;
            Ok(vec![load_cert_and_key(cert, key)?])
        }
        "DIR" => load_identity_dir(residual),
        "ENV" if depth < 8 => match std::env::var(residual) {
            Ok(v) => load_identities_at(&v, depth + 1),
            Err(_) => Err(EINVAL.into()),
        },
        "ENV" => Err(EINVAL.into()),
        _ => Err(format!("Unsupported type while processing '{value}'\n")),
    }
}

/// MIT `parse_fs_options` (`plugins/preauth/pkinit/pkinit_identity.c:307-346`): `cert[,key]`, the key in the certificate's file when not named.
fn parse_fs_options(residual: &str) -> Option<(&str, &str)> {
    if residual.is_empty() || residual.starts_with(',') {
        return None;
    }
    let mut names = residual.split(',').filter(|n| !n.is_empty());
    let cert = names.next()?;
    Some((cert, names.next().unwrap_or(cert)))
}

/// MIT `pkinit_load_fs_cert_and_key` (`plugins/preauth/pkinit/pkinit_crypto_openssl.c:4210-4268`): the certificate file, then the key file, each with its own message.
fn load_cert_and_key(cert_file: &str, key_file: &str) -> Result<PkinitIdentity, String> {
    let fsname = format!("FILE:{cert_file},{key_file}");
    let cert = read_cert(cert_file)
        .map_err(|why| format!("Cannot read certificate file '{cert_file}': {why}"))?;
    let key = read_key(key_file).map_err(|fault| match fault {
        KeyFault::Read(why) => format!("Cannot read key file '{fsname}': {why}"),
        KeyFault::NotP256 => {
            format!("Cannot use key file '{fsname}': only P-256 EC keys are supported")
        }
    })?;
    Ok(PkinitIdentity::new(cert, key))
}

/// MIT `pkinit_get_certs_dir` (`plugins/preauth/pkinit/pkinit_crypto_openssl.c:4298-4366`): each `NAME.crt` not starting with a dot, with `NAME.key`; a pair that does not load is skipped.
fn load_identity_dir(dir: &str) -> Result<Vec<PkinitIdentity>, String> {
    let mut found = Vec::new();
    for name in dir_names(dir)? {
        let Some(stem) = name.strip_suffix(".crt") else {
            continue;
        };
        if stem.is_empty() {
            continue;
        }
        let cert = join(dir, &name);
        let key = join(dir, &format!("{stem}.key"));
        if let Ok(id) = load_cert_and_key(&cert, &key) {
            found.push(id);
            if found.len() >= MAX_CREDS {
                break;
            }
        }
    }
    if found.is_empty() {
        return Err(ENOENT.into());
    }
    Ok(found)
}

/// The certificates of one `pkinit_anchors` or `pkinit_pool` value: `FILE:` a PEM file, or
/// `DIR:` every file in a directory.
/// MIT `process_option_ca_crl` (`plugins/preauth/pkinit/pkinit_identity.c:468-501`): the type is required, and only FILE and DIR are known.
///
/// # Errors
///
/// MIT's message for the value that does not load.
pub fn load_ca_certs(value: &str) -> Result<Vec<Vec<u8>>, String> {
    let Some((kind, residual)) = value.split_once(':') else {
        return Err(EINVAL.into());
    };
    match kind {
        "FILE" => load_ca_file(residual),
        "DIR" => {
            let mut certs = Vec::new();
            for name in dir_names(residual)? {
                for cert in load_ca_file(&join(residual, &name))? {
                    if !certs.contains(&cert) {
                        certs.push(cert);
                    }
                }
            }
            Ok(certs)
        }
        _ => Err(ENOTSUP.into()),
    }
}

/// MIT `load_cas_and_crls` (`plugins/preauth/pkinit/pkinit_crypto_openssl.c:4997-5151`): every certificate in the file once; a file with none loads nothing.
fn load_ca_file(path: &str) -> Result<Vec<Vec<u8>>, String> {
    let bytes =
        std::fs::read(path).map_err(|_| format!("Cannot open file '{path}': {NO_REASON}"))?;
    let text = String::from_utf8_lossy(&bytes);
    let mut certs = Vec::new();
    for block in pem_blocks(&text) {
        if !matches!(
            block.label,
            "CERTIFICATE" | "X509 CERTIFICATE" | "TRUSTED CERTIFICATE"
        ) {
            continue;
        }
        let cert = block_cert(&block).map_err(|why| format!("Cannot read file '{path}': {why}"))?;
        if !certs.contains(&cert) {
            certs.push(cert);
        }
    }
    Ok(certs)
}

/// The first certificate in `path`, as `PEM_read_bio_X509` reads it.
fn read_cert(path: &str) -> Result<Vec<u8>, &'static str> {
    let bytes = std::fs::read(path).map_err(|_| NO_REASON)?;
    let text = String::from_utf8_lossy(&bytes);
    let block = pem_blocks(&text)
        .into_iter()
        .find(|b| matches!(b.label, "CERTIFICATE" | "X509 CERTIFICATE"))
        .ok_or("no start line")?;
    block_cert(&block)
}

fn block_cert(block: &PemBlock<'_>) -> Result<Vec<u8>, &'static str> {
    let der = unbase64(block.body).ok_or("bad base64 decode")?;
    let (tag, body, _) = take_tlv(&der).ok_or("wrong tag")?;
    let (inner, tbs, _) = take_tlv(body).ok_or("wrong tag")?;
    if tag != 0x30 || inner != 0x30 || tbs.is_empty() {
        return Err("wrong tag");
    }
    let len = der.len() - take_tlv(&der).map_or(0, |(_, _, rest)| rest.len());
    Ok(der[..len].to_vec())
}

enum KeyFault {
    /// OpenSSL's reason the key does not read.
    Read(&'static str),
    /// A key MIT reads that this KDC cannot use.
    NotP256,
}

/// The P-256 private scalar of the first private key in `path`, as `PEM_read_bio_PrivateKey`
/// finds it; an encrypted key cannot be read, as the KDC has no prompter.
/// MIT `get_key` (`plugins/preauth/pkinit/pkinit_crypto_openssl.c:1406-1444`): the KDC's password callback fails, so an encrypted key is an error.
fn read_key(path: &str) -> Result<Zeroizing<[u8; 32]>, KeyFault> {
    let bytes = Zeroizing::new(std::fs::read(path).map_err(|_| KeyFault::Read(NO_REASON))?);
    let text = Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned());
    for block in pem_blocks(&text) {
        let pkcs8 = match block.label {
            "ENCRYPTED PRIVATE KEY" => return Err(KeyFault::Read("interrupted or cancelled")),
            "PRIVATE KEY" => true,
            "EC PRIVATE KEY" => false,
            "RSA PRIVATE KEY" | "DSA PRIVATE KEY" => return Err(KeyFault::NotP256),
            _ => continue,
        };
        if block.encrypted {
            return Err(KeyFault::Read("interrupted or cancelled"));
        }
        let der = Zeroizing::new(unbase64(block.body).ok_or(KeyFault::Read("bad base64 decode"))?);
        let scalar = if pkcs8 {
            pkcs8_p256(&der)
        } else {
            sec1_p256(&der, true)
        };
        return scalar.ok_or(KeyFault::NotP256);
    }
    Err(KeyFault::Read("unsupported"))
}

/// RFC 5208 PrivateKeyInfo of an id-ecPublicKey prime256v1 key.
fn pkcs8_p256(der: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    let (_, info, _) = take_tlv(der)?;
    let (_, _, rest) = take_tlv(info)?;
    let (_, alg, rest) = take_tlv(rest)?;
    let (_, alg_oid, params) = take_tlv(alg)?;
    let (_, curve, _) = take_tlv(params)?;
    if alg_oid != OID_EC_PUBLIC_KEY || curve != OID_P256 {
        return None;
    }
    let (_, key, _) = take_tlv(rest)?;
    sec1_p256(key, false)
}

/// RFC 5915 ECPrivateKey: a 32-byte scalar, and (when `named` is required) prime256v1.
fn sec1_p256(der: &[u8], named: bool) -> Option<Zeroizing<[u8; 32]>> {
    let (_, body, _) = take_tlv(der)?;
    let (_, _, rest) = take_tlv(body)?;
    let (t, scalar, mut rest) = take_tlv(rest)?;
    if t != 0x04 || scalar.len() != 32 {
        return None;
    }
    let mut curve_ok = !named;
    while let Some((t, v, next)) = take_tlv(rest) {
        if t == 0xa0 {
            curve_ok = take_tlv(v).is_some_and(|(_, oid, _)| oid == OID_P256);
        }
        rest = next;
    }
    if !curve_ok || p256::SecretKey::from_slice(scalar).is_err() {
        return None;
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(scalar);
    Some(key)
}

struct PemBlock<'a> {
    label: &'a str,
    encrypted: bool,
    body: &'a str,
}

/// The PEM blocks of `text` in order, each with its label, whether an RFC 1421 header marks it
/// encrypted, and its base64 text.
fn pem_blocks(text: &str) -> Vec<PemBlock<'_>> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("-----BEGIN ") {
        let after = &rest[at + 11..];
        let Some(close) = after.find("-----") else {
            break;
        };
        let label = &after[..close];
        let body_start = &after[close + 5..];
        let end = format!("-----END {label}-----");
        let Some(stop) = body_start.find(&end) else {
            break;
        };
        let raw = &body_start[..stop];
        let (headers, body) = match raw.find("\n\n").or_else(|| raw.find("\r\n\r\n")) {
            Some(gap) if raw[..gap].contains(':') => (&raw[..gap], &raw[gap..]),
            _ => ("", raw),
        };
        out.push(PemBlock {
            label,
            encrypted: headers.contains("ENCRYPTED"),
            body: body.trim(),
        });
        rest = &body_start[stop + end.len()..];
    }
    out
}

/// The names in `dir` not starting with a dot, sorted.
/// MIT `k5_dir_filenames` (`util/support/dir_filenames.c`): the directory's names, sorted; a directory that does not open is its errno.
fn dir_names(dir: &str) -> Result<Vec<String>, String> {
    let entries = std::fs::read_dir(dir).map_err(|e| sys_text(&e))?;
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| !n.starts_with('.'))
        .collect();
    names.sort();
    Ok(names)
}

fn join(dir: &str, name: &str) -> String {
    Path::new(dir).join(name).to_string_lossy().into_owned()
}

/// `strerror` of an I/O error: its text without Rust's " (os error N)".
fn sys_text(e: &std::io::Error) -> String {
    let text = e.to_string();
    match text.rfind(" (os error ") {
        Some(at) => text[..at].to_owned(),
        None => text,
    }
}
