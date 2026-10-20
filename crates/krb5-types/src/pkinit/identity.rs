//! A KDC's PKINIT identity and CA certificates, loaded from MIT's option strings as
//! `pkinit_identity.c` and `pkinit_crypto_openssl.c` load them. An error is the message MIT
//! sets, which follows "PKINIT initialization failed: " in the KDC's startup line; where MIT
//! appends OpenSSL's reason, the reason is OpenSSL 3's (a system error has none: "(null)").

use std::path::Path;

use zeroize::{Zeroize, Zeroizing};

use super::cms::{
    OID_ECDSA_SHA256, OID_K256_CURVE, OID_P224_CURVE, OID_P256_CURVE, OID_P384_CURVE,
    OID_P521_CURVE, OID_RSA_SHA256, k256_sign, p224_sign, p256_sign, p384_sign, p521_sign,
    unbase64,
};
use super::matching::{MatchTrace, select_cert};
use super::rsa::RsaKey;
use super::take_tlv;

const EINVAL: &str = "Invalid argument";
const ENOENT: &str = "No such file or directory";
const ENOTSUP: &str = "Operation not supported";
const EIO: i64 = 5;
/// `KRB5_PREAUTH_FAILED`, which `process_option_identity` returns for an unknown type.
const PREAUTH_FAILED: i64 = -1_765_328_174;
/// `KRB5KDC_ERR_PREAUTH_FAILED`, what `oerr` makes of a code of 0.
const KDC_PREAUTH_FAILED: i64 = -1_765_328_360;
/// `ERR_reason_error_string` of a system error is NULL, which glibc prints so.
const NO_REASON: &str = "(null)";
/// MIT `MAX_CREDS_ALLOWED` (`pkinit.h`): the most identities a `DIR:` yields.
const MAX_CREDS: usize = 20;
/// id-ecPublicKey 1.2.840.10045.2.1 (OID body).
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

#[derive(Clone)]
pub enum IdentityKey {
    P256(Zeroizing<[u8; 32]>),
    P384(Zeroizing<[u8; 48]>),
    P521(Zeroizing<[u8; 66]>),
    P224(Zeroizing<[u8; 28]>),
    K256(Zeroizing<[u8; 32]>),
    Rsa(Box<RsaKey>),
}

impl IdentityKey {
    #[must_use]
    pub fn p256(scalar: [u8; 32]) -> Self {
        Self::P256(Zeroizing::new(scalar))
    }

    #[must_use]
    pub fn from_pkcs8(der: &[u8]) -> Option<Self> {
        pkcs8_ec(der).or_else(|| RsaKey::from_pkcs8(der).map(|k| Self::Rsa(Box::new(k))))
    }

    // MIT cert_sig_alg; see docs/parity/a3-preauth.md
    #[must_use]
    pub fn sign_sha256(&self, msg: &[u8]) -> Option<(Vec<u8>, &'static [u8])> {
        match self {
            Self::P256(k) => Some((p256_sign(k, msg)?, OID_ECDSA_SHA256)),
            Self::P384(k) => Some((p384_sign(k, msg)?, OID_ECDSA_SHA256)),
            Self::P521(k) => Some((p521_sign(k, msg)?, OID_ECDSA_SHA256)),
            Self::P224(k) => Some((p224_sign(k, msg)?, OID_ECDSA_SHA256)),
            Self::K256(k) => Some((k256_sign(k, msg)?, OID_ECDSA_SHA256)),
            Self::Rsa(k) => Some((k.sign_sha256(msg)?, OID_RSA_SHA256)),
        }
    }
}

impl std::fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::P256(_) => f.write_str("IdentityKey::P256"),
            Self::P384(_) => f.write_str("IdentityKey::P384"),
            Self::P521(_) => f.write_str("IdentityKey::P521"),
            Self::P224(_) => f.write_str("IdentityKey::P224"),
            Self::K256(_) => f.write_str("IdentityKey::K256"),
            Self::Rsa(k) => write!(f, "IdentityKey::Rsa({k:?})"),
        }
    }
}

impl Zeroize for IdentityKey {
    fn zeroize(&mut self) {
        match self {
            Self::P256(k) | Self::K256(k) => k.zeroize(),
            Self::P384(k) => k.zeroize(),
            Self::P521(k) => k.zeroize(),
            Self::P224(k) => k.zeroize(),
            Self::Rsa(k) => k.zeroize(),
        }
    }
}

/// A certificate and its private key; the key is wiped on drop.
pub struct PkinitIdentity {
    /// The certificate (DER).
    pub cert: Vec<u8>,
    key: IdentityKey,
}

impl PkinitIdentity {
    #[must_use]
    pub fn new(cert: Vec<u8>, key: IdentityKey) -> Self {
        Self { cert, key }
    }

    /// The identity of `cert` and a copy of `key`.
    #[must_use]
    pub fn from_key(cert: Vec<u8>, key: [u8; 32]) -> Self {
        Self::new(cert, IdentityKey::P256(Zeroizing::new(key)))
    }

    #[must_use]
    pub fn key(&self) -> &IdentityKey {
        &self.key
    }
}

/// Why an identity did not load: MIT's code and the message it sets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityError {
    /// MIT's `krb5_error_code`: an errno, or a Kerberos code.
    pub code: i64,
    /// The message `krb5_get_error_message` gives for it.
    pub text: String,
}

impl IdentityError {
    fn new(code: i64, text: impl Into<String>) -> Self {
        Self {
            code,
            text: text.into(),
        }
    }

    fn einval() -> Self {
        Self::new(22, EINVAL)
    }

    fn enoent() -> Self {
        Self::new(2, ENOENT)
    }
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

impl From<IdentityError> for String {
    fn from(e: IdentityError) -> Self {
        e.text
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
/// are P-256 EC or RSA; `PKCS11:` and `PKCS12:` are refused as unsupported types.
/// MIT `process_option_identity` (`plugins/preauth/pkinit/pkinit_identity.c:378-465`): the type before the first colon, else FILE.
/// MIT `crypto_cert_select_default` (`plugins/preauth/pkinit/pkinit_crypto_openssl.c:4986-4991`): the KDC's identity is the only certificate loaded.
///
/// # Errors
///
/// MIT's message for the value that does not load.
pub fn load_identity(
    value: &str,
    trace: &mut dyn FnMut(MatchTrace<'_>),
) -> Result<PkinitIdentity, IdentityError> {
    let mut found = load_identities(value)?;
    let certs: Vec<&[u8]> = found.iter().map(|c| c.cert.as_slice()).collect();
    select_cert(&[], &certs, trace).map_err(|_| IdentityError::einval())?;
    found.pop().ok_or_else(IdentityError::enoent)
}

/// Every certificate and key an identity value names, for a client to choose from: one for
/// `FILE:`, each `NAME.crt` with its `NAME.key` (20 at most) for `DIR:`.
/// MIT `crypto_load_certs` (`plugins/preauth/pkinit/pkinit_crypto_openssl.c:4645-4688`): the identity's type decides how its certificates load.
///
/// # Errors
///
/// As [`load_identity`]; a `DIR:` holding no pair that loads is `ENOENT`'s text.
pub fn load_identities(value: &str) -> Result<Vec<PkinitIdentity>, IdentityError> {
    load_identities_at(value, 0)
}

fn load_identities_at(value: &str, depth: usize) -> Result<Vec<PkinitIdentity>, IdentityError> {
    let (kind, residual) = value.split_once(':').unwrap_or(("FILE", value));
    match kind {
        "FILE" => {
            let (cert, key) = parse_fs_options(residual).ok_or_else(IdentityError::einval)?;
            Ok(vec![load_cert_and_key(cert, key)?])
        }
        "DIR" => load_identity_dir(residual),
        "ENV" if depth < 8 => match std::env::var(residual) {
            Ok(v) => load_identities_at(&v, depth + 1),
            Err(_) => Err(IdentityError::einval()),
        },
        "ENV" => Err(IdentityError::einval()),
        _ => Err(IdentityError::new(
            PREAUTH_FAILED,
            format!("Unsupported type while processing '{value}'\n"),
        )),
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
fn load_cert_and_key(cert_file: &str, key_file: &str) -> Result<PkinitIdentity, IdentityError> {
    let fsname = format!("FILE:{cert_file},{key_file}");
    let cert = read_cert(cert_file).map_err(|(code, why)| {
        IdentityError::new(
            code,
            format!("Cannot read certificate file '{cert_file}': {why}"),
        )
    })?;
    let key = read_key(key_file).map_err(|fault| match fault {
        KeyFault::Read(code, why) => {
            IdentityError::new(code, format!("Cannot read key file '{fsname}': {why}"))
        }
        KeyFault::Unsupported => IdentityError::new(
            KDC_PREAUTH_FAILED,
            format!("Cannot use key file '{fsname}': only P-224, P-256, P-384, P-521 and secp256k1 EC keys and RSA keys are supported"),
        ),
    })?;
    Ok(PkinitIdentity::new(cert, key))
}

/// MIT `pkinit_get_certs_dir` (`plugins/preauth/pkinit/pkinit_crypto_openssl.c:4298-4366`): each `NAME.crt` not starting with a dot, with `NAME.key`; a pair that does not load is skipped.
fn load_identity_dir(dir: &str) -> Result<Vec<PkinitIdentity>, IdentityError> {
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
        return Err(IdentityError::enoent());
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
            for name in dir_names(residual).map_err(String::from)? {
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
/// MIT `get_cert` (`plugins/preauth/pkinit/pkinit_crypto_openssl.c:1311-1345`): a file that does not open is its errno, one with no certificate `EIO`.
fn read_cert(path: &str) -> Result<Vec<u8>, (i64, &'static str)> {
    let bytes = std::fs::read(path).map_err(|e| (errno(&e), NO_REASON))?;
    let text = String::from_utf8_lossy(&bytes);
    let block = pem_blocks(&text)
        .into_iter()
        .find(|b| matches!(b.label, "CERTIFICATE" | "X509 CERTIFICATE"))
        .ok_or((EIO, "no start line"))?;
    block_cert(&block).map_err(|why| (EIO, why))
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
    /// MIT's code and OpenSSL's reason the key does not read.
    Read(i64, &'static str),
    /// A key MIT reads that this KDC cannot use.
    Unsupported,
}

/// The first private key in `path`, P-256 EC or RSA, as `PEM_read_bio_PrivateKey`
/// finds it; an encrypted key cannot be read, as the KDC has no prompter.
/// MIT `get_key` (`plugins/preauth/pkinit/pkinit_crypto_openssl.c:1406-1444`): the KDC's password callback fails, so an encrypted key is an error.
fn read_key(path: &str) -> Result<IdentityKey, KeyFault> {
    let bytes =
        Zeroizing::new(std::fs::read(path).map_err(|e| KeyFault::Read(errno(&e), NO_REASON))?);
    let text = Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned());
    for block in pem_blocks(&text) {
        match block.label {
            "ENCRYPTED PRIVATE KEY" => {
                return Err(KeyFault::Read(EIO, "interrupted or cancelled"));
            }
            "PRIVATE KEY" | "EC PRIVATE KEY" | "RSA PRIVATE KEY" => {}
            "DSA PRIVATE KEY" => return Err(KeyFault::Unsupported),
            _ => continue,
        }
        if block.encrypted {
            return Err(KeyFault::Read(EIO, "interrupted or cancelled"));
        }
        let der =
            Zeroizing::new(unbase64(block.body).ok_or(KeyFault::Read(EIO, "bad base64 decode"))?);
        let rsa = |k: RsaKey| IdentityKey::Rsa(Box::new(k));
        let key = match block.label {
            "PRIVATE KEY" => pkcs8_ec(&der).or_else(|| RsaKey::from_pkcs8(&der).map(rsa)),
            "EC PRIVATE KEY" => sec1_ec(&der, None),
            _ => RsaKey::from_pkcs1(&der).map(rsa),
        };
        return key.ok_or(KeyFault::Unsupported);
    }
    Err(KeyFault::Read(EIO, "unsupported"))
}

fn pkcs8_ec(der: &[u8]) -> Option<IdentityKey> {
    let (_, info, _) = take_tlv(der)?;
    let (_, _, rest) = take_tlv(info)?;
    let (_, alg, rest) = take_tlv(rest)?;
    let (_, alg_oid, params) = take_tlv(alg)?;
    let (_, curve, _) = take_tlv(params)?;
    if alg_oid != OID_EC_PUBLIC_KEY {
        return None;
    }
    let (_, key, _) = take_tlv(rest)?;
    sec1_ec(key, Some(curve))
}

/// RFC 5915 ECPrivateKey: the scalar, on the curve it names, else the one PKCS#8 named.
fn sec1_ec(der: &[u8], outer: Option<&[u8]>) -> Option<IdentityKey> {
    let (_, body, _) = take_tlv(der)?;
    let (_, _, rest) = take_tlv(body)?;
    let (t, scalar, mut rest) = take_tlv(rest)?;
    if t != 0x04 {
        return None;
    }
    let mut named = None;
    while let Some((t, v, next)) = take_tlv(rest) {
        if t == 0xa0 {
            named = take_tlv(v).map(|(_, oid, _)| oid);
        }
        rest = next;
    }
    let curve = match (outer, named) {
        (Some(o), Some(n)) if o != n => return None,
        (Some(c), _) | (None, Some(c)) => c,
        (None, None) => return None,
    };
    match curve {
        OID_P256_CURVE => scalar_on::<32>(scalar, |k| p256::SecretKey::from_slice(k).is_ok())
            .map(IdentityKey::P256),
        OID_P384_CURVE => scalar_on::<48>(scalar, |k| p384::SecretKey::from_slice(k).is_ok())
            .map(IdentityKey::P384),
        OID_P521_CURVE => scalar_on::<66>(scalar, |k| p521::SecretKey::from_slice(k).is_ok())
            .map(IdentityKey::P521),
        OID_P224_CURVE => scalar_on::<28>(scalar, |k| p224::SecretKey::from_slice(k).is_ok())
            .map(IdentityKey::P224),
        OID_K256_CURVE => scalar_on::<32>(scalar, |k| k256::SecretKey::from_slice(k).is_ok())
            .map(IdentityKey::K256),
        _ => None,
    }
}

fn scalar_on<const N: usize>(
    scalar: &[u8],
    valid: impl Fn(&[u8]) -> bool,
) -> Option<Zeroizing<[u8; N]>> {
    let start = N.checked_sub(scalar.len())?;
    let mut key = Zeroizing::new([0u8; N]);
    key[start..].copy_from_slice(scalar);
    valid(&key[..]).then_some(key)
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
fn dir_names(dir: &str) -> Result<Vec<String>, IdentityError> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| IdentityError::new(errno(&e), sys_text(&e)))?;
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

/// The errno of an I/O error, `EIO` when it has none.
fn errno(e: &std::io::Error) -> i64 {
    e.raw_os_error().map_or(EIO, i64::from)
}

/// `strerror` of an I/O error: its text without Rust's " (os error N)".
fn sys_text(e: &std::io::Error) -> String {
    let text = e.to_string();
    match text.rfind(" (os error ") {
        Some(at) => text[..at].to_owned(),
        None => text,
    }
}
