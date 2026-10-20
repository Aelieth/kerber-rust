//! CMS SignedData (`plugins/preauth/pkinit/pkinit_crypto_openssl.c`
//! `cms_signeddata_create` / `cms_signeddata_verify`): wrap, verify,
//! and the RFC 5652 certificate walk.

use super::identity::IdentityKey;
use super::{
    ECONTENT_AUTHDATA, OID_BC, OID_EKU, OID_KP_CLIENT_AUTH, OID_KP_KDC, OID_KU, OID_PKINIT_SAN,
    OID_SAN, oid_der, take_tlv, tlv,
};
use crate::OctetString;
use crate::wipe::Wiped;
use rasn::prelude::*;

const OID_CONTENT_TYPE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];

const OID_MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];

/// CMS AlgorithmIdentifier (digest or signature).
/// MIT `algorithm_identifier` (`lib/krb5/asn.1/asn1_k_encode.c:1331-1332`): the algorithm OID, then the parameters as their own DER.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct CmsAlgorithmIdentifier {
    /// Object identifier.
    pub algorithm: ObjectIdentifier,
    /// The parameters' whole DER element, whatever its type (a NULL included).
    /// MIT `opt_der_data` (`lib/krb5/asn.1/asn1_k_encode.c:65-65`): an optional field kept as its raw DER.
    pub parameters: Option<Any>,
}

/// CMS EncapsulatedContentInfo.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct CmsEncapContentInfo {
    /// eContentType (id-pkinit-authData or id-data).
    pub e_content_type: ObjectIdentifier,
    /// eContent.
    #[rasn(tag(explicit(0)))]
    pub e_content: Option<OctetString>,
}

/// CMS SignerInfo (subjectKeyIdentifier form, no signedAttrs).
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct CmsSignerInfo {
    /// version (3 when sid is subjectKeyIdentifier).
    pub version: i32,
    /// `subjectKeyIdentifier [0] EXPLICIT` (local CMS profile).
    #[rasn(tag(explicit(0)))]
    pub sid: OctetString,
    /// Digest algorithm.
    pub digest_algorithm: CmsAlgorithmIdentifier,
    /// Signature algorithm.
    pub signature_algorithm: CmsAlgorithmIdentifier,
    /// ECDSA-SHA256 signature of eContent (DER `SEQUENCE { r, s }`).
    pub signature: OctetString,
}

/// CMS SignedData.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct CmsSignedData {
    /// CMSVersion.
    pub version: i32,
    /// DigestAlgorithmIdentifiers.
    pub digest_algorithms: SequenceOf<CmsAlgorithmIdentifier>,
    /// Encapsulated content.
    pub encap_content_info: CmsEncapContentInfo,
    /// SignerInfos.
    pub signer_infos: SequenceOf<CmsSignerInfo>,
}

/// CMS ContentInfo wrapping [`CmsSignedData`].
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct CmsContentInfo {
    /// id-signedData.
    pub content_type: ObjectIdentifier,
    /// `SignedData [0] EXPLICIT`.
    #[rasn(tag(explicit(0)))]
    pub content: CmsSignedData,
}

fn sha256_bytes(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).to_vec()
}

pub(super) fn p256_sign(secret: &[u8; 32], message: &[u8]) -> Option<Vec<u8>> {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    let sk = SigningKey::from_bytes(secret.into()).ok()?;
    let sig: Signature = sk.sign(message);
    Some(sig.to_der().as_bytes().to_vec())
}

pub(super) fn p384_sign(secret: &[u8; 48], message: &[u8]) -> Option<Vec<u8>> {
    use p384::ecdsa::signature::hazmat::PrehashSigner;
    use p384::ecdsa::{Signature, SigningKey};
    let sk = SigningKey::from_bytes(secret.into()).ok()?;
    let sig: Signature = sk.sign_prehash(&sha256_bytes(message)).ok()?;
    Some(sig.to_der().as_bytes().to_vec())
}

pub(super) fn p224_sign(secret: &[u8; 28], message: &[u8]) -> Option<Vec<u8>> {
    use p224::ecdsa::signature::hazmat::PrehashSigner;
    use p224::ecdsa::{Signature, SigningKey};
    let sk = SigningKey::from_bytes(secret.into()).ok()?;
    let sig: Signature = sk.sign_prehash(&sha256_bytes(message)).ok()?;
    Some(sig.to_der().as_bytes().to_vec())
}

pub(super) fn k256_sign(secret: &[u8; 32], message: &[u8]) -> Option<Vec<u8>> {
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::{Signature, SigningKey};
    let sk = SigningKey::from_bytes(secret.into()).ok()?;
    let sig: Signature = sk.sign_prehash(&sha256_bytes(message)).ok()?;
    Some(sig.to_der().as_bytes().to_vec())
}

pub(super) fn p521_sign(secret: &[u8; 66], message: &[u8]) -> Option<Vec<u8>> {
    let d = zeroize::Zeroizing::new(
        p521::SecretKey::from_slice(secret)
            .ok()?
            .to_nonzero_scalar(),
    );
    let mut z = p521::FieldBytes::default();
    z[34..].copy_from_slice(&sha256_bytes(message));
    for _ in 0..8 {
        let mut k = zeroize::Zeroizing::new(p521::FieldBytes::default());
        getrandom::getrandom(&mut k).ok()?;
        k[0] &= 0x01;
        let Some(k) = p521::NonZeroScalar::from_repr(*k)
            .into_option()
            .map(zeroize::Zeroizing::new)
        else {
            continue;
        };
        if let Ok((sig, _)) = ecdsa::hazmat::sign_prehashed::<p521::NistP521>(&d, &k, &z) {
            return Some(sig.to_der().as_bytes().to_vec());
        }
    }
    None
}

fn p256_verify(public: &[u8], message: &[u8], der_sig: &[u8]) -> bool {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    let Ok(vk) = VerifyingKey::from_sec1_bytes(public) else {
        return false;
    };
    let Ok(sig) = Signature::from_der(der_sig) else {
        return false;
    };
    vk.verify(message, &sig).is_ok()
}

fn spki_uncompressed(cert: &[u8]) -> Option<Vec<u8>> {
    let (t, body, _) = take_tlv(cert)?;
    if t != 0x30 {
        return None;
    }
    let (t, tbs, _) = take_tlv(body)?;
    if t != 0x30 {
        return None;
    }
    let mut cur = tbs;
    if cur.first() == Some(&0xa0) {
        cur = take_tlv(cur)?.2;
    }
    cur = take_tlv(cur)?.2;
    cur = take_tlv(cur)?.2;
    cur = take_tlv(cur)?.2;
    cur = take_tlv(cur)?.2;
    cur = take_tlv(cur)?.2;
    let (t, spki, _) = take_tlv(cur)?;
    if t != 0x30 {
        return None;
    }
    let (_, _, rest) = take_tlv(spki)?;
    let (t, bit, _) = take_tlv(rest)?;
    if t != 0x03 {
        return None;
    }
    let pt = if bit.first() == Some(&0) {
        bit.get(1..)?
    } else {
        bit
    };
    if pt.first() == Some(&0x04) && pt.len() == 65 {
        return Some(pt.to_vec());
    }
    decompress_p256(pt)
}

fn decompress_p256(pt: &[u8]) -> Option<Vec<u8>> {
    use p256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
    use p256::{AffinePoint, Sec1Point};
    let ep = Sec1Point::from_bytes(pt).ok()?;
    let aff = Option::<AffinePoint>::from(AffinePoint::from_sec1_point(&ep))?;
    Some(aff.to_sec1_point(false).as_bytes().to_vec())
}

/// Encoded by hand so the Certificate SET uses IMPLICIT `[0]` (RFC 5652).
/// SignerInfo uses **issuerAndSerialNumber** (CMS version 1), matching MIT
/// OpenSSL `PKCS7_SIGNER_INFO`. `signed_attrs` if present is the
/// `[0] IMPLICIT SET` encoding; the signature is over the corresponding
/// `SET` (tag 0x31).
#[must_use]
#[expect(
    clippy::too_many_arguments,
    reason = "a SignerInfo's fields, as MIT's cms_signeddata_create sets them"
)]
pub fn cms_wrap_signed(
    e_content: &[u8],
    cert_der: &[u8],
    signature: &[u8],
    issuer: &[u8],
    serial: &[u8],
    econtent_oid: &[u8],
    signed_attrs: Option<&[u8]>,
    sig_alg: &[u8],
) -> Vec<u8> {
    let sha256 = oid_der(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
    let signed_data = oid_der(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]);
    let ectype = oid_der(econtent_oid);
    let sha256_alg = tlv(0x30, &[sha256.clone(), tlv(0x05, &[])].concat());
    // MIT cms_signeddata_create; see docs/parity/a3-preauth.md
    let sig_alg = tlv(0x30, &[oid_der(sig_alg), tlv(0x05, &[])].concat());
    let digest_algs = tlv(0x31, &sha256_alg);
    let econt = tlv(0xa0, &tlv(0x04, e_content));
    let encap = tlv(0x30, &[ectype, econt].concat());
    let certs = tlv(0xa0, cert_der);
    let mut ias_body = issuer.to_vec();
    ias_body.extend(tlv(0x02, serial));
    let ias = tlv(0x30, &ias_body);
    let mut signer_body = vec![tlv(0x02, &[0x01]), ias, sha256_alg];
    if let Some(sa) = signed_attrs {
        signer_body.push(sa.to_vec());
    }
    signer_body.push(sig_alg);
    signer_body.push(tlv(0x04, signature));
    let signer = tlv(0x30, &signer_body.concat());
    let signers = tlv(0x31, &signer);
    let sd = tlv(
        0x30,
        &[tlv(0x02, &[0x03]), digest_algs, encap, certs, signers].concat(),
    );
    tlv(0x30, &[signed_data, tlv(0xa0, &sd)].concat())
}

pub fn cms_sign_leaf(
    e_content: &[u8],
    cert_der: &[u8],
    key: &IdentityKey,
    econtent_oid: &[u8],
) -> Result<Vec<u8>, &'static str> {
    cms_sign_leaf_oids(e_content, cert_der, key, econtent_oid, econtent_oid)
}

/// CMS SignedData with independent encap and signed `content-type` OIDs.
pub fn cms_sign_leaf_oids(
    e_content: &[u8],
    cert_der: &[u8],
    key: &IdentityKey,
    encap_oid: &[u8],
    signed_oid: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let (issuer, serial) = cert_issuer_serial(cert_der).ok_or("cms issuer")?;
    let sattrs = signed_attrs_set(signed_oid, e_content);
    let (signature, sig_alg) = key.sign_sha256(&sattrs).ok_or("cms sign")?;
    let mut implicit = sattrs;
    if implicit.first() == Some(&0x31) {
        implicit[0] = 0xa0;
    }
    Ok(cms_wrap_signed(
        e_content,
        cert_der,
        &signature,
        &issuer,
        &serial,
        encap_oid,
        Some(&implicit),
        sig_alg,
    ))
}

pub(super) fn cert_issuer_serial(cert: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (t, body, _) = take_tlv(cert)?;
    if t != 0x30 {
        return None;
    }
    let (t, tbs, _) = take_tlv(body)?;
    if t != 0x30 {
        return None;
    }
    let mut cur = tbs;
    if cur.first() == Some(&0xa0) {
        cur = take_tlv(cur)?.2;
    }
    let (t, serial, rest) = take_tlv(cur)?;
    if t != 0x02 {
        return None;
    }
    let (_, _, rest) = take_tlv(rest)?;
    let (t, issuer, _) = take_tlv(rest)?;
    if t != 0x30 {
        return None;
    }
    Some((tlv(0x30, issuer), serial.to_vec()))
}

/// First PEM block of `kind` (`CERTIFICATE`, `EC PRIVATE KEY`, …).
#[must_use]
pub fn parse_pem(kind: &str, text: &str) -> Option<Vec<u8>> {
    let begin = format!("-----BEGIN {kind}-----");
    let end = format!("-----END {kind}-----");
    let start = text.find(&begin)? + begin.len();
    let rest = text.get(start..)?;
    let stop = rest.find(&end)?;
    unbase64(rest.get(..stop)?.trim())
}

/// Certificate DER plus P-256 scalar from a MIT `FILE:` identity PEM. The key's base64 text and
/// DER are wiped on every return.
#[must_use]
pub fn parse_identity_pem(text: &str) -> Option<(Vec<u8>, [u8; 32])> {
    let cert = parse_pem("CERTIFICATE", text)?;
    let key_der =
        Wiped(parse_pem("EC PRIVATE KEY", text).or_else(|| parse_pem("PRIVATE KEY", text))?);
    let key = parse_ec_scalar(&key_der)?;
    Some((cert, key))
}

fn parse_ec_scalar(der: &[u8]) -> Option<[u8; 32]> {
    let (t, body, _) = take_tlv(der)?;
    if t != 0x30 {
        return None;
    }
    let (t, _, rest) = take_tlv(body)?;
    if t != 0x02 {
        return None;
    }
    let (t, val, rest) = take_tlv(rest)?;
    if t == 0x04 {
        if val.len() == 32 {
            let mut s = [0u8; 32];
            s.copy_from_slice(val);
            return Some(s);
        }
        return parse_ec_scalar(val);
    }
    if t == 0x30 {
        let (t, oct, _) = take_tlv(rest)?;
        if t == 0x04 {
            if oct.len() == 32 {
                let mut s = [0u8; 32];
                s.copy_from_slice(oct);
                return Some(s);
            }
            return parse_ec_scalar(oct);
        }
    }
    None
}

pub(super) fn unbase64(s: &str) -> Option<Vec<u8>> {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bytes = Wiped(Vec::with_capacity(s.len()));
    bytes.extend(s.bytes().filter(|b| *b != b'=' && !b.is_ascii_whitespace()));
    let mut out = Wiped(Vec::with_capacity(bytes.len() * 3 / 4 + 1));
    for chunk in bytes.chunks(4) {
        let mut v = [0u8; 4];
        for (i, b) in chunk.iter().enumerate() {
            v[i] = u8::try_from(T.iter().position(|t| t == b)?).ok()?;
        }
        out.push((v[0] << 2) | (v[1] >> 4));
        if chunk.len() >= 3 {
            out.push((v[1] << 4) | (v[2] >> 2));
        }
        if chunk.len() >= 4 {
            out.push((v[2] << 6) | v[3]);
        }
    }
    Some(std::mem::take(&mut out.0))
}

pub(super) fn signed_attrs_set(econtent_oid: &[u8], e_content: &[u8]) -> Vec<u8> {
    let digest = sha256_bytes(e_content);
    let ct_oid = oid_der(OID_CONTENT_TYPE);
    let md_oid = oid_der(OID_MESSAGE_DIGEST);
    let ct = tlv(0x30, &[ct_oid, tlv(0x31, &oid_der(econtent_oid))].concat());
    let md = tlv(0x30, &[md_oid, tlv(0x31, &tlv(0x04, &digest))].concat());
    tlv(0x31, &[ct, md].concat())
}

/// CMS ContentInfo wrapping AuthPack with no signers (anonymous PKINIT).
#[must_use]
pub fn cms_wrap_unsigned(e_content: &[u8]) -> Vec<u8> {
    let oid = oid_der(ECONTENT_AUTHDATA);
    tlv(0x30, &[oid, tlv(0xa0, &tlv(0x04, e_content))].concat())
}

/// AuthPack from an unsigned CMS ContentInfo or SignedData with no signers.
#[must_use]
pub fn cms_extract_unsigned(der: &[u8]) -> Option<Vec<u8>> {
    if let Some((tag, body, _)) = take_tlv(der)
        && tag == 0x30
        && let Some((t, oid, rest)) = take_tlv(body)
        && t == 0x06
        && oid == ECONTENT_AUTHDATA
        && let Some((t, expl, _)) = take_tlv(rest)
        && t == 0xa0
        && let Some((t, oct, _)) = take_tlv(expl)
        && t == 0x04
    {
        return Some(oct.to_vec());
    }
    if let Ok(ci) = rasn::der::decode::<CmsContentInfo>(der)
        && ci.content.signer_infos.is_empty()
        && let Some(ec) = ci.content.encap_content_info.e_content
    {
        return Some(ec.to_vec());
    }
    unsigned_signeddata_econtent(der)
}

/// MIT `cms_signeddata_verify` (`pkinit_crypto_openssl.c:2052-2063`): a SignedData with no
/// SignerInfo is the anonymous case, and its content is read with no signature check.
/// The encapsulated content is returned without checking a signer, so the bytes are not an
/// authenticated pack.
fn unsigned_signeddata_econtent(der: &[u8]) -> Option<Vec<u8>> {
    let (tag, ci, _) = take_tlv(der)?;
    if tag != 0x30 {
        return None;
    }
    let (_, _, rest) = take_tlv(ci)?;
    let (t, sd_wrap, _) = take_tlv(rest)?;
    if t != 0xa0 {
        return None;
    }
    let (t, sd, _) = take_tlv(sd_wrap)?;
    if t != 0x30 {
        return None;
    }
    let mut cur = sd;
    cur = take_tlv(cur)?.2;
    cur = take_tlv(cur)?.2;
    let (t, encap, rest) = take_tlv(cur)?;
    if t != 0x30 {
        return None;
    }
    let (t, _, after_oid) = take_tlv(encap)?;
    if t != 0x06 {
        return None;
    }
    let (t, expl, _) = take_tlv(after_oid)?;
    if t != 0xa0 {
        return None;
    }
    let (t, oct, _) = take_tlv(expl)?;
    if t != 0x04 {
        return None;
    }
    let signers = if rest.first() == Some(&0xa0) {
        take_tlv(rest)?.2
    } else {
        rest
    };
    let (t, sbody, _) = take_tlv(signers)?;
    if t != 0x31 || !sbody.is_empty() {
        return None;
    }
    Some(oct.to_vec())
}

/// Extract eContent from CMS SignedData, or return `der` unchanged.
///
/// This does **not** authenticate the content. PKINIT must call
/// [`cms_verify`] against a provisioned trust anchor.
#[must_use]
pub fn cms_unwrap(der: &[u8]) -> Vec<u8> {
    if let Ok(ci) = rasn::der::decode::<CmsContentInfo>(der)
        && let Some(ec) = ci.content.encap_content_info.e_content
    {
        return ec.to_vec();
    }
    if let Ok(p) = cms_parts(der) {
        return p.e_content;
    }
    der.to_vec()
}

/// Verified CMS SignedData: eContent, signer certificate, eContentType OID body.
#[derive(Clone, Debug)]
pub struct CmsVerified {
    /// Encapsulated content.
    pub e_content: Vec<u8>,
    /// Embedded signer certificate (DER).
    pub cert: Vec<u8>,
    /// `eContentType` OID body (no DER tag).
    pub e_content_type: Vec<u8>,
}

/// Verify CMS SignedData against `trust_anchor` (CA certificate DER).
///
/// The embedded leaf must be issued by the trust anchor; the SignerInfo
/// ECDSA-SHA256 signature is then checked with the leaf public key.
/// There is no unverified fallback. Role checks (KDC vs client EKU/SAN)
/// are separate: [`cert_sans`], [`cert_eku`] and [`require_client_pkinit_san`].
///
/// # Errors
///
/// A field-named string (`"cms"`, `"encap"`, `"signer"`, …) when the SignedData is malformed;
/// a `"cms …"` chain string (`"cms trust"`, `"cms chain"`, `"cms expired"`, …) when
/// `trust_anchor` is not a usable CA or did not validly issue the leaf; `"cms spki"` for a leaf
/// with no P-256 key; `"cms signedAttrs"` when signedAttrs are absent, `"cms ecdsa attrs"` when
/// their signature fails, `"cms message-digest"` when their digest is not SHA-256 of the
/// eContent, and `"cms content-type"` when their content type is absent or not the eContentType.
pub fn cms_verify(der: &[u8], trust_anchor: &[u8]) -> Result<Vec<u8>, &'static str> {
    Ok(cms_verify_full(der, trust_anchor)?.e_content)
}

/// [`cms_verify`] plus the signer certificate and eContentType.
///
/// # Errors
///
/// A field-named string (`"cms"`, `"encap"`, `"signer"`, …) when the SignedData is malformed;
/// a `"cms …"` chain string (`"cms trust"`, `"cms chain"`, `"cms expired"`, …) when
/// `trust_anchor` is not a usable CA or did not validly issue the leaf; `"cms spki"` for a leaf
/// with no P-256 key; `"cms signedAttrs"` when signedAttrs are absent, `"cms ecdsa attrs"` when
/// their signature fails, `"cms message-digest"` when their digest is not SHA-256 of the
/// eContent, and `"cms content-type"` when their content type is absent or not the eContentType.
pub fn cms_verify_full(der: &[u8], trust_anchor: &[u8]) -> Result<CmsVerified, &'static str> {
    let p = cms_parts(der)?;
    cert_path_ok(&p.cert, trust_anchor)?;
    signer_verified(p)
}

fn signer_verified(p: CmsParts) -> Result<CmsVerified, &'static str> {
    let public = spki_uncompressed(&p.cert).ok_or("cms spki")?;
    // RFC 5652 §5.3: signedAttrs MUST be present when eContentType ≠ id-data.
    let sa = p.signed_attrs.as_ref().ok_or("cms signedAttrs")?;
    let mut set = sa.clone();
    if set.first() == Some(&0xa0) {
        set[0] = 0x31;
    }
    if !p256_verify(&public, &set, &p.signature) {
        return Err("cms ecdsa attrs");
    }
    let expect = sha256_bytes(&p.e_content);
    if !signed_attrs_digest_ok(sa, &expect) {
        return Err("cms message-digest");
    }
    let ct = signed_attrs_content_type(sa).ok_or("cms content-type")?;
    if ct != p.e_content_type {
        return Err("cms content-type");
    }
    Ok(CmsVerified {
        e_content: p.e_content,
        cert: p.cert,
        e_content_type: p.e_content_type,
    })
}

/// RFC 4556 §3.2.2: signer is a client cert bound to `cname` by its SAN.
///
/// # Errors
///
/// `"pkinit client san"` when `cert` has no PKINIT SAN, or the SAN realm is not `realm` or its
/// name is not `cname` (an enterprise `cname` compares the part before its last `@`).
pub fn require_client_pkinit_san(
    cert: &[u8],
    cname: &crate::PrincipalName,
    realm: &str,
) -> Result<(), &'static str> {
    let (san_realm, parts) = cert_pkinit_san(cert).ok_or("pkinit client san")?;
    if san_realm != realm {
        return Err("pkinit client san");
    }
    if parts != pkinit_cname_parts(cname) {
        return Err("pkinit client san");
    }
    Ok(())
}

fn pkinit_cname_parts(cname: &crate::PrincipalName) -> Vec<String> {
    if cname.name_type == crate::PrincipalName::NT_ENTERPRISE {
        let raw = cname.components_joined();
        let user = raw.rsplit_once('@').map_or(raw.as_str(), |(u, _)| u);
        return vec![user.to_string()];
    }
    cname
        .name_string
        .iter()
        .map(|s| String::from_utf8_lossy(s.as_bytes()).into_owned())
        .collect()
}

fn oid_body(der: &[u8]) -> &[u8] {
    if der.first() == Some(&0x06) {
        take_tlv(der).map_or(der, |(_, b, _)| b)
    } else {
        der
    }
}

fn signed_attr_set(sattrs: &[u8], want: &[u8]) -> Option<Vec<u8>> {
    let body = if sattrs.first() == Some(&0xa0) || sattrs.first() == Some(&0x31) {
        take_tlv(sattrs).map_or(sattrs, |(_, b, _)| b)
    } else {
        sattrs
    };
    let mut cur = body;
    while let Some((_, attr, rest)) = take_tlv(cur) {
        if let Some((_, oid, after)) = take_tlv(attr)
            && oid_body(oid) == want
            && let Some((_, set, _)) = take_tlv(after)
        {
            return Some(set.to_vec());
        }
        cur = rest;
        if rest.is_empty() {
            break;
        }
    }
    None
}

fn signed_attrs_digest_ok(sattrs: &[u8], expect: &[u8]) -> bool {
    let Some(set) = signed_attr_set(sattrs, OID_MESSAGE_DIGEST) else {
        return false;
    };
    take_tlv(&set).is_some_and(|(t, oct, _)| {
        let d = if t == 0x04 { oct } else { set.as_slice() };
        d == expect
    })
}

fn signed_attrs_content_type(sattrs: &[u8]) -> Option<Vec<u8>> {
    let set = signed_attr_set(sattrs, OID_CONTENT_TYPE)?;
    let (t, body, _) = take_tlv(&set)?;
    if t == 0x06 {
        Some(body.to_vec())
    } else {
        Some(set)
    }
}

fn cert_tbs_sig(cert: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (tag, body, _) = take_tlv(cert)?;
    if tag != 0x30 {
        return None;
    }
    let (t, tbs_body, rest) = take_tlv(body)?;
    let tbs = tlv(t, tbs_body);
    let (_, _, rest) = take_tlv(rest)?;
    let (t, sig_bit, _) = take_tlv(rest)?;
    if t != 0x03 {
        return None;
    }
    let sig = if sig_bit.first() == Some(&0) {
        sig_bit.get(1..)?.to_vec()
    } else {
        sig_bit.to_vec()
    };
    Some((tbs, sig))
}

fn cert_path_ok(leaf: &[u8], ca: &[u8]) -> Result<(), &'static str> {
    let ca_pub = spki_uncompressed(ca).ok_or("cms ca spki")?;
    let (tbs, sig) = cert_tbs_sig(leaf).ok_or("cms leaf")?;
    if !p256_verify(&ca_pub, &tbs, &sig) {
        return Err("cms trust");
    }
    if !cert_basic_constraints_ca(ca) {
        return Err("cms ca");
    }
    if !cert_key_cert_sign_ok(ca) {
        return Err("cms ca ku");
    }
    let iss = cert_name_der(leaf, true).ok_or("cms issuer")?;
    let sub = cert_name_der(ca, false).ok_or("cms subject")?;
    if iss != sub {
        return Err("cms chain");
    }
    let now = chrono::Utc::now();
    let (nb, na) = cert_time_window(leaf).ok_or("cms validity")?;
    if now < nb {
        return Err("cms notyet");
    }
    if now > na {
        return Err("cms expired");
    }
    let (ca_nb, ca_na) = cert_time_window(ca).ok_or("cms ca validity")?;
    if now < ca_nb {
        return Err("cms ca notyet");
    }
    if now > ca_na {
        return Err("cms ca expired");
    }
    Ok(())
}

/// rsaEncryption 1.2.840.113549.1.1.1 (OID body).
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// sha256WithRSAEncryption 1.2.840.113549.1.1.11 (OID body).
pub(super) const OID_RSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
/// sha384WithRSAEncryption 1.2.840.113549.1.1.12 (OID body).
const OID_RSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
/// sha512WithRSAEncryption 1.2.840.113549.1.1.13 (OID body).
const OID_RSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
/// ecdsa-with-SHA256 1.2.840.10045.4.3.2 (OID body).
pub(super) const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
/// ecdsa-with-SHA384 1.2.840.10045.4.3.3 (OID body).
const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
/// ecdsa-with-SHA512 1.2.840.10045.4.3.4 (OID body).
const OID_ECDSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];
/// id-sha256 2.16.840.1.101.3.4.2.1 (OID body).
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// id-sha384 2.16.840.1.101.3.4.2.2 (OID body).
const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
/// id-sha512 2.16.840.1.101.3.4.2.3 (OID body).
const OID_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

/// A digest a signature names. SHA-1 is not one: the lab's crypto policy refuses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Digest {
    Sha256,
    Sha384,
    Sha512,
}

impl Digest {
    fn from_oid(oid: &[u8]) -> Option<Self> {
        match oid {
            OID_SHA256 => Some(Self::Sha256),
            OID_SHA384 => Some(Self::Sha384),
            OID_SHA512 => Some(Self::Sha512),
            _ => None,
        }
    }

    fn of(self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest as _;
        match self {
            Self::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }

    /// The DER DigestInfo before the hash (RFC 8017 §9.2, note 1).
    fn digest_info_prefix(self) -> &'static [u8] {
        match self {
            Self::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            Self::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            Self::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }
}

/// id-ecPublicKey 1.2.840.10045.2.1 (OID body).
const OID_EC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// prime256v1 1.2.840.10045.3.1.7 (OID body).
pub(super) const OID_P256_CURVE: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
pub(super) const OID_P384_CURVE: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
pub(super) const OID_P521_CURVE: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];
pub(super) const OID_P224_CURVE: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x21];
pub(super) const OID_K256_CURVE: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x0a];

/// A certificate's SubjectPublicKeyInfo (its DER).
fn cert_spki(cert: &[u8]) -> Option<&[u8]> {
    let (_, body, _) = take_tlv(cert)?;
    let (_, tbs, _) = take_tlv(body)?;
    let mut cur = tbs;
    if cur.first() == Some(&0xa0) {
        cur = take_tlv(cur)?.2;
    }
    for _ in 0..5 {
        cur = take_tlv(cur)?.2;
    }
    let (t, _, rest) = take_tlv(cur)?;
    (t == 0x30).then(|| &cur[..cur.len() - rest.len()])
}

/// A certificate's to-be-signed DER, its signature algorithm OID and its signature.
fn cert_signed_parts(cert: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let (_, body, _) = take_tlv(cert)?;
    let (_, _, after_tbs) = take_tlv(body)?;
    let tbs = &body[..body.len() - after_tbs.len()];
    let (_, alg, rest) = take_tlv(after_tbs)?;
    let (_, oid, _) = take_tlv(alg)?;
    let (t, bits, _) = take_tlv(rest)?;
    if t != 0x03 {
        return None;
    }
    Some((tbs, oid, bits.get(1..)?))
}

/// Whether `issuer`'s key signed `cert`.
fn cert_signed_by(cert: &[u8], issuer: &[u8]) -> bool {
    cert_signed_parts(cert)
        .zip(cert_spki(issuer))
        .is_some_and(|((tbs, alg, sig), spki)| signature_ok(spki, alg, None, tbs, sig))
}

/// Whether `sig` over `msg` verifies under the key of `spki`. The key's own type decides how:
/// ECDSA on P-224, P-256, P-384, P-521 or secp256k1, or RSASSA-PKCS1-v1_5 (RFC 8017 §8.2.2). The digest is the one `alg` names, or
/// `digest` for `rsaEncryption` / `id-ecPublicKey`; SHA-1 is refused, as the lab's crypto policy
/// refuses it. MIT's client names its key's type with SHA-256 in its SignerInfo (`cert_sig_alg`):
/// `ecdsa-with-SHA256` for an EC key, else `sha256WithRSAEncryption`.
fn signature_ok(spki: &[u8], alg: &[u8], digest: Option<Digest>, msg: &[u8], sig: &[u8]) -> bool {
    let digest = match alg {
        OID_ECDSA_SHA256 | OID_RSA_SHA256 => Some(Digest::Sha256),
        OID_ECDSA_SHA384 | OID_RSA_SHA384 => Some(Digest::Sha384),
        OID_ECDSA_SHA512 | OID_RSA_SHA512 => Some(Digest::Sha512),
        OID_RSA | OID_EC_KEY => digest,
        _ => None,
    };
    let Some(digest) = digest else {
        return false;
    };
    let Some((_, spki_body, _)) = take_tlv(spki) else {
        return false;
    };
    let Some((_, key_alg, rest)) = take_tlv(spki_body) else {
        return false;
    };
    let Some((_, key_oid, params)) = take_tlv(key_alg) else {
        return false;
    };
    let Some((0x03, bits, _)) = take_tlv(rest) else {
        return false;
    };
    let Some(key) = bits.get(1..) else {
        return false;
    };
    let hash = digest.of(msg);
    if key_oid == OID_RSA {
        rsa_pkcs1_ok(key, digest, &hash, sig)
    } else {
        key_oid == OID_EC_KEY
            && take_tlv(params).is_some_and(|(_, curve, _)| ecdsa_ok(curve, key, &hash, sig))
    }
}

/// Whether `sig` over `msg` verifies under the SubjectPublicKeyInfo `spki` with algorithm `alg`.
#[must_use]
pub fn spki_signature_ok(spki: &[u8], alg: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    signature_ok(spki, alg, None, msg, sig)
}

fn ecdsa_ok(curve: &[u8], key: &[u8], hash: &[u8], sig: &[u8]) -> bool {
    use ecdsa::signature::hazmat::PrehashVerifier;
    match curve {
        OID_P256_CURVE => p256::ecdsa::VerifyingKey::from_sec1_bytes(key)
            .ok()
            .zip(p256::ecdsa::Signature::from_der(sig).ok())
            .is_some_and(|(vk, s)| vk.verify_prehash(hash, &s).is_ok()),
        OID_P384_CURVE => p384::ecdsa::VerifyingKey::from_sec1_bytes(key)
            .ok()
            .zip(p384::ecdsa::Signature::from_der(sig).ok())
            .is_some_and(|(vk, s)| vk.verify_prehash(hash, &s).is_ok()),
        OID_P521_CURVE => {
            let mut prehash = vec![0u8; 33usize.saturating_sub(hash.len())];
            prehash.extend_from_slice(hash);
            p521::ecdsa::VerifyingKey::from_sec1_bytes(key)
                .ok()
                .zip(p521::ecdsa::Signature::from_der(sig).ok())
                .is_some_and(|(vk, s)| vk.verify_prehash(&prehash, &s).is_ok())
        }
        OID_P224_CURVE => p224::ecdsa::VerifyingKey::from_sec1_bytes(key)
            .ok()
            .zip(p224::ecdsa::Signature::from_der(sig).ok())
            .is_some_and(|(vk, s)| vk.verify_prehash(hash, &s).is_ok()),
        // k256 refuses a high s, which OpenSSL takes; (r, n - s) verifies as (r, s) does.
        OID_K256_CURVE => k256::ecdsa::VerifyingKey::from_sec1_bytes(key)
            .ok()
            .zip(k256::ecdsa::Signature::from_der(sig).ok())
            .is_some_and(|(vk, s)| vk.verify_prehash(hash, &s.normalize_s()).is_ok()),
        _ => false,
    }
}

/// RSASSA-PKCS1-v1_5 verification of `sig` over a message whose digest is `hash`, under the
/// RSAPublicKey `key`: `sig^e mod n` is `00 01 FF.. 00` and the DigestInfo of `hash`.
/// Only public values are used, so no part of it is secret.
fn rsa_pkcs1_ok(key: &[u8], digest: Digest, hash: &[u8], sig: &[u8]) -> bool {
    use num_bigint::BigUint;
    let Some((_, body, _)) = take_tlv(key) else {
        return false;
    };
    let Some((0x02, n, rest)) = take_tlv(body) else {
        return false;
    };
    let Some((0x02, e, _)) = take_tlv(rest) else {
        return false;
    };
    let n_bytes = n.iter().skip_while(|b| **b == 0).count();
    let (n, e, s) = (
        BigUint::from_bytes_be(n),
        BigUint::from_bytes_be(e),
        BigUint::from_bytes_be(sig),
    );
    if sig.len() != n_bytes
        || s >= n
        || n_bytes < 11 + digest.digest_info_prefix().len() + hash.len()
    {
        return false;
    }
    let em = s.modpow(&e, &n).to_bytes_be();
    let info_len = digest.digest_info_prefix().len() + hash.len();
    let mut want = vec![0xff; n_bytes];
    want[0] = 0x00;
    want[1] = 0x01;
    want[n_bytes - info_len - 1] = 0x00;
    want[n_bytes - info_len..n_bytes - hash.len()].copy_from_slice(digest.digest_info_prefix());
    want[n_bytes - hash.len()..].copy_from_slice(hash);
    em.len() == n_bytes - 1 && em[..] == want[1..]
}

/// id-data 1.2.840.113549.1.7.1 (OID body).
const OID_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
/// id-signedData 1.2.840.113549.1.7.2 (OID body).
const OID_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
/// subjectKeyIdentifier 2.5.29.14 (OID body).
const OID_SKID: &[u8] = &[0x55, 0x1d, 0x0e];

/// Why the KDC refuses a client's signedAuthPack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CmsFault {
    /// The ContentInfo does not decode: OpenSSL's reason.
    Decode(&'static str),
    /// The pre-1.10 form, whose content is not an OCTET STRING.
    NotOctetString,
    /// The ContentInfo is not SignedData, or the eContentType is not id-pkinit-authData.
    WrongOid,
    /// No certificate names the signer, or an unsigned message carries no content.
    NoSigner,
    /// The signer's chain did not verify, and the certificate where it stopped.
    Chain(ChainError, Vec<u8>),
    /// The signature or its message digest did not verify: OpenSSL's reason.
    Signature(&'static str),
    /// The signed content-type attribute is not the eContentType. OpenSSL's `CMS_verify` does not
    /// check it; RFC 5652 binds the two, and this verifier refuses the message.
    ContentType,
}

impl CmsFault {
    #[must_use]
    pub fn code(&self) -> i32 {
        match self {
            Self::Signature(_) => crate::err::DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED,
            Self::Chain(e, _)
                if matches!(
                    e.reason,
                    "unable to get local issuer certificate" | "unable to get issuer certificate"
                ) =>
            {
                crate::err::CANT_VERIFY_CERTIFICATE
            }
            Self::Chain(..) => crate::err::INVALID_CERTIFICATE,
            _ => crate::err::PREAUTH_FAILED,
        }
    }

    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Decode(reason) => format!("Failed to decode CMS message: {reason}"),
            Self::NotOctetString => "Invalid pkinit packet: octet string expected".to_owned(),
            Self::WrongOid => "wrong oid\n".to_owned(),
            Self::NoSigner | Self::ContentType => "Preauthentication failed".to_owned(),
            Self::Signature(reason) => format!("Failed to verify CMS message: {reason}"),
            Self::Chain(e, _) => format!("Failed to verify received certificate {e}"),
        }
    }
}

/// MIT's `cms_msg_type`: a client's AuthPack, which may come unsigned, or the KDC's DH reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmsSigner {
    Client,
    Server,
}

/// A client's AuthPack from its signedAuthPack, and the certificate that signed it (none when
/// the message is unsigned, the anonymous case).
#[derive(Clone, Debug)]
pub struct CmsAuthPack {
    /// The encapsulated AuthPack.
    pub e_content: Vec<u8>,
    /// The signer's certificate (DER).
    pub signer: Option<Vec<u8>>,
}

/// A client's signedAuthPack as the KDC verifies it: it decodes; the pre-1.10 form and a
/// SignedData without signers are unsigned; the signer's certificate is found by its signer
/// identifier among the message's certificates, then `anchors`, then `intermediates`; its chain
/// reaches an anchor; its signature verifies; the eContentType is id-pkinit-authData.
/// MIT `cms_signeddata_verify` (`pkinit_crypto_openssl.c:1987-2229`): the order, and the
/// refusal of each step.
///
/// # Errors
///
/// The [`CmsFault`] of the first step that fails.
pub fn cms_signeddata_verify(
    der: &[u8],
    anchors: &[Vec<u8>],
    intermediates: &[Vec<u8>],
    from: CmsSigner,
) -> Result<CmsAuthPack, CmsFault> {
    let content_type = match from {
        CmsSigner::Client => ECONTENT_AUTHDATA,
        CmsSigner::Server => super::ECONTENT_DHKEY,
    };
    if let Some(reason) = cms_decode_reason(der) {
        return Err(CmsFault::Decode(reason));
    }
    let (_, ci, _) = take_tlv(der).ok_or(CmsFault::Decode("header too long"))?;
    let (_, oid, rest) = take_tlv(ci).ok_or(CmsFault::Decode("field missing"))?;
    let (_, content, _) = take_tlv(rest).ok_or(CmsFault::Decode("field missing"))?;
    if from == CmsSigner::Client && oid == ECONTENT_AUTHDATA {
        return match take_tlv(content) {
            Some((0x04, octets, _)) => Ok(CmsAuthPack {
                e_content: octets.to_vec(),
                signer: None,
            }),
            _ => Err(CmsFault::NotOctetString),
        };
    }
    if oid != OID_SIGNED_DATA {
        return Err(CmsFault::WrongOid);
    }
    let sd = SignedDataFields::read(content).ok_or(CmsFault::NoSigner)?;
    let Some(signer_info) = sd.signers.first() else {
        if from == CmsSigner::Server {
            return Err(CmsFault::NoSigner);
        }
        let e_content = sd.e_content.clone().ok_or(CmsFault::NoSigner)?;
        if sd.e_content_type != ECONTENT_AUTHDATA {
            return Err(CmsFault::WrongOid);
        }
        return Ok(CmsAuthPack {
            e_content,
            signer: None,
        });
    };
    let signer = sd
        .certs
        .iter()
        .chain(anchors)
        .chain(intermediates)
        .find(|c| signer_info.names(c))
        .cloned()
        .ok_or(CmsFault::NoSigner)?;
    let pool: Vec<&[u8]> = intermediates
        .iter()
        .chain(&sd.certs)
        .map(Vec::as_slice)
        .collect();
    build_chain(&signer, anchors, &pool).map_err(|(e, chain)| {
        CmsFault::Chain(e, chain.get(e.depth).cloned().unwrap_or_default())
    })?;
    let e_content = sd.e_content.clone().unwrap_or_default();
    let digest = Digest::from_oid(&signer_info.digest_alg);
    let verified = signer_info.signed_attrs.as_ref().is_some_and(|sa| {
        let mut set = sa.clone();
        set[0] = 0x31;
        cert_spki(&signer).is_some_and(|spki| {
            signature_ok(
                spki,
                &signer_info.signature_alg,
                digest,
                &set,
                &signer_info.signature,
            )
        })
    });
    if !verified {
        return Err(CmsFault::Signature("provider signature failure"));
    }
    let sa = signer_info.signed_attrs.as_deref().unwrap_or_default();
    if !digest.is_some_and(|d| signed_attrs_digest_ok(sa, &d.of(&e_content))) {
        return Err(CmsFault::Signature("verification failure"));
    }
    if signed_attrs_content_type(sa).as_deref() != Some(sd.e_content_type.as_slice()) {
        return Err(CmsFault::ContentType);
    }
    if sd.e_content_type != content_type {
        return Err(CmsFault::WrongOid);
    }
    Ok(CmsAuthPack {
        e_content,
        signer: Some(signer),
    })
}

/// A SignedData's encapsulated content, certificates and signers.
struct SignedDataFields {
    e_content_type: Vec<u8>,
    e_content: Option<Vec<u8>>,
    certs: Vec<Vec<u8>>,
    signers: Vec<SignerFields>,
}

/// One SignerInfo: how it names its certificate, its signed attributes (`[0]`), its signature.
struct SignerFields {
    issuer_serial: Option<(Vec<u8>, Vec<u8>)>,
    key_id: Option<Vec<u8>>,
    digest_alg: Vec<u8>,
    signed_attrs: Option<Vec<u8>>,
    signature_alg: Vec<u8>,
    signature: Vec<u8>,
}

impl SignerFields {
    /// Whether `cert` is the one this signer names: its issuer and serial number, or its
    /// subject key identifier.
    fn names(&self, cert: &[u8]) -> bool {
        if let Some(want) = &self.issuer_serial {
            return cert_issuer_serial(cert).as_ref() == Some(want);
        }
        self.key_id
            .as_deref()
            .is_some_and(|id| cert_key_id(cert).as_deref() == Some(id))
    }
}

impl SignedDataFields {
    /// The fields of the `[0]` content of a SignedData ContentInfo that decoded.
    fn read(content: &[u8]) -> Option<Self> {
        let (_, sd, _) = take_tlv(content)?;
        let (_, _, rest) = take_tlv(sd)?;
        let (_, _, rest) = take_tlv(rest)?;
        let (_, encap, mut rest) = take_tlv(rest)?;
        let (_, e_content_type, after) = take_tlv(encap)?;
        let e_content = take_tlv(after)
            .and_then(|(_, expl, _)| take_tlv(expl))
            .map(|(_, octets, _)| octets.to_vec());
        let mut certs = Vec::new();
        if rest.first() == Some(&0xa0) {
            let (_, mut set, next) = take_tlv(rest)?;
            rest = next;
            while let Some((t, body, more)) = take_tlv(set) {
                if t == 0x30 {
                    certs.push(tlv(t, body));
                }
                set = more;
            }
        }
        if rest.first() == Some(&0xa1) {
            rest = take_tlv(rest)?.2;
        }
        let (_, mut set, _) = take_tlv(rest)?;
        let mut signers = Vec::new();
        while let Some((_, info, more)) = take_tlv(set) {
            set = more;
            let (_, _, after_version) = take_tlv(info)?;
            let (sid_tag, sid, mut cur) = take_tlv(after_version)?;
            let (issuer_serial, key_id) = if sid_tag == 0x30 {
                let (it, issuer, after) = take_tlv(sid)?;
                let (_, serial, _) = take_tlv(after)?;
                (Some((tlv(it, issuer), serial.to_vec())), None)
            } else {
                (None, Some(sid.to_vec()))
            };
            let (_, digest_alg, next) = take_tlv(cur)?;
            cur = next;
            let signed_attrs = if cur.first() == Some(&0xa0) {
                let (t, body, next) = take_tlv(cur)?;
                cur = next;
                Some(tlv(t, body))
            } else {
                None
            };
            let (_, signature_alg, next) = take_tlv(cur)?;
            let (_, signature, _) = take_tlv(next)?;
            signers.push(SignerFields {
                issuer_serial,
                key_id,
                digest_alg: take_tlv(digest_alg)?.1.to_vec(),
                signed_attrs,
                signature_alg: take_tlv(signature_alg)?.1.to_vec(),
                signature: signature.to_vec(),
            });
        }
        Some(Self {
            e_content_type: e_content_type.to_vec(),
            e_content,
            certs,
            signers,
        })
    }
}

/// A certificate's subject key identifier.
fn cert_key_id(cert: &[u8]) -> Option<Vec<u8>> {
    let exts = walk_tbs(cert)?.extensions?;
    let mut id = None;
    each_ext(exts, |oid, val| {
        if oid != OID_SKID {
            return false;
        }
        id = take_tlv(val).map(|(_, keyid, _)| keyid.to_vec());
        true
    });
    id
}

/// The TD-TRUSTED-CERTIFIERS or TD-INVALID-CERTIFICATES of `certs`: one
/// ExternalPrincipalIdentifier each, its subject name, its issuer and serial number, and its
/// subject key identifier when it has one, each the DER of that field.
/// MIT `create_identifiers_from_stack` (`pkinit_crypto_openssl.c:5224-5300`): the fields of each certificate, in the stack's order.
#[must_use]
pub fn encode_td_certifiers(certs: &[&[u8]]) -> Vec<u8> {
    let ids: Vec<super::ExternalPrincipalIdentifier> = certs
        .iter()
        .map(|cert| {
            let subject = cert_name_der(cert, false);
            let issuer_serial = cert_issuer_serial(cert)
                .map(|(issuer, serial)| tlv(0x30, &[issuer, tlv(0x02, &serial)].concat()));
            super::ExternalPrincipalIdentifier {
                subject_name: subject.map(Into::into),
                issuer_and_serial_number: issuer_serial.map(Into::into),
                subject_key_identifier: cert_key_id(cert).map(|id| tlv(0x04, &id).into()),
            }
        })
        .collect();
    rasn::der::encode(&ids).unwrap_or_default()
}

/// One DER element's tag, contents and the rest, with the reason OpenSSL gives for a header it
/// cannot read or a length past the input.
fn der_next(input: &[u8]) -> Result<(u8, &[u8], &[u8]), &'static str> {
    let (&tag, after) = input.split_first().ok_or("header too long")?;
    let (&first, after) = after.split_first().ok_or("header too long")?;
    if tag & 0x1f == 0x1f || first == 0x80 {
        return Err("header too long");
    }
    let (len, after) = if first < 0x80 {
        (usize::from(first), after)
    } else {
        let n = usize::from(first & 0x7f);
        if n > std::mem::size_of::<usize>() || after.len() < n {
            return Err("header too long");
        }
        let len = after[..n]
            .iter()
            .fold(0usize, |l, b| (l << 8) | usize::from(*b));
        (len, &after[n..])
    };
    if len > after.len() {
        return Err("too long");
    }
    Ok((tag, &after[..len], &after[len..]))
}

/// The next element of a sequence, which must carry `tag`.
fn der_field<'a>(cur: &mut &'a [u8], tag: u8) -> Result<&'a [u8], &'static str> {
    if cur.is_empty() {
        return Err("field missing");
    }
    let (t, body, rest) = der_next(cur)?;
    if t != tag {
        return Err("wrong tag");
    }
    *cur = rest;
    Ok(body)
}

/// The next element of a sequence when it carries `tag`.
fn der_optional<'a>(cur: &mut &'a [u8], tag: u8) -> Result<Option<&'a [u8]>, &'static str> {
    if cur.first() == Some(&tag) {
        der_field(cur, tag).map(Some)
    } else {
        Ok(None)
    }
}

/// Every element of a SET OF or SEQUENCE OF, each checked by `each`.
fn der_each(
    mut items: &[u8],
    each: impl Fn(u8, &[u8]) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    while !items.is_empty() {
        let (t, body, rest) = der_next(items)?;
        each(t, body)?;
        items = rest;
    }
    Ok(())
}

/// OpenSSL's first reason when `d2i_CMS_ContentInfo` refuses `der`, as far as a client's
/// signedAuthPack goes: the ContentInfo, and a SignedData's fields and signers. The inside of a
/// certificate, an algorithm's parameters or an attribute is not walked.
/// MIT `cms_signeddata_verify` (`pkinit_crypto_openssl.c:1989-1991`): "Failed to decode CMS message" and OpenSSL's reason.
fn cms_decode_reason(der: &[u8]) -> Option<&'static str> {
    if der.is_empty() {
        return Some("too small");
    }
    cms_template(der).err()
}

/// The ContentInfo template walk of [`cms_decode_reason`].
fn cms_template(der: &[u8]) -> Result<(), &'static str> {
    let mut top = der;
    {
        let mut ci = der_field(&mut top, 0x30)?;
        let oid = der_field(&mut ci, 0x06)?;
        let mut content = der_field(&mut ci, 0xa0)?;
        if oid == OID_DATA {
            der_field(&mut content, 0x04)?;
        } else if oid == OID_SIGNED_DATA {
            let mut sd = der_field(&mut content, 0x30)?;
            der_field(&mut sd, 0x02)?;
            der_each(der_field(&mut sd, 0x31)?, |t, _| {
                (t == 0x30).then_some(()).ok_or("wrong tag")
            })?;
            let mut encap = der_field(&mut sd, 0x30)?;
            der_field(&mut encap, 0x06)?;
            if let Some(mut expl) = der_optional(&mut encap, 0xa0)? {
                der_field(&mut expl, 0x04)?;
            }
            if let Some(certs) = der_optional(&mut sd, 0xa0)? {
                der_each(certs, |t, _| {
                    matches!(t, 0x30 | 0xa0..=0xa3)
                        .then_some(())
                        .ok_or("wrong tag")
                })?;
            }
            der_optional(&mut sd, 0xa1)?;
            der_each(der_field(&mut sd, 0x31)?, |t, mut info| {
                if t != 0x30 {
                    return Err("wrong tag");
                }
                der_field(&mut info, 0x02)?;
                if der_optional(&mut info, 0x80)?.is_none() {
                    der_field(&mut info, 0x30)?;
                }
                der_field(&mut info, 0x30)?;
                der_optional(&mut info, 0xa0)?;
                der_field(&mut info, 0x30)?;
                der_field(&mut info, 0x04)?;
                der_optional(&mut info, 0xa1)?;
                Ok(())
            })?;
        } else {
            der_next(content)?;
        }
    }
    Ok(())
}

/// Where a certificate chain failed: the depth of the certificate (0 is the end entity) and
/// OpenSSL's `X509_verify_cert_error_string` for the error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainError {
    /// Depth of the certificate the error is about.
    pub depth: usize,
    /// OpenSSL's text for the error.
    pub reason: &'static str,
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(depth {}): {}", self.depth, self.reason)
    }
}

/// Certificates (DER), the end entity first.
type CertChain = Vec<Vec<u8>>;

/// OpenSSL's default verify depth.
const MAX_CHAIN: usize = 100;

/// `leaf`'s chain, leaf first, to one of `anchors` through `intermediates`, as OpenSSL's
/// `X509_verify_cert` builds and checks it: issuers found by subject name, trusted ones first;
/// each issuer a CA; then, from the anchor down, each issuer's key usage, each signature, each
/// validity period.
/// MIT `cms_signeddata_create` (`pkinit_crypto_openssl.c:1758-1782`): the KDC's own chain is built against its `pkinit_anchors` and `pkinit_pool`, and sent without the anchor.
///
/// # Errors
///
/// The depth and OpenSSL's text where the chain failed. Signatures are P-256 ECDSA only.
pub fn verify_chain(
    leaf: &[u8],
    anchors: &[Vec<u8>],
    intermediates: &[&[u8]],
) -> Result<Vec<Vec<u8>>, ChainError> {
    build_chain(leaf, anchors, intermediates).map_err(|(e, _)| e)
}

/// [`verify_chain`], and on failure the chain as far as it was built, the certificate at the
/// error's depth included (OpenSSL's current certificate).
fn build_chain(
    leaf: &[u8],
    anchors: &[Vec<u8>],
    intermediates: &[&[u8]],
) -> Result<CertChain, (ChainError, CertChain)> {
    let fail = |depth, reason| ChainError { depth, reason };
    let subject = |c: &[u8]| cert_name_der(c, false);
    let mut chain = vec![leaf.to_vec()];
    loop {
        let depth = chain.len() - 1;
        let current = &chain[depth];
        let issuer = cert_name_der(current, true);
        let signs = |c: &&[u8]| cert_signed_by(current, c);
        let named = |c: &&[u8]| issuer.is_some() && subject(c) == issuer;
        let trusted: Vec<&[u8]> = anchors.iter().map(Vec::as_slice).filter(named).collect();
        if let Some(a) = trusted
            .iter()
            .copied()
            .find(signs)
            .or(trusted.first().copied())
        {
            if a != current.as_slice() {
                chain.push(a.to_vec());
            }
            break;
        }
        let untrusted: Vec<&[u8]> = intermediates
            .iter()
            .copied()
            .filter(|c| named(c) && !chain.iter().any(|x| x == c))
            .collect();
        let Some(next) = untrusted
            .iter()
            .copied()
            .find(signs)
            .or(untrusted.first().copied())
        else {
            let self_signed = issuer.is_some() && issuer == subject(current);
            return Err((
                fail(
                    depth,
                    match (self_signed, depth) {
                        (true, 0) => "self-signed certificate",
                        (true, _) => "self-signed certificate in certificate chain",
                        _ => "unable to get local issuer certificate",
                    },
                ),
                chain.clone(),
            ));
        };
        if chain.len() > MAX_CHAIN {
            return Err((fail(depth, "certificate chain too long"), chain.clone()));
        }
        chain.push(next.to_vec());
    }
    let top = chain.len() - 1;
    let mut path_len = 0u64;
    for (depth, cert) in chain.iter().enumerate() {
        if cert_unhandled_critical(cert) {
            return Err((fail(depth, "unhandled critical extension"), chain.clone()));
        }
        if depth == 0 {
            continue;
        }
        if !(cert_basic_constraints_ca(cert) || (depth == top && cert_v1(cert))) {
            return Err((fail(depth, "invalid CA certificate"), chain.clone()));
        }
        if depth > 1 && cert_path_len(cert).is_some_and(|max| path_len > max) {
            return Err((
                fail(depth, "path length constraint exceeded"),
                chain.clone(),
            ));
        }
        if cert_name_der(cert, true) != cert_name_der(cert, false) {
            path_len += 1;
        }
    }
    let now = chrono::Utc::now();
    for depth in (0..=top).rev() {
        let cert = &chain[depth];
        if depth < top {
            let issuer = &chain[depth + 1];
            if !cert_key_cert_sign_ok(issuer) {
                return Err((
                    fail(depth + 1, "key usage does not include certificate signing"),
                    chain.clone(),
                ));
            }
            if !cert_signed_by(cert, issuer) {
                return Err((fail(depth, "certificate signature failure"), chain.clone()));
            }
        }
        let (not_before, not_after) = cert_time_window(cert).ok_or_else(|| {
            (
                fail(depth, "format error in certificate's notBefore field"),
                chain.clone(),
            )
        })?;
        if now < not_before {
            return Err((fail(depth, "certificate is not yet valid"), chain.clone()));
        }
        if now > not_after {
            return Err((fail(depth, "certificate has expired"), chain.clone()));
        }
    }
    Ok(chain)
}

/// A critical extension other than the four this verifier reads. OpenSSL refuses a critical one
/// it does not handle; this refuses every other, name constraints and policies included.
fn cert_unhandled_critical(cert: &[u8]) -> bool {
    let Some(mut cur) = walk_tbs(cert).and_then(|w| w.extensions) else {
        return false;
    };
    while let Some((_, ext, rest)) = take_tlv(cur) {
        if let Some((t, oid, after)) = take_tlv(ext)
            && t == 0x06
            && after.first() == Some(&0x01)
            && take_tlv(after).is_some_and(|(_, flag, _)| flag.first().is_some_and(|b| *b != 0))
            && ![OID_BC, OID_KU, OID_EKU, OID_SAN].contains(&oid)
        {
            return true;
        }
        cur = rest;
    }
    false
}

/// The `pathLenConstraint` of a certificate's basic constraints.
fn cert_path_len(cert: &[u8]) -> Option<u64> {
    let exts = walk_tbs(cert)?.extensions?;
    let mut max = None;
    each_ext(exts, |oid, val| {
        if oid != OID_BC {
            return false;
        }
        let mut cur = take_tlv(val).map_or(&[][..], |(_, seq, _)| seq);
        while let Some((t, v, rest)) = take_tlv(cur) {
            if t == 0x02 && v.len() <= 8 {
                max = Some(v.iter().fold(0u64, |n, b| (n << 8) | u64::from(*b)));
            }
            cur = rest;
        }
        true
    });
    max
}

/// A version 1 certificate: OpenSSL's `X509_check_ca` takes a self-signed one as a CA.
fn cert_v1(cert: &[u8]) -> bool {
    let Some((_, body, _)) = take_tlv(cert) else {
        return false;
    };
    let Some((_, tbs, _)) = take_tlv(body) else {
        return false;
    };
    tbs.first() != Some(&0xa0) && cert_name_der(cert, true) == cert_name_der(cert, false)
}

/// MIT `cms_signeddata_create` (`pkinit_crypto_openssl.c:1784-1811`): the chain without its trust anchor rides in the message, and the signer is named by its issuer and serial number.
pub fn cms_sign_chain(
    e_content: &[u8],
    leaf: &[u8],
    certs: &[Vec<u8>],
    key: &IdentityKey,
    econtent_oid: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let (issuer, serial) = cert_issuer_serial(leaf).ok_or("cms issuer")?;
    let sattrs = signed_attrs_set(econtent_oid, e_content);
    let (signature, sig_alg) = key.sign_sha256(&sattrs).ok_or("cms sign")?;
    let mut implicit = sattrs;
    if implicit.first() == Some(&0x31) {
        implicit[0] = 0xa0;
    }
    Ok(cms_wrap_signed(
        e_content,
        &certs.concat(),
        &signature,
        &issuer,
        &serial,
        econtent_oid,
        Some(&implicit),
        sig_alg,
    ))
}

/// id-ms-san-upn 1.3.6.1.4.1.311.20.2.3 (OID body): Microsoft's UPN otherName.
const OID_MS_SAN_UPN: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03];

/// The PKINIT names in a certificate's subjectAltName.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CertSans {
    /// The id-pkinit-san principals: realm, name type, components.
    pub principals: Vec<(String, i32, Vec<String>)>,
    /// The Microsoft UPNs, when asked for.
    pub upns: Vec<String>,
    pub dns_names: Vec<String>,
}

/// The PKINIT principals of `cert`'s subjectAltName and, with `upns`, its UPNs; `None` when the
/// extension is not a sequence of general names. A certificate without the extension has none.
/// MIT `crypto_retrieve_X509_sans` (`pkinit_crypto_openssl.c:2343-2440`): an extension that does not decode is an error; a principal name that does not decode, and a UPN holding a NUL, are skipped.
#[must_use]
pub fn cert_sans(cert: &[u8], upns: bool) -> Option<CertSans> {
    let mut out = CertSans::default();
    let Some(exts) = walk_tbs(cert).and_then(|w| w.extensions) else {
        return Some(out);
    };
    let mut san = None;
    each_ext(exts, |oid, val| {
        if oid == OID_SAN {
            san = Some(val.to_vec());
            return true;
        }
        false
    });
    let Some(san) = san else {
        return Some(out);
    };
    let (t, mut names, _) = take_tlv(&san)?;
    if t != 0x30 {
        return None;
    }
    while !names.is_empty() {
        let (tag, name, rest) = take_tlv(names)?;
        names = rest;
        if tag == 0x82 {
            if let Ok(dns) = std::str::from_utf8(name)
                && !name.contains(&0)
            {
                out.dns_names.push(dns.to_owned());
            }
            continue;
        }
        let Some((0x06, oid, value)) = (tag == 0xa0).then(|| take_tlv(name)).flatten() else {
            continue;
        };
        let Some((0xa0, value, _)) = take_tlv(value) else {
            continue;
        };
        if oid == OID_PKINIT_SAN {
            out.principals
                .extend(parse_krb5_principal_name_typed(value));
        } else if upns
            && oid == OID_MS_SAN_UPN
            && let Some((_, upn, _)) = take_tlv(value)
            && !upn.contains(&0)
            && let Ok(upn) = std::str::from_utf8(upn)
        {
            out.upns.push(upn.to_owned());
        }
    }
    Some(out)
}

/// id-ms-kp-sc-logon 1.3.6.1.4.1.311.20.2.2 (OID body).
pub(super) const OID_MS_SC_LOGON: &[u8] =
    &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x02];

/// What a certificate's extended key usage and key usage allow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EkuCheck {
    Accepted,
    NoDigitalSignature,
    Rejected,
}

const OID_KP_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];

// MIT crypto_check_cert_eku; see docs/parity/a3-preauth.md
#[must_use]
pub fn cert_eku(cert: &[u8], kdc: bool, accept_secondary: bool) -> EkuCheck {
    let (main, secondary) = if kdc {
        (OID_KP_KDC, OID_KP_SERVER_AUTH)
    } else {
        (OID_KP_CLIENT_AUTH, OID_MS_SC_LOGON)
    };
    if !(cert_has_eku(cert, main) || (accept_secondary && cert_has_eku(cert, secondary))) {
        return EkuCheck::Rejected;
    }
    let Some(exts) = walk_tbs(cert).and_then(|w| w.extensions) else {
        return EkuCheck::Rejected;
    };
    let mut usage = None;
    each_ext(exts, |oid, val| {
        if oid != OID_KU {
            return false;
        }
        usage = Some(bitstring_has(val, 0));
        true
    });
    match usage {
        Some(true) => EkuCheck::Accepted,
        Some(false) => EkuCheck::NoDigitalSignature,
        None => EkuCheck::Rejected,
    }
}

pub(super) struct TbsWalk<'a> {
    pub(super) issuer: &'a [u8],
    validity: &'a [u8],
    pub(super) subject: &'a [u8],
    pub(super) extensions: Option<&'a [u8]>,
}

/// Locate the issuer, validity, subject and extensions of a DER certificate. MIT has no walker of
/// its own: its PKINIT reads these fields through OpenSSL.
/// A certificate that is not a sequence yields no issuer or validity, and an optional version is
/// skipped rather than read as the serial.
pub(super) fn walk_tbs(cert: &[u8]) -> Option<TbsWalk<'_>> {
    let (t, body, _) = take_tlv(cert)?;
    if t != 0x30 {
        return None;
    }
    let (t, tbs, _) = take_tlv(body)?;
    if t != 0x30 {
        return None;
    }
    let mut cur = tbs;
    if cur.first() == Some(&0xa0) {
        cur = take_tlv(cur)?.2;
    }
    cur = take_tlv(cur)?.2;
    cur = take_tlv(cur)?.2;
    let (t, issuer, rest) = take_tlv(cur)?;
    if t != 0x30 {
        return None;
    }
    let (t, validity, rest) = take_tlv(rest)?;
    if t != 0x30 {
        return None;
    }
    let (t, subject, rest) = take_tlv(rest)?;
    if t != 0x30 {
        return None;
    }
    cur = take_tlv(rest)?.2;
    let mut extensions = None;
    while !cur.is_empty() {
        let (t, inner, rest) = take_tlv(cur)?;
        if t == 0xa3 {
            let (t, seq, _) = take_tlv(inner)?;
            if t == 0x30 {
                extensions = Some(seq);
            }
            break;
        }
        cur = rest;
    }
    Some(TbsWalk {
        issuer,
        validity,
        subject,
        extensions,
    })
}

pub(super) fn each_ext(extensions: &[u8], mut visit: impl FnMut(&[u8], &[u8]) -> bool) {
    let mut cur = extensions;
    while let Some((_, ext, rest)) = take_tlv(cur) {
        if let Some((t, oid, after)) = take_tlv(ext)
            && t == 0x06
        {
            let val = if after.first() == Some(&0x01) {
                take_tlv(after).and_then(|(_, _, r)| take_tlv(r))
            } else {
                take_tlv(after)
            };
            if let Some((t, oct, _)) = val
                && t == 0x04
                && visit(oid, oct)
            {
                return;
            }
        }
        cur = rest;
        if rest.is_empty() {
            break;
        }
    }
}

fn cert_key_cert_sign_ok(cert: &[u8]) -> bool {
    let Some(w) = walk_tbs(cert) else {
        return false;
    };
    let Some(exts) = w.extensions else {
        return true;
    };
    let mut saw_ku = false;
    let mut ok = false;
    each_ext(exts, |oid, val| {
        if oid != OID_KU {
            return false;
        }
        saw_ku = true;
        ok = bitstring_has(val, 5);
        true
    });
    !saw_ku || ok
}

pub(super) fn bitstring_has(der: &[u8], bit: usize) -> bool {
    let Some((t, body, _)) = take_tlv(der) else {
        return false;
    };
    if t != 0x03 {
        return false;
    }
    let Some((&unused, data)) = body.split_first() else {
        return false;
    };
    let total = data
        .len()
        .saturating_mul(8)
        .saturating_sub(usize::from(unused));
    if bit >= total {
        return false;
    }
    let Some(byte) = data.get(bit / 8) else {
        return false;
    };
    byte & (1 << (7 - (bit % 8))) != 0
}

fn cert_has_eku(cert: &[u8], oid_body: &[u8]) -> bool {
    let Some(w) = walk_tbs(cert) else {
        return false;
    };
    let Some(exts) = w.extensions else {
        return false;
    };
    let mut found = false;
    each_ext(exts, |oid, val| {
        if oid != OID_EKU {
            return false;
        }
        let Some((t, seq, _)) = take_tlv(val) else {
            return false;
        };
        if t != 0x30 {
            return false;
        }
        let mut cur = seq;
        while let Some((t, body, rest)) = take_tlv(cur) {
            if t == 0x06 && body == oid_body {
                found = true;
                return true;
            }
            cur = rest;
            if rest.is_empty() {
                break;
            }
        }
        false
    });
    found
}

fn cert_pkinit_san(cert: &[u8]) -> Option<(String, Vec<String>)> {
    let w = walk_tbs(cert)?;
    let exts = w.extensions?;
    let mut out = None;
    each_ext(exts, |oid, val| {
        if oid != OID_SAN {
            return false;
        }
        let Some((t, gns, _)) = take_tlv(val) else {
            return false;
        };
        if t != 0x30 {
            return false;
        }
        let mut cur = gns;
        while let Some((t, gn, rest)) = take_tlv(cur) {
            if t == 0xa0
                && let Some((ot, oidb, after)) = take_tlv(gn)
                && ot == 0x06
                && oidb == OID_PKINIT_SAN
                && let Some((vt, vbody, _)) = take_tlv(after)
            {
                let kn = if vt == 0xa0 { vbody } else { gn };
                out = parse_krb5_principal_name(kn);
                return out.is_some();
            }
            cur = rest;
            if rest.is_empty() {
                break;
            }
        }
        false
    });
    out
}

/// MIT `pkinit_krb5_principal_name_data` (`asn1_k_encode.c:1360-1364`): KRB5PrincipalName is a
/// SEQUENCE of `realm [0]` and `principalName [1]`, not RFC 4120's PrincipalName.
/// A realm that is not a string, or a name that is not the principal-name tag, is not a principal.
fn parse_krb5_principal_name(der: &[u8]) -> Option<(String, Vec<String>)> {
    parse_krb5_principal_name_typed(der).map(|(realm, _, parts)| (realm, parts))
}

/// A KRB5PrincipalName's realm, name type and components.
fn parse_krb5_principal_name_typed(der: &[u8]) -> Option<(String, i32, Vec<String>)> {
    let seq = if der.first() == Some(&0x30) {
        take_tlv(der)?.1
    } else {
        der
    };
    let (t, realm_inner, rest) = take_tlv(seq)?;
    if t != 0xa0 {
        return None;
    }
    let (t, realm_b, _) = take_tlv(realm_inner)?;
    if t != 0x1b && t != 0x16 && t != 0x0c {
        return None;
    }
    let realm = std::str::from_utf8(realm_b).ok()?.to_string();
    let (t, pname, _) = take_tlv(rest)?;
    if t != 0xa1 {
        return None;
    }
    let pname_seq = if pname.first() == Some(&0x30) {
        take_tlv(pname)?.1
    } else {
        pname
    };
    let mut cur = pname_seq;
    let mut parts = Vec::new();
    let mut name_type = 0;
    while let Some((t, inner, rest)) = take_tlv(cur) {
        if t == 0xa0
            && let Some((0x02, n, _)) = take_tlv(inner)
            && (1..=4).contains(&n.len())
        {
            let fill = if n[0] & 0x80 == 0 { 0 } else { 0xff };
            let mut be = [fill; 4];
            be[4 - n.len()..].copy_from_slice(n);
            name_type = i32::from_be_bytes(be);
        }
        if t == 0xa1 {
            let names = if inner.first() == Some(&0x30) {
                take_tlv(inner)?.1
            } else {
                inner
            };
            let mut n = names;
            while let Some((nt, nb, nrest)) = take_tlv(n) {
                if nt == 0x1b || nt == 0x16 || nt == 0x0c {
                    parts.push(std::str::from_utf8(nb).ok()?.to_string());
                }
                n = nrest;
                if nrest.is_empty() {
                    break;
                }
            }
        }
        cur = rest;
        if rest.is_empty() {
            break;
        }
    }
    Some((realm, name_type, parts))
}

fn cert_basic_constraints_ca(cert: &[u8]) -> bool {
    let Some(w) = walk_tbs(cert) else {
        return false;
    };
    let Some(exts) = w.extensions else {
        return false;
    };
    let mut is_ca = false;
    each_ext(exts, |oid, val| {
        if oid != OID_BC {
            return false;
        }
        if let Some((t, seq, _)) = take_tlv(val)
            && t == 0x30
            && let Some((bt, bb, _)) = take_tlv(seq)
        {
            is_ca = bt == 0x01 && bb.first() == Some(&0xff);
        }
        true
    });
    is_ca
}

fn cert_name_der(cert: &[u8], issuer: bool) -> Option<Vec<u8>> {
    let w = walk_tbs(cert)?;
    let body = if issuer { w.issuer } else { w.subject };
    Some(tlv(0x30, body))
}

fn cert_time_window(
    cert: &[u8],
) -> Option<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)> {
    let w = walk_tbs(cert)?;
    let (t0, b0, rest) = take_tlv(w.validity)?;
    let (t1, b1, _) = take_tlv(rest)?;
    Some((parse_x509_time(t0, b0)?, parse_x509_time(t1, b1)?))
}

fn parse_x509_time(tag: u8, body: &[u8]) -> Option<chrono::DateTime<chrono::Utc>> {
    let s = std::str::from_utf8(body).ok()?;
    let (year, rest) = if tag == 0x17 && s.len() >= 13 {
        let yy: i32 = s.get(..2)?.parse().ok()?;
        let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        (year, s.get(2..13)?)
    } else if tag == 0x18 && s.len() >= 15 {
        let year: i32 = s.get(..4)?.parse().ok()?;
        (year, s.get(4..15)?)
    } else {
        return None;
    };
    let month: u32 = rest.get(..2)?.parse().ok()?;
    let day: u32 = rest.get(2..4)?.parse().ok()?;
    let hour: u32 = rest.get(4..6)?.parse().ok()?;
    let min: u32 = rest.get(6..8)?.parse().ok()?;
    let sec: u32 = rest.get(8..10)?.parse().ok()?;
    Some(
        chrono::NaiveDate::from_ymd_opt(year, month, day)?
            .and_hms_opt(hour, min, sec)?
            .and_utc(),
    )
}

struct CmsParts {
    e_content: Vec<u8>,
    cert: Vec<u8>,
    signature: Vec<u8>,
    signed_attrs: Option<Vec<u8>>,
    e_content_type: Vec<u8>,
}

/// MIT `cms_signeddata_verify` (`pkinit_crypto_openssl.c:2022-2028`): MIT refuses a message whose
/// ContentInfo type is not id-signedData ("wrong oid"); this port does not check that type and
/// reads the `[0]` content as SignedData whatever the OID.
/// Content that does not parse as SignedData is an error.
fn cms_parts(der: &[u8]) -> Result<CmsParts, &'static str> {
    let (tag, ci, _) = take_tlv(der).ok_or("cms")?;
    if tag != 0x30 {
        return Err("cms");
    }
    let (_, _oid, rest) = take_tlv(ci).ok_or("cms oid")?;
    let (t, sd_wrap, _) = take_tlv(rest).ok_or("cms sd")?;
    if t != 0xa0 {
        return Err("cms sd tag");
    }
    let (t, sd, _) = take_tlv(sd_wrap).ok_or("cms sd seq")?;
    if t != 0x30 {
        return Err("cms sd seq");
    }
    // version, digestAlgs, encap, [0] certs, signerInfos
    let mut cur = sd;
    let _ = take_tlv(cur).ok_or("ver")?;
    cur = take_tlv(cur).ok_or("ver")?.2;
    cur = take_tlv(cur).ok_or("digests")?.2;
    let (t, encap, rest) = take_tlv(cur).ok_or("encap")?;
    if t != 0x30 {
        return Err("encap");
    }
    let (t, ct, after_oid) = take_tlv(encap).ok_or("eContentType")?;
    if t != 0x06 {
        return Err("eContentType");
    }
    let e_content_type = ct.to_vec();
    let (t, expl, _) = take_tlv(after_oid).ok_or("eContent")?;
    if t != 0xa0 {
        return Err("eContent tag");
    }
    let (t, oct, _) = take_tlv(expl).ok_or("eContent oct")?;
    if t != 0x04 {
        return Err("eContent oct");
    }
    let e_content = oct.to_vec();
    let (t, cert_set, rest) = take_tlv(rest).ok_or("certs")?;
    if t != 0xa0 {
        return Err("certs tag");
    }
    // IMPLICIT SET OF Certificate: body is the Certificate SEQUENCE
    let cert = if cert_set.first() == Some(&0x30) {
        let (tt, body, _) = take_tlv(cert_set).ok_or("cert")?;
        tlv(tt, body)
    } else {
        cert_set.to_vec()
    };
    let (t, signers, _) = take_tlv(rest).ok_or("signers")?;
    if t != 0x31 {
        return Err("signers");
    }
    let (t, signer, _) = take_tlv(signers).ok_or("signer")?;
    if t != 0x30 {
        return Err("signer seq");
    }
    // version, sid, digestAlg, sigAlg, signature OCTET STRING
    let mut s = signer;
    s = take_tlv(s).ok_or("sver")?.2;
    s = take_tlv(s).ok_or("sid")?.2;
    s = take_tlv(s).ok_or("dalg")?.2;
    let signed_attrs = if s.first() == Some(&0xa0) {
        let (t, body, rest) = take_tlv(s).ok_or("sattr")?;
        s = rest;
        Some(tlv(t, body))
    } else {
        None
    };
    s = take_tlv(s).ok_or("salg")?.2;
    let (t, sig, _) = take_tlv(s).ok_or("sig")?;
    if t != 0x04 {
        return Err("sig oct");
    }
    Ok(CmsParts {
        e_content,
        cert,
        signature: sig.to_vec(),
        signed_attrs,
        e_content_type,
    })
}

#[cfg(any(test, feature = "test-ca"))]
pub(super) fn pem(kind: &str, der: &[u8]) -> String {
    let b = base64(der);
    let mut out = format!("-----BEGIN {kind}-----\n");
    for chunk in b.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(kind);
    out.push_str("-----\n");
    out
}

#[cfg(any(test, feature = "test-ca"))]
fn base64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0usize;
    while i < data.len() {
        let b0 = data[i];
        let b1 = data.get(i + 1).copied();
        let b2 = data.get(i + 2).copied();
        out.push(T[(b0 >> 2) as usize] as char);
        out.push(T[(((b0 & 0x03) << 4) | (b1.unwrap_or(0) >> 4)) as usize] as char);
        if b1.is_none() {
            out.push('=');
            out.push('=');
        } else {
            out.push(
                T[(((b1.unwrap_or(0) & 0x0f) << 2) | (b2.unwrap_or(0) >> 6)) as usize] as char,
            );
            if b2.is_none() {
                out.push('=');
            } else {
                out.push(T[(b2.unwrap_or(0) & 0x3f) as usize] as char);
            }
        }
        i += 3;
    }
    out
}
