//! CMS SignedData (`plugins/preauth/pkinit/pkinit_crypto_openssl.c`
//! `cms_signeddata_create` / `cms_signeddata_verify`): wrap, verify,
//! and the RFC 5652 certificate walk.

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

/// CMS SignedData with an explicit certificate and ECDSA signature.
///
/// Encoded by hand so the Certificate SET uses IMPLICIT `[0]` (RFC 5652).
/// SignerInfo uses **issuerAndSerialNumber** (CMS version 1), matching MIT
/// OpenSSL `PKCS7_SIGNER_INFO`. `signed_attrs` if present is the
/// `[0] IMPLICIT SET` encoding; the signature is over the corresponding
/// `SET` (tag 0x31).
#[must_use]
pub fn cms_wrap_signed(
    e_content: &[u8],
    cert_der: &[u8],
    signature: &[u8],
    issuer: &[u8],
    serial: &[u8],
    econtent_oid: &[u8],
    signed_attrs: Option<&[u8]>,
) -> Vec<u8> {
    let sha256 = oid_der(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
    let ecdsa = oid_der(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);
    let signed_data = oid_der(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]);
    let ectype = oid_der(econtent_oid);
    let sha256_alg = tlv(0x30, &[sha256.clone(), tlv(0x05, &[])].concat());
    let ecdsa_alg = tlv(0x30, &ecdsa);
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
    signer_body.push(ecdsa_alg);
    signer_body.push(tlv(0x04, signature));
    let signer = tlv(0x30, &signer_body.concat());
    let signers = tlv(0x31, &signer);
    let sd = tlv(
        0x30,
        &[tlv(0x02, &[0x03]), digest_algs, encap, certs, signers].concat(),
    );
    tlv(0x30, &[signed_data, tlv(0xa0, &sd)].concat())
}

/// CMS SignedData of `e_content` using an existing leaf cert and P-256 key.
///
/// # Errors
///
/// `"cms issuer"` when the issuer and serial number cannot be read from `cert_der`;
/// `"cms ecdsa"` when `secret` is not a valid P-256 private scalar.
pub fn cms_sign_leaf(
    e_content: &[u8],
    cert_der: &[u8],
    secret: &[u8; 32],
    econtent_oid: &[u8],
) -> Result<Vec<u8>, &'static str> {
    cms_sign_leaf_oids(e_content, cert_der, secret, econtent_oid, econtent_oid)
}

/// CMS SignedData with independent encap and signed `content-type` OIDs.
///
/// # Errors
///
/// `"cms issuer"` when the issuer and serial number cannot be read from `cert_der`;
/// `"cms ecdsa"` when `secret` is not a valid P-256 private scalar.
pub fn cms_sign_leaf_oids(
    e_content: &[u8],
    cert_der: &[u8],
    secret: &[u8; 32],
    encap_oid: &[u8],
    signed_oid: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let (issuer, serial) = cert_issuer_serial(cert_der).ok_or("cms issuer")?;
    let sattrs = signed_attrs_set(signed_oid, e_content);
    let signature = p256_sign(secret, &sattrs).ok_or("cms ecdsa")?;
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
/// are separate: [`require_kdc_pkinit_cert`] / [`require_client_pkinit_san`].
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

/// The KDC's [`cms_verify_full`]: the signer's chain reaches one of `anchors` through
/// `intermediates` and the SignedData's other certificates.
/// MIT `cms_signeddata_verify` (`pkinit_crypto_openssl.c:2087-2105`): the untrusted certificates are `pkinit_pool`'s, then the message's.
/// MIT `cms_signeddata_verify` (`pkinit_crypto_openssl.c:2151-2187`): the chain is verified before the signature.
///
/// # Errors
///
/// MIT's text for a chain that does not verify, else [`cms_verify_full`]'s strings.
pub fn cms_verify_anchored(
    der: &[u8],
    anchors: &[Vec<u8>],
    intermediates: &[Vec<u8>],
) -> Result<CmsVerified, String> {
    let p = cms_parts(der).map_err(str::to_owned)?;
    let pool: Vec<&[u8]> = intermediates
        .iter()
        .chain(&p.others)
        .map(Vec::as_slice)
        .collect();
    verify_chain(&p.cert, anchors, &pool)
        .map_err(|e| format!("Failed to verify received certificate {e}"))?;
    signer_verified(p).map_err(str::to_owned)
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

/// RFC 4556 §3.2.4: signer is a KDC cert for `realm` (KPKdc + SAN krbtgt/REALM@REALM).
///
/// # Errors
///
/// `"pkinit kdc eku"` when `cert` lacks the id-pkinit-KPKdc extended key usage;
/// `"pkinit kdc san"` when it has no PKINIT SAN or the SAN is not `krbtgt/<realm>@<realm>`.
pub fn require_kdc_pkinit_cert(cert: &[u8], realm: &str) -> Result<(), &'static str> {
    if !cert_has_eku(cert, OID_KP_KDC) {
        return Err("pkinit kdc eku");
    }
    let (san_realm, parts) = cert_pkinit_san(cert).ok_or("pkinit kdc san")?;
    if san_realm != realm || parts.len() != 2 || parts[0] != "krbtgt" || parts[1] != realm {
        return Err("pkinit kdc san");
    }
    Ok(())
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
    let fail = |depth, reason| ChainError { depth, reason };
    let subject = |c: &[u8]| cert_name_der(c, false);
    let mut chain = vec![leaf.to_vec()];
    loop {
        let depth = chain.len() - 1;
        let current = &chain[depth];
        let issuer = cert_name_der(current, true);
        let signs = |c: &&[u8]| {
            spki_uncompressed(c)
                .zip(cert_tbs_sig(current))
                .is_some_and(|(key, (tbs, sig))| p256_verify(&key, &tbs, &sig))
        };
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
            return Err(fail(
                depth,
                match (self_signed, depth) {
                    (true, 0) => "self-signed certificate",
                    (true, _) => "self-signed certificate in certificate chain",
                    _ => "unable to get local issuer certificate",
                },
            ));
        };
        if chain.len() > MAX_CHAIN {
            return Err(fail(depth, "certificate chain too long"));
        }
        chain.push(next.to_vec());
    }
    let top = chain.len() - 1;
    let mut path_len = 0u64;
    for (depth, cert) in chain.iter().enumerate() {
        if cert_unhandled_critical(cert) {
            return Err(fail(depth, "unhandled critical extension"));
        }
        if depth == 0 {
            continue;
        }
        if !(cert_basic_constraints_ca(cert) || (depth == top && cert_v1(cert))) {
            return Err(fail(depth, "invalid CA certificate"));
        }
        if depth > 1 && cert_path_len(cert).is_some_and(|max| path_len > max) {
            return Err(fail(depth, "path length constraint exceeded"));
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
                return Err(fail(
                    depth + 1,
                    "key usage does not include certificate signing",
                ));
            }
            let signed = spki_uncompressed(issuer)
                .zip(cert_tbs_sig(cert))
                .is_some_and(|(key, (tbs, sig))| p256_verify(&key, &tbs, &sig));
            if !signed {
                return Err(fail(depth, "certificate signature failure"));
            }
        }
        let (not_before, not_after) = cert_time_window(cert)
            .ok_or_else(|| fail(depth, "format error in certificate's notBefore field"))?;
        if now < not_before {
            return Err(fail(depth, "certificate is not yet valid"));
        }
        if now > not_after {
            return Err(fail(depth, "certificate has expired"));
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

/// CMS SignedData of `e_content` signed with `leaf`'s P-256 key `secret`, carrying `certs` in
/// order.
/// MIT `cms_signeddata_create` (`pkinit_crypto_openssl.c:1784-1811`): the chain without its trust anchor rides in the message, and the signer is named by its issuer and serial number.
///
/// # Errors
///
/// `"cms issuer"` when `leaf`'s issuer and serial number do not read; `"cms ecdsa"` when
/// `secret` is not a valid P-256 private scalar.
pub fn cms_sign_chain(
    e_content: &[u8],
    leaf: &[u8],
    certs: &[Vec<u8>],
    secret: &[u8; 32],
    econtent_oid: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let (issuer, serial) = cert_issuer_serial(leaf).ok_or("cms issuer")?;
    let sattrs = signed_attrs_set(econtent_oid, e_content);
    let signature = p256_sign(secret, &sattrs).ok_or("cms ecdsa")?;
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
const OID_MS_SC_LOGON: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x02];

/// Whether a client certificate may authenticate with PKINIT: its extended key usage names
/// id-pkinit-KPClientAuth (or, when `accept_secondary`, Microsoft's smart-card logon), and its
/// key usage is present and allows digital signatures.
/// MIT `crypto_check_cert_eku` (`pkinit_crypto_openssl.c:2499-2571`): the EKU, then the digitalSignature key usage, which must be there.
#[must_use]
pub fn client_eku_ok(cert: &[u8], accept_secondary: bool) -> bool {
    let eku = cert_has_eku(cert, OID_KP_CLIENT_AUTH)
        || (accept_secondary && cert_has_eku(cert, OID_MS_SC_LOGON));
    if !eku {
        return false;
    }
    let Some(exts) = walk_tbs(cert).and_then(|w| w.extensions) else {
        return false;
    };
    let mut digital_signature = false;
    each_ext(exts, |oid, val| {
        if oid != OID_KU {
            return false;
        }
        digital_signature = bitstring_has(val, 0);
        true
    });
    digital_signature
}

struct TbsWalk<'a> {
    issuer: &'a [u8],
    validity: &'a [u8],
    subject: &'a [u8],
    extensions: Option<&'a [u8]>,
}

/// Locate the issuer, validity, subject and extensions of a DER certificate. MIT has no walker of
/// its own: its PKINIT reads these fields through OpenSSL.
/// A certificate that is not a sequence yields no issuer or validity, and an optional version is
/// skipped rather than read as the serial.
fn walk_tbs(cert: &[u8]) -> Option<TbsWalk<'_>> {
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

fn each_ext(extensions: &[u8], mut visit: impl FnMut(&[u8], &[u8]) -> bool) {
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

fn bitstring_has(der: &[u8], bit: usize) -> bool {
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
    others: Vec<Vec<u8>>,
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
    // IMPLICIT SET OF Certificate: the signer's first, then any that complete its chain
    let mut others = Vec::new();
    let mut certs = cert_set;
    while certs.first() == Some(&0x30) {
        let (tt, body, rest) = take_tlv(certs).ok_or("cert")?;
        others.push(tlv(tt, body));
        certs = rest;
    }
    let cert = if others.is_empty() {
        cert_set.to_vec()
    } else {
        others.remove(0)
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
        others,
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
