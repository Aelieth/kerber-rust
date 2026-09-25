//! RFC 4556 PKINIT PA-DATA types (AuthPack / PA-PK-AS-REQ / PA-PK-AS-REP).
//!
//! CMS SignedData lives in `cms` (`pkinit_crypto_openssl.c`
//! `cms_signeddata_create` / `cms_signeddata_verify`); the test CA
//! lives in `ca`.

use crate::{Checksum, KerberosTime, Microseconds, OctetString};
use rasn::prelude::*;

mod ca;
mod cms;

pub use ca::{PkinitCa, cms_wrap};
pub use cms::{
    CmsAlgorithmIdentifier, CmsContentInfo, CmsEncapContentInfo, CmsSignedData, CmsSignerInfo,
    CmsVerified, cms_extract_unsigned, cms_sign_leaf, cms_sign_leaf_oids, cms_unwrap, cms_verify,
    cms_verify_full, cms_wrap_signed, cms_wrap_unsigned, parse_identity_pem, parse_pem,
    require_client_pkinit_cert, require_kdc_pkinit_cert,
};

/// PA-PK-AS-REQ ::= SEQUENCE { signedAuthPack, trustedCertifiers, kdcPkId }
///
/// RFC 4556 uses EXPLICIT TAGS with `signedAuthPack` / `kdcPkId` **IMPLICIT**
/// OCTET STRING (wire tag `0x80` / `0x82`).
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PaPkAsReq {
    /// CMS SignedData wrapping [`AuthPack`] (DER).
    #[rasn(tag(0))]
    pub signed_auth_pack: OctetString,
    /// Optional trusted certifiers (opaque DER).
    #[rasn(tag(explicit(1)))]
    pub trusted_certifiers: Option<SequenceOf<OctetString>>,
    /// Optional KDC public-key identifier.
    #[rasn(tag(2))]
    pub kdc_pk_id: Option<OctetString>,
}

/// PKAuthenticator ::= SEQUENCE { cusec, ctime, nonce, paChecksum, … }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PkAuthenticator {
    /// Client microseconds.
    #[rasn(tag(explicit(0)))]
    pub cusec: Microseconds,
    /// Client time.
    #[rasn(tag(explicit(1)))]
    pub ctime: KerberosTime,
    /// Nonce.
    #[rasn(tag(explicit(2)))]
    pub nonce: u32,
    /// SHA-1 of the KDC-REQ-BODY (RFC 4556 `OCTET STRING`, not a Checksum).
    #[rasn(tag(explicit(3)))]
    pub pa_checksum: Option<OctetString>,
    /// RFC 8070 freshness token (`PKAuthenticator` `[4]`).
    #[rasn(tag(explicit(4)))]
    pub freshness_token: Option<OctetString>,
}

/// AuthPack ::= SEQUENCE { pkAuthenticator, clientPublicValue, … }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct AuthPack {
    /// PKAuthenticator.
    #[rasn(tag(explicit(0)))]
    pub pk_authenticator: PkAuthenticator,
    /// SubjectPublicKeyInfo DER (client DH/ECDH public value).
    #[rasn(tag(explicit(1)))]
    pub client_public_value: Option<OctetString>,
    /// Optional supported CMS types.
    #[rasn(tag(explicit(2)))]
    pub supported_cms_types: Option<SequenceOf<OctetString>>,
}

/// DHRepInfo ::= SEQUENCE { dhSignedData, serverDHNonce }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct DhRepInfo {
    /// CMS SignedData wrapping ReplyKeyPack / server DH public.
    #[rasn(tag(0))]
    pub dh_signed_data: OctetString,
    /// Optional server DH nonce (`DHNonce` = OCTET STRING, EXPLICIT `[1]`).
    #[rasn(tag(explicit(1)))]
    pub server_dh_nonce: Option<OctetString>,
}

/// `PA-PK-AS-REP ::= CHOICE { dhInfo [0] DHRepInfo, encKeyPack [1] IMPLICIT OCTET STRING }`
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(choice)]
pub enum PaPkAsRep {
    /// Diffie-Hellman (or ECDH) reply.
    #[rasn(tag(explicit(0)))]
    DhInfo(DhRepInfo),
    /// CMS EnvelopedData key pack.
    #[rasn(tag(1))]
    EncKeyPack(OctetString),
}

/// ReplyKeyPack ::= SEQUENCE { replyKey, asChecksum }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct ReplyKeyPack {
    /// AS reply key.
    #[rasn(tag(explicit(0)))]
    pub reply_key: crate::EncryptionKey,
    /// Checksum of the corresponding AS-REQ.
    #[rasn(tag(explicit(1)))]
    pub as_checksum: Checksum,
}

/// KdcDHKeyInfo ::= SEQUENCE { subjectPublicKey, nonce, dhKeyExpiration }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct KdcDHKeyInfo {
    /// Server ECDH public key (BIT STRING of the uncompressed point).
    #[rasn(tag(explicit(0)))]
    pub subject_public_key: OctetString,
    /// Nonce.
    #[rasn(tag(explicit(1)))]
    pub nonce: u32,
    /// Optional DH key expiration.
    #[rasn(tag(explicit(2)))]
    pub dh_key_expiration: Option<KerberosTime>,
}

/// id-pkinit-authData 1.3.6.1.5.2.3.1 (OID body).
pub const ECONTENT_AUTHDATA: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x01];

/// id-pkinit-DHKeyData 1.3.6.1.5.2.3.2 (OID body).
pub const ECONTENT_DHKEY: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x02];

/// id-pkinit-san 1.3.6.1.5.2.2 (OID body).
pub const OID_PKINIT_SAN: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x02, 0x02];

/// id-pkinit-KPClientAuth 1.3.6.1.5.2.3.4 (OID body).
pub const OID_KP_CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x04];

/// id-pkinit-KPKdc 1.3.6.1.5.2.3.5 (OID body).
pub const OID_KP_KDC: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x05];

const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];

const OID_EKU: &[u8] = &[0x55, 0x1d, 0x25];

const OID_BC: &[u8] = &[0x55, 0x1d, 0x13];

const OID_KU: &[u8] = &[0x55, 0x1d, 0x0f];

/// SubjectPublicKeyInfo for an uncompressed P-256 point (RFC 5480).
#[must_use]
pub fn encode_ec_spki(uncompressed: &[u8]) -> Vec<u8> {
    let spki_alg = tlv(
        0x30,
        &[
            oid_der(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
            oid_der(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
        ]
        .concat(),
    );
    let mut bit = vec![0u8];
    bit.extend_from_slice(uncompressed);
    tlv(0x30, &[spki_alg, tlv(0x03, &bit)].concat())
}

/// Decode [`encode_ec_spki`] or accept a raw uncompressed SEC1 point.
#[must_use]
pub fn decode_ec_spki(der: &[u8]) -> Option<Vec<u8>> {
    if der.first() == Some(&0x04) && der.len() == 65 {
        return Some(der.to_vec());
    }
    let (t, body, _) = take_tlv(der)?;
    if t != 0x30 {
        return None;
    }
    let (_, _, rest) = take_tlv(body)?;
    let (t, bit, _) = take_tlv(rest)?;
    if t != 0x03 {
        return None;
    }
    let pt = if bit.first() == Some(&0) {
        bit.get(1..)?.to_vec()
    } else {
        bit.to_vec()
    };
    if pt.first() == Some(&0x04) && pt.len() == 65 {
        Some(pt)
    } else {
        None
    }
}

/// dhpublicnumber 1.2.840.10046.2.1 (RFC 3279 DomainParameters).
const OID_DHPUBLICNUMBER: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3e, 0x02, 0x01];

/// PKCS#3 dhKeyAgreement 1.2.840.113549.1.3.1.
const OID_DHKEYAGREEMENT: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x03, 0x01];

fn is_dh_oid(oid_body: &[u8]) -> bool {
    oid_body == OID_DHPUBLICNUMBER || oid_body == OID_DHKEYAGREEMENT
}

fn strip_leading_zeros(n: &[u8]) -> Vec<u8> {
    let skip = n.iter().take_while(|b| **b == 0).count();
    if skip == n.len() {
        vec![0]
    } else {
        n[skip..].to_vec()
    }
}

fn der_unsigned(be: &[u8]) -> Vec<u8> {
    let mut n = strip_leading_zeros(be);
    if n.first().copied().unwrap_or(0) & 0x80 != 0 {
        n.insert(0, 0);
    }
    tlv(0x02, &n)
}

/// RFC 3279 DH `SubjectPublicKeyInfo` (`DomainParameters` + `DHPublicKey`).
#[must_use]
pub fn encode_dh_spki(p: &[u8], y: &[u8]) -> Vec<u8> {
    let params = tlv(0x30, &[der_unsigned(p), der_unsigned(&[2])].concat());
    let alg = tlv(0x30, &[oid_der(OID_DHPUBLICNUMBER), params].concat());
    let mut bit = vec![0u8];
    bit.extend(der_unsigned(y));
    tlv(0x30, &[alg, tlv(0x03, &bit)].concat())
}

/// Parse a MODP DH SPKI: `(p, y)` as unsigned big-endian integers.
///
/// Accepts RFC 3279 `dhpublicnumber` and PKCS#3 `dhKeyAgreement`. `y` may
/// be a DER `INTEGER` inside the BIT STRING (MIT / OpenSSL) or raw bytes.
#[must_use]
pub fn parse_dh_spki(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (t, body, _) = take_tlv(der)?;
    if t != 0x30 {
        return None;
    }
    let (t, alg, rest) = take_tlv(body)?;
    if t != 0x30 {
        return None;
    }
    let (t, oid, params) = take_tlv(alg)?;
    if t != 0x06 || !is_dh_oid(oid) {
        return None;
    }
    let (t, pbody, _) = take_tlv(params)?;
    if t != 0x30 {
        return None;
    }
    let (t, p_int, _) = take_tlv(pbody)?;
    if t != 0x02 {
        return None;
    }
    let p = strip_leading_zeros(p_int);
    let (t, bit, _) = take_tlv(rest)?;
    if t != 0x03 {
        return None;
    }
    let payload = if bit.first() == Some(&0) {
        bit.get(1..)?
    } else {
        bit
    };
    let y = if payload.first() == Some(&0x02) {
        let (_, yb, _) = take_tlv(payload)?;
        strip_leading_zeros(yb)
    } else {
        strip_leading_zeros(payload)
    };
    Some((p, y))
}

/// Unsigned integer from a DER `INTEGER` (or already-unsigned bytes).
#[must_use]
pub fn der_integer_unsigned(der: &[u8]) -> Option<Vec<u8>> {
    if der.first() == Some(&0x02) {
        let (_, body, _) = take_tlv(der)?;
        return Some(strip_leading_zeros(body));
    }
    Some(strip_leading_zeros(der))
}

/// RFC 4556 `KdcDHKeyInfo` DER wrapping a BIT STRING payload.
///
/// For ECDH the payload is an uncompressed P-256 point; for MODP DH it is
/// the DER `INTEGER` of `y` (RFC 4556 `DHPublicKey`).
#[must_use]
pub fn encode_kdc_dh_key_info(uncompressed: &[u8], nonce: u32) -> Vec<u8> {
    let mut bit = vec![0u8];
    bit.extend_from_slice(uncompressed);
    let spk = tlv(0xa0, &tlv(0x03, &bit));
    let mut n = nonce.to_be_bytes().to_vec();
    while n.len() > 1 && n.first() == Some(&0) {
        n.remove(0);
    }
    if n.first().copied().unwrap_or(0) & 0x80 != 0 {
        n.insert(0, 0);
    }
    let ni = tlv(0xa1, &tlv(0x02, &n));
    tlv(0x30, &[spk, ni].concat())
}

/// Parse RFC 4556 `AuthPack` for `(nonce, clientPublicValue)`.
///
/// Accepts MIT's EXPLICIT `[1]` `SubjectPublicKeyInfo` SEQUENCE and this
/// crate's rasn `OCTET STRING` wrapping of the same SPKI. Extra fields
/// (`supportedKDFs`, …) are ignored so MIT 1.22.2 AuthPack decodes.
#[must_use]
pub fn parse_authpack(der: &[u8]) -> Option<(u32, Vec<u8>)> {
    let (t, body, _) = take_tlv(der)?;
    if t != 0x30 {
        return None;
    }
    let mut nonce = 0u32;
    let mut spki: Option<Vec<u8>> = None;
    let mut cur = body;
    while !cur.is_empty() {
        let (tag, inner, rest) = take_tlv(cur)?;
        if tag == 0xa0 {
            let seq = unwrap_explicit_seq(inner);
            if let Some(n) = pkauth_nonce(seq) {
                nonce = n;
            }
        } else if tag == 0xa1 {
            spki = Some(unwrap_spki_field(inner));
        }
        cur = rest;
    }
    Some((nonce, spki?))
}

/// SHA-1 of encoded `KDC-REQ-BODY` (RFC 4556 `paChecksum`).
#[must_use]
pub fn kdc_req_body_checksum(body: &[u8]) -> Vec<u8> {
    sha1_bytes(body)
}

/// RFC 8070 `PKAuthenticator.freshnessToken` `[4]` (opaque token bytes).
#[must_use]
pub fn parse_authpack_freshness_token(der: &[u8]) -> Option<Vec<u8>> {
    let (t, body, _) = take_tlv(der)?;
    if t != 0x30 {
        return None;
    }
    let mut cur = body;
    while !cur.is_empty() {
        let (tag, inner, rest) = take_tlv(cur)?;
        if tag == 0xa0 {
            return pkauth_freshness_token(unwrap_explicit_seq(inner));
        }
        cur = rest;
    }
    None
}

fn pkauth_freshness_token(seq_body: &[u8]) -> Option<Vec<u8>> {
    let mut cur = seq_body;
    while !cur.is_empty() {
        let (tag, inner, rest) = take_tlv(cur)?;
        if tag == 0xa4 {
            if inner.first() == Some(&0x04)
                && let Some((_, body, _)) = take_tlv(inner)
            {
                return Some(body.to_vec());
            }
            return Some(inner.to_vec());
        }
        cur = rest;
    }
    None
}

/// RFC 4556 §3.2.2: AuthPack `pkAuthenticator` `ctime` / `cusec`.
#[must_use]
pub fn parse_authpack_freshness(der: &[u8]) -> Option<(u32, u32)> {
    let (t, body, _) = take_tlv(der)?;
    if t != 0x30 {
        return None;
    }
    let mut cur = body;
    while !cur.is_empty() {
        let (tag, inner, rest) = take_tlv(cur)?;
        if tag == 0xa0 {
            return pkauth_times(unwrap_explicit_seq(inner));
        }
        cur = rest;
    }
    None
}

/// RFC 4556 §3.2.2: AuthPack `paChecksum` equals SHA-1 of `KDC-REQ-BODY`.
///
/// # Errors
///
/// Missing or mismatched checksum.
pub fn authpack_pa_checksum_ok(authpack: &[u8], body: &[u8]) -> Result<(), &'static str> {
    let got = parse_authpack_pa_checksum(authpack).ok_or("pkinit paChecksum")?;
    let expect = sha1_bytes(body);
    if got.len() != expect.len()
        || !bool::from(subtle::ConstantTimeEq::ct_eq(
            got.as_slice(),
            expect.as_slice(),
        ))
    {
        return Err("pkinit paChecksum");
    }
    Ok(())
}

fn parse_authpack_pa_checksum(der: &[u8]) -> Option<Vec<u8>> {
    let (t, body, _) = take_tlv(der)?;
    if t != 0x30 {
        return None;
    }
    let mut cur = body;
    while !cur.is_empty() {
        let (tag, inner, rest) = take_tlv(cur)?;
        if tag == 0xa0 {
            return pkauth_checksum(unwrap_explicit_seq(inner));
        }
        cur = rest;
    }
    None
}

/// RFC 8636 `id-pkinit-kdf-ah-sha256` (1.3.6.1.5.2.3.6.2).
pub const KDF_AH_SHA256_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x06, 0x02];

/// RFC 4556 `KRB5PrincipalName` (realm + `PrincipalName`).
#[must_use]
pub fn encode_krb5_principal_name(realm: &str, ntype: i32, parts: &[&str]) -> Vec<u8> {
    let realm_f = tlv(0xa0, &tlv(0x1b, realm.as_bytes()));
    let nt = tlv(0xa0, &der_i32(ntype));
    let mut names = Vec::new();
    for p in parts {
        names.extend(tlv(0x1b, p.as_bytes()));
    }
    let ns = tlv(0xa1, &tlv(0x30, &names));
    let pname = tlv(0xa1, &tlv(0x30, &[nt, ns].concat()));
    tlv(0x30, &[realm_f, pname].concat())
}

fn der_i32(v: i32) -> Vec<u8> {
    der_unsigned(&v.to_be_bytes())
}

/// RFC 8636 `KDFAlgorithmId`.
#[must_use]
pub fn encode_kdf_algorithm_id(oid: &[u8]) -> Vec<u8> {
    tlv(0x30, &tlv(0xa0, &oid_der(oid)))
}

/// RFC 8636 `PkinitSuppPubInfo`.
#[must_use]
pub fn encode_pkinit_supp_pub_info(enctype: i32, as_req: &[u8], pk_as_rep: &[u8]) -> Vec<u8> {
    let e = tlv(0xa0, &der_i32(enctype));
    let a = tlv(0xa1, &tlv(0x04, as_req));
    let p = tlv(0xa2, &tlv(0x04, pk_as_rep));
    tlv(0x30, &[e, a, p].concat())
}

/// RFC 8636 `OtherInfo`. Tagged OCTET STRING fields use the SP 800-56A
/// ASN.1 `FixedInfo` layout MIT encodes (`[n] IMPLICIT OCTET STRING`).
#[must_use]
pub fn encode_rfc8636_other_info(
    kdf_oid: &[u8],
    party_u: &[u8],
    party_v: &[u8],
    supp_pub: &[u8],
) -> Vec<u8> {
    let alg = tlv(0x30, &oid_der(kdf_oid));
    let u = tlv(0xa0, &tlv(0x04, party_u));
    let v = tlv(0xa1, &tlv(0x04, party_v));
    let s = tlv(0xa2, &tlv(0x04, supp_pub));
    tlv(0x30, &[alg, u, v, s].concat())
}

/// Append `supportedKDFs` (SHA-256) as AuthPack `[4]`.
#[must_use]
pub fn authpack_with_sha256_kdf(authpack: &[u8]) -> Option<Vec<u8>> {
    let (t, body, _) = take_tlv(authpack)?;
    if t != 0x30 {
        return None;
    }
    let kdfs = tlv(
        0xa4,
        &tlv(0x30, &encode_kdf_algorithm_id(KDF_AH_SHA256_OID)),
    );
    Some(tlv(0x30, &[body, kdfs.as_slice()].concat()))
}

/// AuthPack whose `clientPublicValue` is a raw SPKI SEQUENCE (MIT 1.22.2).
#[must_use]
pub fn encode_client_authpack(pk_auth: &PkAuthenticator, spki: &[u8]) -> Option<Vec<u8>> {
    let pk = rasn::der::encode(pk_auth).ok()?;
    let body = [tlv(0xa0, &pk), tlv(0xa1, spki)].concat();
    authpack_with_sha256_kdf(&tlv(0x30, &body))
}

/// Insert RFC 8636 `kdf [2]` into a rasn-encoded `PA-PK-AS-REP` dhInfo.
#[must_use]
pub fn pa_pk_as_rep_with_kdf(pa_pk_as_rep: &[u8], kdf_oid: &[u8]) -> Option<Vec<u8>> {
    let (t, inner, _) = take_tlv(pa_pk_as_rep)?;
    if t != 0xa0 {
        return None;
    }
    let (st, body, _) = take_tlv(inner)?;
    if st != 0x30 {
        return None;
    }
    let kdf = tlv(0xa2, &encode_kdf_algorithm_id(kdf_oid));
    Some(tlv(0xa0, &tlv(0x30, &[body, kdf.as_slice()].concat())))
}

/// `dhSignedData` octets from a `PA-PK-AS-REP` dhInfo (with or without `kdf`).
#[must_use]
pub fn pa_pk_as_rep_dh_signed_data(pa_pk_as_rep: &[u8]) -> Option<Vec<u8>> {
    let (t, inner, _) = take_tlv(pa_pk_as_rep)?;
    if t != 0xa0 {
        return None;
    }
    let (st, body, _) = take_tlv(inner)?;
    if st != 0x30 {
        return None;
    }
    let (tag, val, _) = take_tlv(body)?;
    // [0] IMPLICIT OCTET STRING is 0x80.
    if tag == 0x80 || tag == 0xa0 {
        Some(val.to_vec())
    } else {
        None
    }
}

/// OID body of `DHRepInfo.kdf` when present.
#[must_use]
pub fn pa_pk_as_rep_kdf_oid(pa_pk_as_rep: &[u8]) -> Option<Vec<u8>> {
    let (t, inner, _) = take_tlv(pa_pk_as_rep)?;
    if t != 0xa0 {
        return None;
    }
    let (st, mut body, _) = take_tlv(inner)?;
    if st != 0x30 {
        return None;
    }
    while !body.is_empty() {
        let (tag, val, rest) = take_tlv(body)?;
        if tag == 0xa2 {
            return kdf_oid_from_algorithm_id(val);
        }
        body = rest;
    }
    None
}

fn kdf_oid_from_algorithm_id(mut b: &[u8]) -> Option<Vec<u8>> {
    if b.first() == Some(&0x30) {
        let (_, inner, _) = take_tlv(b)?;
        b = inner;
    }
    while !b.is_empty() {
        let (tag, val, rest) = take_tlv(b)?;
        if tag == 0xa0 || tag == 0x06 {
            if tag == 0x06 {
                return Some(val.to_vec());
            }
            let (t2, v2, _) = take_tlv(val)?;
            if t2 == 0x06 {
                return Some(v2.to_vec());
            }
        }
        b = rest;
    }
    None
}

/// Whether AuthPack `supportedKDFs` includes SHA-256 (RFC 8636).
#[must_use]
pub fn authpack_wants_sha256_kdf(der: &[u8]) -> bool {
    let Some((t, body, _)) = take_tlv(der) else {
        return false;
    };
    if t != 0x30 {
        return false;
    }
    let mut cur = body;
    while !cur.is_empty() {
        let Some((tag, inner, rest)) = take_tlv(cur) else {
            break;
        };
        if tag == 0xa4 && oid_in(inner, KDF_AH_SHA256_OID) {
            return true;
        }
        cur = rest;
    }
    false
}

fn oid_in(mut b: &[u8], oid: &[u8]) -> bool {
    while !b.is_empty() {
        let Some((tag, inner, rest)) = take_tlv(b) else {
            return false;
        };
        if tag == 0x06 && inner == oid {
            return true;
        }
        if oid_in(inner, oid) {
            return true;
        }
        b = rest;
    }
    false
}

fn unwrap_explicit_seq(inner: &[u8]) -> &[u8] {
    if inner.first() == Some(&0x30) {
        take_tlv(inner).map_or(inner, |(_, b, _)| b)
    } else {
        inner
    }
}

fn unwrap_spki_field(inner: &[u8]) -> Vec<u8> {
    if inner.first() == Some(&0x04)
        && let Some((_, body, _)) = take_tlv(inner)
    {
        return body.to_vec();
    }
    inner.to_vec()
}

fn pkauth_times(seq_body: &[u8]) -> Option<(u32, u32)> {
    let mut cusec = None;
    let mut ctime = None;
    let mut cur = seq_body;
    while !cur.is_empty() {
        let (tag, inner, rest) = take_tlv(cur)?;
        if tag == 0xa0 {
            let intb = if inner.first() == Some(&0x02) {
                take_tlv(inner)?.1
            } else {
                inner
            };
            cusec = Some(der_uint(intb));
        } else if tag == 0xa1 {
            let gt = if inner.first() == Some(&0x18) {
                take_tlv(inner)?.1
            } else {
                inner
            };
            let s = std::str::from_utf8(gt).ok()?;
            ctime = Some(crate::kerberos_time_from_utc_z(s).ok()?.unix_seconds());
        }
        cur = rest;
        if cusec.is_some() && ctime.is_some() {
            break;
        }
    }
    Some((ctime?, cusec?))
}

fn pkauth_nonce(seq_body: &[u8]) -> Option<u32> {
    let mut cur = seq_body;
    while !cur.is_empty() {
        let (tag, inner, rest) = take_tlv(cur)?;
        if tag == 0xa2 {
            let intb = if inner.first() == Some(&0x02) {
                take_tlv(inner)?.1
            } else {
                inner
            };
            return Some(der_uint(intb));
        }
        cur = rest;
    }
    None
}

fn pkauth_checksum(seq_body: &[u8]) -> Option<Vec<u8>> {
    let mut cur = seq_body;
    while !cur.is_empty() {
        let (tag, inner, rest) = take_tlv(cur)?;
        if tag == 0xa3 {
            if inner.first() == Some(&0x04)
                && let Some((_, body, _)) = take_tlv(inner)
            {
                return Some(body.to_vec());
            }
            return Some(inner.to_vec());
        }
        cur = rest;
    }
    None
}

fn der_uint(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0u32, |acc, &b| {
        acc.saturating_mul(256).saturating_add(u32::from(b))
    })
}

/// Extract the uncompressed point from [`encode_kdc_dh_key_info`].
#[must_use]
pub fn decode_kdc_dh_point(der: &[u8]) -> Option<Vec<u8>> {
    let (t, body, _) = take_tlv(der)?;
    if t != 0x30 {
        return None;
    }
    let (t, expl, _) = take_tlv(body)?;
    if t != 0xa0 {
        return None;
    }
    let (t, bit, _) = take_tlv(expl)?;
    if t != 0x03 {
        return None;
    }
    if bit.first() == Some(&0) {
        Some(bit.get(1..)?.to_vec())
    } else {
        Some(bit.to_vec())
    }
}

/// First field of PA-PK-AS-REQ: CMS `signedAuthPack` (IMPLICIT or EXPLICIT).
#[must_use]
pub fn parse_pa_pk_as_req_cms(der: &[u8]) -> Option<Vec<u8>> {
    let (t, body, _) = take_tlv(der)?;
    if t != 0x30 {
        return None;
    }
    let (tag, inner, _) = take_tlv(body)?;
    match tag {
        0xa0 if inner.first() == Some(&0x04) => take_tlv(inner).map(|(_, b, _)| b.to_vec()),
        0x80 | 0xa0 => Some(inner.to_vec()),
        _ => None,
    }
}

/// RFC 4556 `TD-DH-PARAMETERS` advertising ECDH P-256 (`id-ecPublicKey` + secp256r1).
#[must_use]
pub fn encode_td_dh_p256() -> Vec<u8> {
    let ec = oid_der(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
    let p256 = oid_der(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
    let alg = tlv(0x30, &[ec, p256].concat());
    tlv(0x30, &alg)
}

/// KRB5_ANONYMOUS_REALMSTR.
pub const ANONYMOUS_REALM: &str = "WELLKNOWN:ANONYMOUS";

/// MIT `krb5_anonymous_principal` (`bld_princ.c:179-182`): `WELLKNOWN/ANONYMOUS` (NT-WELLKNOWN).
#[must_use]
pub fn anonymous_client() -> crate::PrincipalName {
    crate::PrincipalName::new(
        crate::PrincipalName::NT_WELLKNOWN,
        ["WELLKNOWN", "ANONYMOUS"],
    )
}

/// Component-only compare, like `krb5_principal_compare_any_realm`.
#[must_use]
pub fn is_anonymous_principal(name: &crate::PrincipalName) -> bool {
    name.components_eq(&anonymous_client())
}

/// RFC 8636 `partyUInfo`: anonymous clients use `WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS`.
#[must_use]
pub fn encode_party_u(cname: &crate::PrincipalName, realm: &str) -> Vec<u8> {
    if is_anonymous_principal(cname) {
        return encode_krb5_principal_name(
            ANONYMOUS_REALM,
            crate::PrincipalName::NT_WELLKNOWN,
            &["WELLKNOWN", "ANONYMOUS"],
        );
    }
    let parts: Vec<String> = cname
        .name_string
        .iter()
        .map(|s| String::from_utf8_lossy(s.as_bytes()).into_owned())
        .collect();
    let prefs: Vec<&str> = parts.iter().map(String::as_str).collect();
    encode_krb5_principal_name(realm, cname.name_type, &prefs)
}

/// AuthPack nonce plus optional `clientPublicValue` (absent for unsigned-no-DH).
#[must_use]
pub fn parse_authpack_maybe_dh(der: &[u8]) -> Option<(u32, Option<Vec<u8>>)> {
    let (t, body, _) = take_tlv(der)?;
    if t != 0x30 {
        return None;
    }
    let mut nonce = 0u32;
    let mut spki: Option<Vec<u8>> = None;
    let mut cur = body;
    while !cur.is_empty() {
        let (tag, inner, rest) = take_tlv(cur)?;
        if tag == 0xa0 {
            let seq = unwrap_explicit_seq(inner);
            if let Some(n) = pkauth_nonce(seq) {
                nonce = n;
            }
        } else if tag == 0xa1 {
            spki = Some(unwrap_spki_field(inner));
        }
        cur = rest;
    }
    Some((nonce, spki))
}

fn sha1_bytes(data: &[u8]) -> Vec<u8> {
    use sha1::{Digest, Sha1};
    Sha1::digest(data).to_vec()
}

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if let Ok(b) = u8::try_from(body.len()) {
        if b < 128 {
            out.push(b);
        } else {
            out.push(0x81);
            out.push(b);
        }
    } else {
        out.push(0x82);
        out.extend_from_slice(&(u16::try_from(body.len()).unwrap_or(u16::MAX)).to_be_bytes());
    }
    out.extend_from_slice(body);
    out
}

fn oid_der(arcs: &[u8]) -> Vec<u8> {
    tlv(0x06, arcs)
}

fn der_take_len(b: &[u8]) -> Option<(usize, usize)> {
    let first = *b.first()?;
    if first < 128 {
        return Some((1, usize::from(first)));
    }
    if first == 0x81 && b.len() >= 2 {
        return Some((2, usize::from(b[1])));
    }
    if first == 0x82 && b.len() >= 3 {
        return Some((3, usize::from(u16::from_be_bytes([b[1], b[2]]))));
    }
    None
}

fn take_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *input.first()?;
    let (hlen, ln) = der_take_len(input.get(1..)?)?;
    let start = 1 + hlen;
    let body = input.get(start..start + ln)?;
    let rest = input.get(start + ln..)?;
    Some((tag, body, rest))
}

#[cfg(test)]
mod rfc8636_tests;

#[cfg(test)]
mod signed_attrs_tests;
