//! RFC 4556 PKINIT PA-DATA types (AuthPack / PA-PK-AS-REQ / PA-PK-AS-REP).

use rasn::prelude::*;

use crate::{Checksum, KerberosTime, Microseconds, OctetString};

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
    /// Optional checksum of the KDC-REQ-BODY.
    #[rasn(tag(explicit(3)))]
    pub pa_checksum: Option<Checksum>,
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
    /// Optional server DH nonce (`DHNonce` = OCTET STRING, EXPLICIT [1]).
    #[rasn(tag(explicit(1)))]
    pub server_dh_nonce: Option<OctetString>,
}

/// PA-PK-AS-REP ::= CHOICE { dhInfo [0] DHRepInfo, encKeyPack [1] IMPLICIT OCTET STRING }
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
/// Accepts MIT's EXPLICIT [1] `SubjectPublicKeyInfo` SEQUENCE and this
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

/// Append `supportedKDFs` (SHA-256) as AuthPack [4].
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

/// Insert RFC 8636 `kdf` [2] into a rasn-encoded `PA-PK-AS-REP` dhInfo.
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

/// Anonymous PKINIT well-known client name (`WELLKNOWN/ANONYMOUS`).
#[must_use]
pub fn anonymous_client() -> crate::PrincipalName {
    crate::PrincipalName::new(
        crate::PrincipalName::NT_PRINCIPAL,
        ["WELLKNOWN", "ANONYMOUS"],
    )
}

/// CMS AlgorithmIdentifier (digest or signature).
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct CmsAlgorithmIdentifier {
    /// Object identifier.
    pub algorithm: ObjectIdentifier,
    /// Optional parameters.
    pub parameters: Option<OctetString>,
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
    /// subjectKeyIdentifier [0] EXPLICIT (local CMS profile).
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
    /// SignedData [0] EXPLICIT.
    #[rasn(tag(explicit(0)))]
    pub content: CmsSignedData,
}

fn sha256_bytes(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).to_vec()
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

fn p256_sign(secret: &[u8; 32], message: &[u8]) -> Option<Vec<u8>> {
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

fn generate_p256() -> Option<([u8; 32], Vec<u8>)> {
    use p256::ecdsa::SigningKey;
    let mut secret = [0u8; 32];
    for _ in 0..16 {
        getrandom::getrandom(&mut secret).ok()?;
        secret[0] &= 0x7f;
        if let Ok(sk) = SigningKey::from_bytes((&secret).into()) {
            let pt = sk.verifying_key().to_encoded_point(false);
            return Some((secret, pt.as_bytes().to_vec()));
        }
    }
    None
}

fn directory_name(cn: &str) -> Vec<u8> {
    let cn_atv = tlv(
        0x30,
        &[oid_der(&[0x55, 0x04, 0x03]), tlv(0x0c, cn.as_bytes())].concat(),
    );
    tlv(0x30, &tlv(0x31, &cn_atv))
}

#[derive(Clone, Copy)]
enum CertKind {
    Ca,
    Kdc,
    Client,
}

fn p256_cert(
    serial: u8,
    issuer_cn: &str,
    subject_cn: &str,
    subject_public: &[u8],
    signer_secret: &[u8; 32],
    kind: CertKind,
) -> Option<Vec<u8>> {
    let issuer = directory_name(issuer_cn);
    let subject = directory_name(subject_cn);
    let alg_id = tlv(
        0x30,
        &oid_der(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]),
    );
    let spki_alg = tlv(
        0x30,
        &[
            oid_der(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
            oid_der(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
        ]
        .concat(),
    );
    let mut bit = vec![0u8];
    bit.extend_from_slice(subject_public);
    let spki = tlv(0x30, &[spki_alg, tlv(0x03, &bit)].concat());
    let validity = tlv(
        0x30,
        &[tlv(0x17, b"250101000000Z"), tlv(0x17, b"360101000000Z")].concat(),
    );
    let mut tbs_body = Vec::new();
    tbs_body.extend(tlv(0xa0, &tlv(0x02, &[0x02])));
    tbs_body.extend(tlv(0x02, &[serial]));
    tbs_body.extend_from_slice(&alg_id);
    tbs_body.extend_from_slice(&issuer);
    tbs_body.extend_from_slice(&validity);
    tbs_body.extend_from_slice(&subject);
    tbs_body.extend_from_slice(&spki);
    tbs_body.extend_from_slice(&cert_extensions(kind));
    let tbs = tlv(0x30, &tbs_body);
    let sig = p256_sign(signer_secret, &tbs)?;
    let mut sig_bit = vec![0u8];
    sig_bit.extend_from_slice(&sig);
    Some(tlv(0x30, &[tbs, alg_id, tlv(0x03, &sig_bit)].concat()))
}

/// Minimal X.509 v3 self-signed P-256 certificate (test CA).
fn self_signed_p256_cert(cn: &str, secret: &[u8; 32], public: &[u8]) -> Option<Vec<u8>> {
    p256_cert(1, cn, cn, public, secret, CertKind::Ca)
}

fn cert_extensions(kind: CertKind) -> Vec<u8> {
    let is_ca = matches!(kind, CertKind::Ca);
    let bc_oid = oid_der(&[0x55, 0x1d, 0x13]);
    let bc_val = if is_ca {
        tlv(0x30, &tlv(0x01, &[0xff]))
    } else {
        tlv(0x30, &[])
    };
    let bc = tlv(
        0x30,
        &[bc_oid, tlv(0x01, &[0xff]), tlv(0x04, &bc_val)].concat(),
    );
    let ku_oid = oid_der(&[0x55, 0x1d, 0x0f]);
    let ku_bits = if is_ca {
        tlv(0x03, &[0x01, 0b0000_0110])
    } else {
        tlv(0x03, &[0x07, 0b1000_0000])
    };
    let ku = tlv(
        0x30,
        &[ku_oid, tlv(0x01, &[0xff]), tlv(0x04, &ku_bits)].concat(),
    );
    let mut ext_body = [bc, ku].concat();
    match kind {
        CertKind::Kdc => {
            ext_body.extend(san_dns("kerber.test"));
            ext_body.extend(eku(&[0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x05]));
        }
        CertKind::Client => {
            ext_body.extend(eku(&[0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x04]));
        }
        CertKind::Ca => {}
    }
    tlv(0xa3, &tlv(0x30, &ext_body))
}

fn san_dns(dns: &str) -> Vec<u8> {
    let gn = tlv(0x82, dns.as_bytes());
    let gns = tlv(0x30, &gn);
    tlv(
        0x30,
        &[oid_der(&[0x55, 0x1d, 0x11]), tlv(0x04, &gns)].concat(),
    )
}

fn eku(oid_body: &[u8]) -> Vec<u8> {
    let seq = tlv(0x30, &oid_der(oid_body));
    tlv(
        0x30,
        &[oid_der(&[0x55, 0x1d, 0x25]), tlv(0x04, &seq)].concat(),
    )
}

fn spki_uncompressed(cert: &[u8]) -> Option<Vec<u8>> {
    // BIT STRING of the subject public key: 0x03 len 0x00 0x04 || X || Y
    let mut i = 0usize;
    while i + 3 < cert.len() {
        if cert[i] == 0x03 {
            let (hlen, ln) = der_take_len(&cert[i + 1..])?;
            let start = i + 1 + hlen;
            let body = cert.get(start..start + ln)?;
            if body.len() >= 66 && body[0] == 0 && body[1] == 0x04 {
                return Some(body[1..].to_vec());
            }
            i = start + ln;
            continue;
        }
        i += 1;
    }
    None
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

/// Wrap `e_content` in CMS SignedData under `ca`.
///
/// The SignerInfo signature is ECDSA-SHA256 over `e_content`. Never
/// falls back to plaintext: a CA/signing failure is an error.
///
/// # Errors
///
/// Returns `"cms wrap"` when a leaf cannot be issued or signed.
pub fn cms_wrap(e_content: &[u8], ca: &PkinitCa) -> Result<Vec<u8>, &'static str> {
    ca.sign_cms(e_content, "pkinit-test").ok_or("cms wrap")
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

fn signed_attrs_set(econtent_oid: &[u8], e_content: &[u8]) -> Vec<u8> {
    let digest = sha256_bytes(e_content);
    let ct_oid = oid_der(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03]);
    let md_oid = oid_der(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04]);
    let ct = tlv(0x30, &[ct_oid, tlv(0x31, &oid_der(econtent_oid))].concat());
    let md = tlv(0x30, &[md_oid, tlv(0x31, &tlv(0x04, &digest))].concat());
    tlv(0x31, &[ct, md].concat())
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

/// Verify CMS SignedData against `trust_anchor` (CA certificate DER).
///
/// The embedded leaf must be issued by the trust anchor; the SignerInfo
/// ECDSA-SHA256 signature is then checked with the leaf public key.
/// There is no unverified fallback.
///
/// # Errors
///
/// Missing CMS fields, untrusted certificate, or ECDSA failure.
pub fn cms_verify(der: &[u8], trust_anchor: &[u8]) -> Result<Vec<u8>, &'static str> {
    let p = cms_parts(der)?;
    if !cert_issued_by(&p.cert, trust_anchor) {
        return Err("cms trust");
    }
    let public = spki_uncompressed(&p.cert).ok_or("cms spki")?;
    if let Some(sa) = &p.signed_attrs {
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
    } else if !p256_verify(&public, &p.e_content, &p.signature) {
        return Err("cms ecdsa");
    }
    Ok(p.e_content)
}

fn signed_attrs_digest_ok(sattrs: &[u8], expect: &[u8]) -> bool {
    let body = if sattrs.first() == Some(&0xa0) || sattrs.first() == Some(&0x31) {
        take_tlv(sattrs).map_or(sattrs, |(_, b, _)| b)
    } else {
        sattrs
    };
    let mut cur = body;
    while let Some((_, attr, rest)) = take_tlv(cur) {
        if let Some((_, oid, after)) = take_tlv(attr)
            && (oid == [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04]
                || (oid.first() == Some(&0x06)
                    && oid.get(2..)
                        == Some([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04].as_slice())))
            && let Some((_, set, _)) = take_tlv(after)
            && let Some((t, oct, _)) = take_tlv(set)
        {
            let d = if t == 0x04 { oct } else { set };
            return d == expect;
        }
        cur = rest;
        if rest.is_empty() {
            break;
        }
    }
    false
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

/// True when `leaf` is signed by the public key in `ca` (including a
/// self-signed CA used as both leaf and anchor).
fn cert_issued_by(leaf: &[u8], ca: &[u8]) -> bool {
    let Some(ca_pub) = spki_uncompressed(ca) else {
        return false;
    };
    let Some((tbs, sig)) = cert_tbs_sig(leaf) else {
        return false;
    };
    p256_verify(&ca_pub, &tbs, &sig)
}

struct CmsParts {
    e_content: Vec<u8>,
    cert: Vec<u8>,
    signature: Vec<u8>,
    signed_attrs: Option<Vec<u8>>,
}

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
    let (_, _ct, after_oid) = take_tlv(encap).ok_or("eContentType")?;
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
    })
}

fn take_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *input.first()?;
    let (hlen, ln) = der_take_len(input.get(1..)?)?;
    let start = 1 + hlen;
    let body = input.get(start..start + ln)?;
    let rest = input.get(start + ln..)?;
    Some((tag, body, rest))
}

fn pem(kind: &str, der: &[u8]) -> String {
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

fn pem_ec_key(secret: &[u8; 32], public: &[u8]) -> String {
    let oid = oid_der(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
    let mut bit = vec![0u8];
    bit.extend_from_slice(public);
    let body = [
        tlv(0x02, &[0x01]),
        tlv(0x04, secret),
        tlv(0xa0, &oid),
        tlv(0xa1, &tlv(0x03, &bit)),
    ]
    .concat();
    pem("EC PRIVATE KEY", &tlv(0x30, &body))
}

/// Test CA used as a MIT `pkinit_anchors` FILE trust anchor.
#[derive(Clone, Debug)]
pub struct PkinitCa {
    /// CA private scalar.
    pub ca_secret: [u8; 32],
    /// CA certificate (DER).
    pub ca_cert: Vec<u8>,
    /// Uncompressed P-256 public key.
    pub ca_public: Vec<u8>,
}

impl PkinitCa {
    /// Generate a self-signed P-256 test CA.
    #[must_use]
    pub fn generate() -> Option<Self> {
        let (ca_secret, ca_public) = generate_p256()?;
        let ca_cert = self_signed_p256_cert("Kerber Test CA", &ca_secret, &ca_public)?;
        Some(Self {
            ca_secret,
            ca_cert,
            ca_public,
        })
    }

    /// PEM of the CA certificate (`pkinit_anchors = FILE:`).
    #[must_use]
    pub fn cert_pem(&self) -> String {
        pem("CERTIFICATE", &self.ca_cert)
    }

    /// Issue a leaf certificate signed by this CA.
    #[must_use]
    pub fn issue_leaf(
        &self,
        cn: &str,
        _leaf_secret: &[u8; 32],
        leaf_public: &[u8],
    ) -> Option<Vec<u8>> {
        p256_cert(
            2,
            "Kerber Test CA",
            cn,
            leaf_public,
            &self.ca_secret,
            CertKind::Client,
        )
    }

    /// CMS-sign `e_content` with a fresh leaf under this CA (`id-pkinit-authData`).
    #[must_use]
    pub fn sign_cms(&self, e_content: &[u8], leaf_cn: &str) -> Option<Vec<u8>> {
        self.sign_cms_typed(e_content, leaf_cn, ECONTENT_AUTHDATA)
    }

    /// CMS-sign `e_content` with `econtent_oid` and RFC 5652 signedAttrs.
    #[must_use]
    pub fn sign_cms_typed(
        &self,
        e_content: &[u8],
        leaf_cn: &str,
        econtent_oid: &[u8],
    ) -> Option<Vec<u8>> {
        let (ls, lp) = generate_p256()?;
        let kind = if econtent_oid == ECONTENT_DHKEY {
            CertKind::Kdc
        } else {
            CertKind::Client
        };
        let leaf = p256_cert(2, "Kerber Test CA", leaf_cn, &lp, &self.ca_secret, kind)?;
        let sattrs = signed_attrs_set(econtent_oid, e_content);
        let signature = p256_sign(&ls, &sattrs)?;
        let mut implicit = sattrs;
        if implicit.first() == Some(&0x31) {
            implicit[0] = 0xa0;
        }
        let issuer = directory_name("Kerber Test CA");
        Some(cms_wrap_signed(
            e_content,
            &leaf,
            &signature,
            &issuer,
            &[2],
            econtent_oid,
            Some(&implicit),
        ))
    }

    /// User identity PEM (certificate + EC key) for MIT `X509_user_identity=FILE:`.
    #[must_use]
    pub fn user_identity_pem(&self, cn: &str) -> Option<String> {
        let (s, p) = generate_p256()?;
        let cert = self.issue_leaf(cn, &s, &p)?;
        Some(format!(
            "{}{}",
            pem("CERTIFICATE", &cert),
            pem_ec_key(&s, &p)
        ))
    }
}

#[cfg(test)]
mod rfc8636_tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn rfc8636_other_info_is_stable_and_oid_specific() {
        let client = encode_krb5_principal_name("SU.SE", 1, &["lha"]);
        let server = encode_krb5_principal_name("SU.SE", 2, &["krbtgt", "SU.SE"]);
        let supp = encode_pkinit_supp_pub_info(18, &[0xAA; 10], &[0xBB; 9]);
        let other = encode_rfc8636_other_info(KDF_AH_SHA256_OID, &client, &server, &supp);
        let oid384: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x06, 0x04];
        let other384 = encode_rfc8636_other_info(oid384, &client, &server, &supp);
        assert_ne!(other, other384);
        assert!(other.starts_with(&[0x30]));
        let z = vec![0u8; 256];
        let mut h = Sha256::new();
        h.update(1u32.to_be_bytes());
        h.update(&z);
        h.update(&other);
        let key: [u8; 32] = h.finalize().into();
        let again = encode_rfc8636_other_info(KDF_AH_SHA256_OID, &client, &server, &supp);
        let mut h2 = Sha256::new();
        h2.update(1u32.to_be_bytes());
        h2.update(&z);
        h2.update(&again);
        let key2: [u8; 32] = h2.finalize().into();
        assert_eq!(key, key2);
    }
}
