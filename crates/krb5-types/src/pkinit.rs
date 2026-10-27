use crate::{Checksum, KerberosTime, Microseconds, OctetString};
use rasn::prelude::*;

#[cfg(any(test, feature = "test-ca"))]
mod ca;
mod cms;
mod identity;
mod kx;
mod matching;
mod rsa;

#[cfg(any(test, feature = "test-ca"))]
pub use ca::{PkinitCa, cms_wrap};
pub use cms::{
    CertSans, ChainError, CmsAlgorithmIdentifier, CmsAuthPack, CmsContentInfo, CmsEncapContentInfo,
    CmsFault, CmsSignedData, CmsSigner, CmsSignerInfo, CmsVerified, EkuCheck, cert_eku, cert_sans,
    cms_extract_unsigned, cms_sign_chain, cms_sign_leaf, cms_sign_leaf_oids, cms_signeddata_verify,
    cms_unwrap, cms_verify, cms_verify_full, cms_wrap_signed, cms_wrap_unsigned,
    encode_td_certifiers, parse_identity_pem, parse_pem, require_client_pkinit_san,
    spki_signature_ok, verify_chain,
};
pub use identity::{
    IdentityError, IdentityKey, PkinitIdentity, load_ca_certs, load_identities, load_identity,
};

/// P-384 is compiled in only with `--cfg p384_backend="fiat"`, p384's constant-time field.
pub const P384_ENABLED: bool = cfg!(p384_backend = "fiat");
pub use kx::{
    KxGroup, KxKey, choose_td_group, decode_spki, encode_td_dh_parameters, group_desc,
    parse_dh_min_bits,
};
pub use matching::{CertMatchError, MatchTrace, cert_match, select_cert};
pub use rsa::RsaKey;

/// OCTET STRING (wire tag `0x80` / `0x82`).
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PaPkAsReq {
    #[rasn(tag(0))]
    pub signed_auth_pack: OctetString,
    // MIT: `pa_pk_as_req_1` (lib/krb5/asn.1/asn1_k_encode.c:1464-1465)
    // `[1]`, explicit, an optional SEQUENCE OF ExternalPrincipalIdentifier.
    // MIT: `pkinit_as_req_create` (plugins/preauth/pkinit/pkinit_clnt.c:271-273)
    // the client fills it from its trusted CAs.
    #[rasn(tag(explicit(1)))]
    pub trusted_certifiers: Option<SequenceOf<ExternalPrincipalIdentifier>>,
    #[rasn(tag(2))]
    pub kdc_pk_id: Option<OctetString>,
}

// MIT: `external_principal_identifier_fields` (lib/krb5/asn.1/asn1_k_encode.c:1448-1450)
// three fields, each `[n]` IMPLICIT, an optional octet string.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct ExternalPrincipalIdentifier {
    #[rasn(tag(0))]
    pub subject_name: Option<OctetString>,
    #[rasn(tag(1))]
    pub issuer_and_serial_number: Option<OctetString>,
    #[rasn(tag(2))]
    pub subject_key_identifier: Option<OctetString>,
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PkAuthenticator {
    #[rasn(tag(explicit(0)))]
    pub cusec: Microseconds,
    #[rasn(tag(explicit(1)))]
    pub ctime: KerberosTime,
    #[rasn(tag(explicit(2)))]
    pub nonce: u32,
    #[rasn(tag(explicit(3)))]
    pub pa_checksum: Option<OctetString>,
    #[rasn(tag(explicit(4)))]
    pub freshness_token: Option<OctetString>,
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct AuthPack {
    #[rasn(tag(explicit(0)))]
    pub pk_authenticator: PkAuthenticator,
    #[rasn(tag(explicit(1)))]
    pub client_public_value: Option<OctetString>,
    #[rasn(tag(explicit(2)))]
    pub supported_cms_types: Option<SequenceOf<OctetString>>,
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct DhRepInfo {
    #[rasn(tag(0))]
    pub dh_signed_data: OctetString,
    #[rasn(tag(explicit(1)))]
    pub server_dh_nonce: Option<OctetString>,
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(choice)]
pub enum PaPkAsRep {
    #[rasn(tag(explicit(0)))]
    DhInfo(DhRepInfo),
    #[rasn(tag(1))]
    EncKeyPack(OctetString),
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct ReplyKeyPack {
    #[rasn(tag(explicit(0)))]
    pub reply_key: crate::EncryptionKey,
    #[rasn(tag(explicit(1)))]
    pub as_checksum: Checksum,
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct KdcDHKeyInfo {
    #[rasn(tag(explicit(0)))]
    pub subject_public_key: OctetString,
    #[rasn(tag(explicit(1)))]
    pub nonce: u32,
    #[rasn(tag(explicit(2)))]
    pub dh_key_expiration: Option<KerberosTime>,
}

pub const ECONTENT_AUTHDATA: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x01];

pub const ECONTENT_DHKEY: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x02];

pub const OID_PKINIT_SAN: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x02, 0x02];

pub const OID_KP_CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x04];

pub const OID_KP_KDC: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x05];

const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];

const OID_EKU: &[u8] = &[0x55, 0x1d, 0x25];

const OID_BC: &[u8] = &[0x55, 0x1d, 0x13];

const OID_KU: &[u8] = &[0x55, 0x1d, 0x0f];

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

const OID_DHPUBLICNUMBER: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3e, 0x02, 0x01];

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

#[must_use]
pub fn kdc_req_body_checksum(body: &[u8]) -> Vec<u8> {
    sha1_bytes(body)
}

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

pub const KDF_AH_SHA256_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x06, 0x02];

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

#[must_use]
pub fn encode_kdf_algorithm_id(oid: &[u8]) -> Vec<u8> {
    tlv(0x30, &tlv(0xa0, &oid_der(oid)))
}

#[must_use]
pub fn encode_pkinit_supp_pub_info(enctype: i32, as_req: &[u8], pk_as_rep: &[u8]) -> Vec<u8> {
    let e = tlv(0xa0, &der_i32(enctype));
    let a = tlv(0xa1, &tlv(0x04, as_req));
    let p = tlv(0xa2, &tlv(0x04, pk_as_rep));
    tlv(0x30, &[e, a, p].concat())
}

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

#[must_use]
pub fn encode_client_authpack(pk_auth: &PkAuthenticator, spki: &[u8]) -> Option<Vec<u8>> {
    let pk = rasn::der::encode(pk_auth).ok()?;
    let body = [tlv(0xa0, &pk), tlv(0xa1, spki)].concat();
    authpack_with_sha256_kdf(&tlv(0x30, &body))
}

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
    if tag == 0x80 || tag == 0xa0 {
        Some(val.to_vec())
    } else {
        None
    }
}

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

pub const ANONYMOUS_REALM: &str = "WELLKNOWN:ANONYMOUS";

#[must_use]
pub fn anonymous_client() -> crate::PrincipalName {
    crate::PrincipalName::new(
        crate::PrincipalName::NT_WELLKNOWN,
        ["WELLKNOWN", "ANONYMOUS"],
    )
}

#[must_use]
pub fn is_anonymous_principal(name: &crate::PrincipalName) -> bool {
    name.components_eq(&anonymous_client())
}

#[must_use]
pub fn encode_party_u(cname: &crate::PrincipalName, realm: &str) -> Vec<u8> {
    if is_anonymous_principal(cname) {
        return encode_krb5_principal_name(
            ANONYMOUS_REALM,
            crate::PrincipalName::NT_WELLKNOWN,
            &["WELLKNOWN", "ANONYMOUS"],
        );
    }
    encode_principal(cname, realm)
}

// MIT: `pkinit_as_rep_parse` (plugins/preauth/pkinit/pkinit_clnt.c:489-644)
// MIT: `pkinit_server_return_padata` (pkinit_srv.c:880-881)
// and so does the KDC.
#[must_use]
pub fn encode_party_v(body: &crate::KdcReqBody) -> Option<Vec<u8>> {
    let sname = body.sname.as_ref()?;
    Some(encode_principal(
        sname,
        &String::from_utf8_lossy(body.realm.as_bytes()),
    ))
}

#[must_use]
pub fn encode_principal(name: &crate::PrincipalName, realm: &str) -> Vec<u8> {
    let parts: Vec<String> = name
        .name_string
        .iter()
        .map(|s| String::from_utf8_lossy(s.as_bytes()).into_owned())
        .collect();
    let prefs: Vec<&str> = parts.iter().map(String::as_str).collect();
    encode_krb5_principal_name(realm, name.name_type, &prefs)
}

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
    let mut out = Vec::with_capacity(1 + crate::der::len_len(body.len()) + body.len());
    crate::der::push_tlv(&mut out, tag, body);
    out
}

fn oid_der(arcs: &[u8]) -> Vec<u8> {
    tlv(0x06, arcs)
}

fn der_take_len(b: &[u8]) -> Option<(usize, usize)> {
    crate::der::read_len(b).map(|(len, hlen)| (hlen, len))
}

fn take_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *input.first()?;
    let (hlen, ln) = der_take_len(input.get(1..)?)?;
    let start = 1 + hlen;
    let end = start.checked_add(ln)?;
    let body = input.get(start..end)?;
    let rest = input.get(end..)?;
    Some((tag, body, rest))
}

#[cfg(test)]
mod signed_attrs_tests;
