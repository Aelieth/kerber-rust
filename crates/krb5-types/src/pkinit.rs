//! RFC 4556 PKINIT PA-DATA types (AuthPack / PA-PK-AS-REQ / PA-PK-AS-REP).

use rasn::prelude::*;

use crate::{Checksum, KerberosTime, Microseconds, OctetString};

/// PA-PK-AS-REQ ::= SEQUENCE { signedAuthPack, trustedCertifiers, kdcPkId }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PaPkAsReq {
    /// CMS SignedData wrapping [`AuthPack`] (DER).
    #[rasn(tag(explicit(0)))]
    pub signed_auth_pack: OctetString,
    /// Optional trusted certifiers (opaque DER).
    #[rasn(tag(explicit(1)))]
    pub trusted_certifiers: Option<SequenceOf<OctetString>>,
    /// Optional KDC public-key identifier.
    #[rasn(tag(explicit(2)))]
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
    #[rasn(tag(explicit(0)))]
    pub dh_signed_data: OctetString,
    /// Optional server DH nonce.
    #[rasn(tag(explicit(1)))]
    pub server_dh_nonce: Option<OctetString>,
}

/// PA-PK-AS-REP ::= CHOICE { dhInfo[0], encKeyPack[1] }
///
/// Encoded as a context-tagged wrapper; this struct holds the dhInfo arm.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PaPkAsRep {
    /// DH reply info.
    #[rasn(tag(explicit(0)))]
    pub dh_info: Option<DhRepInfo>,
    /// Encrypted key pack (CMS EnvelopedData) when DH is not used.
    #[rasn(tag(explicit(1)))]
    pub enc_key_pack: Option<OctetString>,
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

/// Minimal X.509 v3 self-signed P-256 certificate (test CA).
fn self_signed_p256_cert(cn: &str, secret: &[u8; 32], public: &[u8]) -> Option<Vec<u8>> {
    let cn_atv = tlv(
        0x30,
        &[oid_der(&[0x55, 0x04, 0x03]), tlv(0x0c, cn.as_bytes())].concat(),
    );
    let name = tlv(0x30, &tlv(0x31, &cn_atv));
    let alg_id = tlv(
        0x30,
        &[
            oid_der(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]), // ecdsa-with-SHA256
        ]
        .concat(),
    );
    let spki_alg = tlv(
        0x30,
        &[
            oid_der(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]), // id-ecPublicKey
            oid_der(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]), // secp256r1
        ]
        .concat(),
    );
    let mut bit = vec![0u8];
    bit.extend_from_slice(public);
    let spki = tlv(0x30, &[spki_alg, tlv(0x03, &bit)].concat());
    let validity = tlv(
        0x30,
        &[tlv(0x17, b"250101000000Z"), tlv(0x17, b"360101000000Z")].concat(),
    );
    let mut tbs_body = Vec::new();
    tbs_body.extend(tlv(0xa0, &tlv(0x02, &[0x02]))); // version v3
    tbs_body.extend(tlv(0x02, &[0x01])); // serial 1
    tbs_body.extend_from_slice(&alg_id);
    tbs_body.extend_from_slice(&name);
    tbs_body.extend_from_slice(&validity);
    tbs_body.extend_from_slice(&name);
    tbs_body.extend_from_slice(&spki);
    let tbs = tlv(0x30, &tbs_body);
    let sig = p256_sign(secret, &tbs)?;
    let mut sig_bit = vec![0u8];
    sig_bit.extend_from_slice(&sig);
    Some(tlv(0x30, &[tbs, alg_id, tlv(0x03, &sig_bit)].concat()))
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

/// Wrap `e_content` in CMS SignedData with a self-signed P-256 certificate.
///
/// The SignerInfo signature is ECDSA-SHA256 over `e_content`. MIT pkinit
/// still needs a configured trust anchor to accept the test CA.
#[must_use]
pub fn cms_wrap(e_content: &[u8]) -> Vec<u8> {
    let Some((secret, public)) = generate_p256() else {
        return e_content.to_vec();
    };
    let Some(cert) = self_signed_p256_cert("pkinit-test", &secret, &public) else {
        return e_content.to_vec();
    };
    let Some(signature) = p256_sign(&secret, e_content) else {
        return e_content.to_vec();
    };
    cms_wrap_signed(e_content, &cert, &signature, &sha256_bytes(&public))
}

/// CMS SignedData with an explicit certificate and ECDSA signature.
///
/// Encoded by hand so the Certificate SET uses IMPLICIT `[0]` (RFC 5652).
#[must_use]
pub fn cms_wrap_signed(e_content: &[u8], cert_der: &[u8], signature: &[u8], ski: &[u8]) -> Vec<u8> {
    let sha256 = oid_der(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
    let ecdsa = oid_der(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);
    let signed_data = oid_der(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]);
    let pkinit_ad = oid_der(&[0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x01]);
    let digest_algs = tlv(0x31, &tlv(0x30, &sha256));
    let econt = tlv(0xa0, &tlv(0x04, e_content));
    let encap = tlv(0x30, &[pkinit_ad, econt].concat());
    let certs = tlv(0xa0, cert_der); // [0] IMPLICIT SET OF Certificate: single SEQUENCE
    let sid = tlv(0x80, ski);
    let signer = tlv(
        0x30,
        &[
            tlv(0x02, &[0x03]),
            sid,
            tlv(0x30, &sha256),
            tlv(0x30, &ecdsa),
            tlv(0x04, signature),
        ]
        .concat(),
    );
    let signers = tlv(0x31, &signer);
    let sd = tlv(
        0x30,
        &[tlv(0x02, &[0x03]), digest_algs, encap, certs, signers].concat(),
    );
    tlv(0x30, &[signed_data, tlv(0xa0, &sd)].concat())
}

/// Extract eContent from [`cms_wrap`], or return `der` unchanged if it is not CMS.
#[must_use]
pub fn cms_unwrap(der: &[u8]) -> Vec<u8> {
    if let Ok(ci) = rasn::der::decode::<CmsContentInfo>(der) {
        if let Some(ec) = ci.content.encap_content_info.e_content {
            return ec.to_vec();
        }
    }
    if let Ok(p) = cms_parts(der) {
        return p.e_content;
    }
    der.to_vec()
}

/// Verify a cert-backed CMS SignedData and return eContent.
///
/// # Errors
///
/// Missing certificate, missing signature, or ECDSA failure.
pub fn cms_verify(der: &[u8]) -> Result<Vec<u8>, &'static str> {
    let p = cms_parts(der)?;
    let public = spki_uncompressed(&p.cert).ok_or("cms spki")?;
    if !p256_verify(&public, &p.e_content, &p.signature) {
        return Err("cms ecdsa");
    }
    Ok(p.e_content)
}

struct CmsParts {
    e_content: Vec<u8>,
    cert: Vec<u8>,
    signature: Vec<u8>,
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
    s = take_tlv(s).ok_or("salg")?.2;
    let (t, sig, _) = take_tlv(s).ok_or("sig")?;
    if t != 0x04 {
        return Err("sig oct");
    }
    Ok(CmsParts {
        e_content,
        cert,
        signature: sig.to_vec(),
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
