//! Test CA used as a pkinit_anchors FILE trust anchor.
//!
//! `cms_wrap` lives here (it names [`PkinitCa`]) so `cms` does not
//! import this module.

use super::cms::{cms_wrap_signed, p256_sign, pem, signed_attrs_set};
use super::{
    ECONTENT_AUTHDATA, ECONTENT_DHKEY, OID_KP_CLIENT_AUTH, OID_KP_KDC, OID_KU,
    encode_krb5_principal_name, oid_der, tlv,
};

const UTC_NOT_BEFORE: &[u8] = b"250101000000Z";

const UTC_NOT_AFTER: &[u8] = b"360101000000Z";

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
    CaNoKeyCertSign,
    CaAbsentKu,
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
    realm: &str,
) -> Option<Vec<u8>> {
    p256_cert_window(
        serial,
        issuer_cn,
        subject_cn,
        subject_public,
        signer_secret,
        kind,
        realm,
        UTC_NOT_BEFORE,
        UTC_NOT_AFTER,
    )
}

/// MIT `cms_contentinfo_create` (`pkinit_crypto_openssl.c:1685-1687`): a DER encode that fails is not a successful object.
/// The certificate is returned only when the signature over the to-be-signed body is produced.
#[expect(clippy::too_many_arguments, reason = "test CA, not a params struct")]
fn p256_cert_window(
    serial: u8,
    issuer_cn: &str,
    subject_cn: &str,
    subject_public: &[u8],
    signer_secret: &[u8; 32],
    kind: CertKind,
    realm: &str,
    not_before: &[u8],
    not_after: &[u8],
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
        &[tlv(0x17, not_before), tlv(0x17, not_after)].concat(),
    );
    let mut tbs_body = Vec::new();
    tbs_body.extend(tlv(0xa0, &tlv(0x02, &[0x02])));
    tbs_body.extend(tlv(0x02, &[serial]));
    tbs_body.extend_from_slice(&alg_id);
    tbs_body.extend_from_slice(&issuer);
    tbs_body.extend_from_slice(&validity);
    tbs_body.extend_from_slice(&subject);
    tbs_body.extend_from_slice(&spki);
    tbs_body.extend_from_slice(&cert_extensions(kind, subject_cn, realm));
    let tbs = tlv(0x30, &tbs_body);
    let sig = p256_sign(signer_secret, &tbs)?;
    let mut sig_bit = vec![0u8];
    sig_bit.extend_from_slice(&sig);
    Some(tlv(0x30, &[tbs, alg_id, tlv(0x03, &sig_bit)].concat()))
}

/// MIT `cms_contentinfo_create` (`pkinit_crypto_openssl.c:1685-1687`): a DER encode that fails is not a successful object.
/// A KDC certificate carries a krbtgt name in that realm and the KDC extended key usage, and a CA without key usage still carries basic constraints.
fn cert_extensions(kind: CertKind, subject_cn: &str, realm: &str) -> Vec<u8> {
    let is_ca = matches!(
        kind,
        CertKind::Ca | CertKind::CaNoKeyCertSign | CertKind::CaAbsentKu
    );
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
    let ku_oid = oid_der(OID_KU);
    let ku_bits = if matches!(kind, CertKind::Ca) {
        tlv(0x03, &[0x01, 0b0000_0110])
    } else {
        tlv(0x03, &[0x07, 0b1000_0000])
    };
    let ku = tlv(
        0x30,
        &[ku_oid, tlv(0x01, &[0xff]), tlv(0x04, &ku_bits)].concat(),
    );
    let mut ext_body = if matches!(kind, CertKind::CaAbsentKu) {
        bc
    } else {
        [bc, ku].concat()
    };
    match kind {
        CertKind::Kdc => {
            ext_body.extend(san_general(&[
                other_name_pkinit(&format!("krbtgt/{realm}@{realm}")),
                tlv(0x82, b"kerber.test"),
            ]));
            ext_body.extend(eku(OID_KP_KDC));
        }
        CertKind::Client => {
            let san = if subject_cn.contains('@') {
                subject_cn.to_owned()
            } else {
                format!("{subject_cn}@{realm}")
            };
            ext_body.extend(san_general(&[other_name_pkinit(&san)]));
            ext_body.extend(eku(OID_KP_CLIENT_AUTH));
        }
        CertKind::Ca | CertKind::CaNoKeyCertSign | CertKind::CaAbsentKu => {}
    }
    tlv(0xa3, &tlv(0x30, &ext_body))
}

fn san_general(names: &[Vec<u8>]) -> Vec<u8> {
    let gns = tlv(0x30, &names.concat());
    tlv(
        0x30,
        &[oid_der(&[0x55, 0x1d, 0x11]), tlv(0x04, &gns)].concat(),
    )
}

fn other_name_pkinit(principal: &str) -> Vec<u8> {
    let parsed = crate::parse_name_ex(principal, "KERBER.TEST", false)
        .or_else(|_| crate::parse_name_ex(principal, "KERBER.TEST", true))
        .unwrap_or_else(|_| crate::ParsedName {
            components: vec![principal.to_owned()],
            realm: "KERBER.TEST".into(),
            has_realm: false,
        });
    let ntype = crate::infer_name_type(&parsed.components);
    let refs: Vec<&str> = parsed.components.iter().map(String::as_str).collect();
    let kn = encode_krb5_principal_name(&parsed.realm, ntype, &refs);
    let oid = oid_der(&[0x2b, 0x06, 0x01, 0x05, 0x02, 0x02]);
    let value = tlv(0xa0, &kn);
    tlv(0xa0, &[oid, value].concat())
}

fn eku(oid_body: &[u8]) -> Vec<u8> {
    let seq = tlv(0x30, &oid_der(oid_body));
    tlv(
        0x30,
        &[oid_der(&[0x55, 0x1d, 0x25]), tlv(0x04, &seq)].concat(),
    )
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

/// Test CA used as a pkinit_anchors FILE trust anchor.
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
        Self::generate_window(UTC_NOT_BEFORE, UTC_NOT_AFTER)
    }

    /// Self-signed CA with an explicit UTCTime window.
    #[must_use]
    pub fn generate_window(not_before: &[u8], not_after: &[u8]) -> Option<Self> {
        let (ca_secret, ca_public) = generate_p256()?;
        let ca_cert = p256_cert_window(
            1,
            "Kerber Test CA",
            "Kerber Test CA",
            &ca_public,
            &ca_secret,
            CertKind::Ca,
            "KERBER.TEST",
            not_before,
            not_after,
        )?;
        Some(Self {
            ca_secret,
            ca_cert,
            ca_public,
        })
    }

    /// CA with `basicConstraints` CA=true but without `keyCertSign`.
    #[must_use]
    pub fn generate_no_key_cert_sign() -> Option<Self> {
        let (ca_secret, ca_public) = generate_p256()?;
        let ca_cert = p256_cert(
            1,
            "Kerber Test CA",
            "Kerber Test CA",
            &ca_public,
            &ca_secret,
            CertKind::CaNoKeyCertSign,
            "KERBER.TEST",
        )?;
        Some(Self {
            ca_secret,
            ca_cert,
            ca_public,
        })
    }

    /// CA with no `keyUsage` extension (RFC 5280 §6.1.4(n) skip).
    #[must_use]
    pub fn generate_absent_key_usage() -> Option<Self> {
        let (ca_secret, ca_public) = generate_p256()?;
        let ca_cert = p256_cert(
            1,
            "Kerber Test CA",
            "Kerber Test CA",
            &ca_public,
            &ca_secret,
            CertKind::CaAbsentKu,
            "KERBER.TEST",
        )?;
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
            "KERBER.TEST",
        )
    }

    /// Client leaf with an explicit UTCTime validity window (`YYMMDDHHMMSSZ`).
    #[must_use]
    pub fn issue_leaf_window(
        &self,
        cn: &str,
        leaf_public: &[u8],
        not_before: &[u8],
        not_after: &[u8],
    ) -> Option<Vec<u8>> {
        p256_cert_window(
            2,
            "Kerber Test CA",
            cn,
            leaf_public,
            &self.ca_secret,
            CertKind::Client,
            "KERBER.TEST",
            not_before,
            not_after,
        )
    }

    /// Client leaf whose issuer DN does not match this CA (CA key still signs).
    #[must_use]
    pub fn issue_leaf_wrong_issuer(&self, cn: &str, leaf_public: &[u8]) -> Option<Vec<u8>> {
        p256_cert(
            2,
            "Wrong CA",
            cn,
            leaf_public,
            &self.ca_secret,
            CertKind::Client,
            "KERBER.TEST",
        )
    }

    /// CMS-sign `e_content` with a fresh leaf under this CA (`id-pkinit-authData`).
    #[must_use]
    pub fn sign_cms(&self, e_content: &[u8], leaf_cn: &str) -> Option<Vec<u8>> {
        self.sign_cms_typed(e_content, leaf_cn, ECONTENT_AUTHDATA, "KERBER.TEST")
    }

    /// CMS-sign `e_content` with `econtent_oid` and RFC 5652 signedAttrs.
    #[must_use]
    pub fn sign_cms_typed(
        &self,
        e_content: &[u8],
        leaf_cn: &str,
        econtent_oid: &[u8],
        realm: &str,
    ) -> Option<Vec<u8>> {
        let (ls, lp) = generate_p256()?;
        let kind = if econtent_oid == ECONTENT_DHKEY {
            CertKind::Kdc
        } else {
            CertKind::Client
        };
        let leaf = p256_cert(
            2,
            "Kerber Test CA",
            leaf_cn,
            &lp,
            &self.ca_secret,
            kind,
            realm,
        )?;
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

    /// KDC identity PEM (cert+key) for MIT `pkinit_identity = FILE:`.
    #[must_use]
    pub fn kdc_identity_pem(&self) -> Option<String> {
        self.kdc_identity_pem_for("KERBER.TEST")
    }

    /// KDC identity whose `id-pkinit-san` is `krbtgt/REALM@REALM`.
    #[must_use]
    pub fn kdc_identity_pem_for(&self, realm: &str) -> Option<String> {
        let (cert, s, p) = self.kdc_identity_for(realm)?;
        Some(format!(
            "{}{}",
            pem("CERTIFICATE", &cert),
            pem_ec_key(&s, &p)
        ))
    }

    /// KDC leaf + scalar for `realm` (EKU KPKdc, SAN `krbtgt/REALM@REALM`).
    #[must_use]
    pub fn kdc_identity_for(&self, realm: &str) -> Option<(Vec<u8>, [u8; 32], Vec<u8>)> {
        let (s, p) = generate_p256()?;
        let cert = p256_cert(
            3,
            "Kerber Test CA",
            "krbtgt",
            &p,
            &self.ca_secret,
            CertKind::Kdc,
            realm,
        )?;
        Some((cert, s, p))
    }

    /// Client cert + scalar (EKU KPClientAuth, SAN from `cn`).
    #[must_use]
    pub fn client_identity_for(&self, cn: &str) -> Option<(Vec<u8>, [u8; 32])> {
        let (s, p) = generate_p256()?;
        let cert = self.issue_leaf(cn, &s, &p)?;
        Some((cert, s))
    }

    /// Client identity with an explicit UTCTime validity window.
    #[must_use]
    pub fn client_identity_window(
        &self,
        cn: &str,
        not_before: &[u8],
        not_after: &[u8],
    ) -> Option<(Vec<u8>, [u8; 32])> {
        let (s, p) = generate_p256()?;
        let cert = self.issue_leaf_window(cn, &p, not_before, not_after)?;
        Some((cert, s))
    }

    /// Client identity whose issuer DN does not match this CA.
    #[must_use]
    pub fn client_identity_wrong_issuer(&self, cn: &str) -> Option<(Vec<u8>, [u8; 32])> {
        let (s, p) = generate_p256()?;
        let cert = self.issue_leaf_wrong_issuer(cn, &p)?;
        Some((cert, s))
    }

    /// Self-signed end-entity (CA=false) for negative path-validation tests.
    #[must_use]
    pub fn self_signed_end_entity() -> Option<(Vec<u8>, [u8; 32])> {
        let (s, p) = generate_p256()?;
        let cert = p256_cert(1, "ee", "ee", &p, &s, CertKind::Client, "KERBER.TEST")?;
        Some((cert, s))
    }
}
