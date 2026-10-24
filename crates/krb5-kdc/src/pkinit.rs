//! The realm PKINIT context.

use krb5_config::PkinitParams;
use krb5_types::pkinit::{PkinitIdentity, load_ca_certs, load_identity, verify_chain};

#[derive(Debug)]
pub struct PkinitKdc {
    pub(crate) identity: PkinitIdentity,
    pub(crate) anchors: Vec<Vec<u8>>,
    pub(crate) pool: Vec<Vec<u8>>,
    pub(crate) require_eku: bool,
    pub(crate) accept_secondary_eku: bool,
    pub(crate) allow_upn: bool,
    pub(crate) dh_min_bits: u32,
}

impl PkinitKdc {
    // MIT: `pkinit_init_kdc_profile` (plugins/preauth/pkinit/pkinit_srv.c:950-1043)
    // MIT: `pkinit_server_plugin_init_realm` (plugins/preauth/pkinit/pkinit_srv.c:1076-1140)
    /// OCSP, revoke, and CRL checking are refused.
    pub fn init(params: &PkinitParams, realm: &str) -> Result<Self, String> {
        let Some(identity) = params.identity.as_deref() else {
            return Err(format!("No pkinit_identity supplied for realm {realm}"));
        };
        if params.anchors.is_empty() {
            return Err(format!("No pkinit_anchors supplied for realm {realm}"));
        }
        if !params.revoke.is_empty() {
            return Err(format!("pkinit_revoke is not supported: (realm: {realm})"));
        }
        if params.kdc_ocsp.is_some() {
            return Err(format!("OCSP is not supported: (realm: {realm})"));
        }
        if params.require_crl_checking {
            return Err(format!(
                "pkinit_require_crl_checking is not supported: (realm: {realm})"
            ));
        }
        if !krb5_types::pkinit::P384_ENABLED {
            tracing::warn!(
                event = krb5_log::events::KDC_PKINIT,
                component = "krb5-kdc",
                outcome = "ok",
                detail = "P-384 is refused: this build has no --cfg p384_backend=\"fiat\"",
            );
        }
        let dh_min_bits = krb5_types::pkinit::parse_dh_min_bits(params.dh_min_bits.as_deref())
            .unwrap_or_else(|v| {
                krb5_protocol::trace::pkinit_dh_invalid_min_bits(&v);
                2048
            });
        let identity = load_identity(identity, &mut krb5_protocol::trace::pkinit_match)?;
        Ok(Self {
            identity,
            anchors: load_some(&params.anchors)?,
            pool: load_some(&params.pool)?,
            require_eku: params.require_eku,
            accept_secondary_eku: params.accept_secondary_eku,
            allow_upn: params.allow_upn,
            dh_min_bits,
        })
    }

    #[must_use]
    pub fn new(identity: PkinitIdentity, anchors: Vec<Vec<u8>>) -> Self {
        Self {
            identity,
            anchors,
            pool: Vec::new(),
            require_eku: true,
            accept_secondary_eku: false,
            allow_upn: false,
            dh_min_bits: 2048,
        }
    }

    // MIT: `cms_signeddata_create` (plugins/preauth/pkinit/pkinit_crypto_openssl.c:1758-1782)
    pub(crate) fn own_chain(&self) -> Result<Vec<Vec<u8>>, String> {
        let pool: Vec<&[u8]> = self.pool.iter().map(Vec::as_slice).collect();
        let mut chain = verify_chain(&self.identity.cert, &self.anchors, &pool)
            .map_err(|e| format!("Failed to verify own certificate {e}"))?;
        chain.pop();
        Ok(chain)
    }
}

// MIT: `pkinit_identity_prompt` (plugins/preauth/pkinit/pkinit_identity.c:635-662)
fn load_some(values: &[String]) -> Result<Vec<Vec<u8>>, String> {
    let mut certs: Vec<Vec<u8>> = Vec::new();
    let mut loaded = false;
    let mut failure = None;
    for value in values {
        match load_ca_certs(value) {
            Ok(found) => {
                loaded = true;
                for cert in found {
                    if !certs.contains(&cert) {
                        certs.push(cert);
                    }
                }
            }
            Err(e) => failure = Some(e),
        }
    }
    match failure {
        Some(e) if !loaded => Err(e),
        _ => Ok(certs),
    }
}
