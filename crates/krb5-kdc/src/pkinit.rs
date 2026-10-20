//! The realm's PKINIT context: the KDC's identity, the anchors and intermediates it verifies
//! client certificates with, and its client-certificate options, initialized when the KDC starts,
//! as MIT's pkinit module initializes a realm.

use krb5_config::PkinitParams;
use krb5_types::pkinit::{PkinitIdentity, load_ca_certs, load_identity, verify_chain};

/// One realm's PKINIT context.
#[derive(Debug)]
pub struct PkinitKdc {
    pub(crate) identity: PkinitIdentity,
    pub(crate) anchors: Vec<Vec<u8>>,
    pub(crate) pool: Vec<Vec<u8>>,
    pub(crate) require_eku: bool,
    pub(crate) accept_secondary_eku: bool,
    pub(crate) allow_upn: bool,
}

impl PkinitKdc {
    /// The context of `realm` from its options: the identity, then the anchors, then the pool.
    /// Certificate revocation is not supported, so a realm that asks for it does not initialize.
    /// MIT `pkinit_init_kdc_profile` (`plugins/preauth/pkinit/pkinit_srv.c:950-1043`): an identity and anchors are required, and `pkinit_kdc_ocsp` is refused.
    /// MIT `pkinit_server_plugin_init_realm` (`plugins/preauth/pkinit/pkinit_srv.c:1076-1140`): the options, then `pkinit_identity_initialize` and `pkinit_identity_prompt`.
    ///
    /// # Errors
    ///
    /// MIT's message, which the KDC logs after "PKINIT initialization failed: ".
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
        let identity = load_identity(identity, &mut krb5_protocol::trace::pkinit_match)?;
        Ok(Self {
            identity,
            anchors: load_some(&params.anchors)?,
            pool: load_some(&params.pool)?,
            require_eku: params.require_eku,
            accept_secondary_eku: params.accept_secondary_eku,
            allow_upn: params.allow_upn,
        })
    }

    /// The context of `identity` trusting `anchors`, with MIT's default options.
    #[must_use]
    pub fn new(identity: PkinitIdentity, anchors: Vec<Vec<u8>>) -> Self {
        Self {
            identity,
            anchors,
            pool: Vec::new(),
            require_eku: true,
            accept_secondary_eku: false,
            allow_upn: false,
        }
    }

    /// The certificates the KDC's signed reply carries: its own chain without the anchor, which
    /// leaves none when its certificate is itself an anchor.
    /// MIT `cms_signeddata_create` (`plugins/preauth/pkinit/pkinit_crypto_openssl.c:1758-1782`): a chain that does not verify is "Failed to verify own certificate (depth N): <reason>".
    pub(crate) fn own_chain(&self) -> Result<Vec<Vec<u8>>, String> {
        let pool: Vec<&[u8]> = self.pool.iter().map(Vec::as_slice).collect();
        let mut chain = verify_chain(&self.identity.cert, &self.anchors, &pool)
            .map_err(|e| format!("Failed to verify own certificate {e}"))?;
        chain.pop();
        Ok(chain)
    }
}

/// The certificates of `values`; when values are given, at least one loads, else the error is
/// the last one's.
/// MIT `pkinit_identity_prompt` (`plugins/preauth/pkinit/pkinit_identity.c:635-662`): one anchor or intermediate value that loads is enough.
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
