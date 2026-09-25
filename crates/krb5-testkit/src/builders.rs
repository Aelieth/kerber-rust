//! AS-REQ / TGS-REQ builders for tests.
//!
//! These wrap the protocol `as_req*` / `tgs_req_ex*` helpers so test
//! sites share one type. Product `src/` and `diffsend` keep calling
//! the protocol functions (S3 records the pub-surface move).

use krb5_crypto::ProtocolKey;
use krb5_kdc::testrealm::TEST_REALM;

use krb5_protocol::{TgsReqParams, as_req, as_req_sname, tgs_req_ex};
use krb5_types::{
    AsReq, EncryptedData, HostAddresses, KdcOptions, KerberosTime, PaData, PrincipalName, TgsReq,
    Ticket,
};

use crate::pref_etypes;

/// AS-REQ builder. Defaults: [`TEST_REALM`], no padata, krbtgt sname
/// and preferred etypes via [`as_req`].
#[must_use]
pub struct AsReqBuilder {
    cname: PrincipalName,
    realm: String,
    nonce: u32,
    padata: Option<Vec<PaData>>,
    sname: Option<PrincipalName>,
    etypes: Option<Vec<i32>>,
}

impl AsReqBuilder {
    /// `cname` + `nonce`. Realm defaults to [`TEST_REALM`].
    pub fn new(cname: PrincipalName, nonce: u32) -> Self {
        Self {
            cname,
            realm: TEST_REALM.to_owned(),
            nonce,
            padata: None,
            sname: None,
            etypes: None,
        }
    }

    /// Request realm.
    pub fn realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = realm.into();
        self
    }

    /// Pre-authentication padata.
    pub fn padata(mut self, padata: Vec<PaData>) -> Self {
        self.padata = Some(padata);
        self
    }

    /// Explicit `sname` (otherwise krbtgt of the realm).
    pub fn sname(mut self, sname: PrincipalName) -> Self {
        self.sname = Some(sname);
        self
    }

    /// Explicit etype list (otherwise [`pref_etypes`]).
    pub fn etypes(mut self, etypes: Vec<i32>) -> Self {
        self.etypes = Some(etypes);
        self
    }

    /// Build the AS-REQ.
    ///
    /// # Errors
    ///
    /// Same as [`krb5_protocol::as_req`] / [`krb5_protocol::as_req_sname`].
    pub fn build(self) -> Result<AsReq, krb5_protocol::Error> {
        match (self.sname, self.etypes) {
            (None, None) => as_req(self.cname, &self.realm, self.nonce, self.padata),
            (sname, etypes) => as_req_sname(
                self.cname,
                &self.realm,
                self.nonce,
                self.padata,
                sname.unwrap_or_else(|| PrincipalName::krbtgt(&self.realm)),
                etypes.unwrap_or_else(pref_etypes),
            ),
        }
    }
}

/// TGS-REQ builder wrapping [`krb5_protocol::tgs_req_ex`].
///
/// Defaults match [`krb5_protocol::tgs_req`]: FORWARDABLE, no
/// additional tickets, empty extra padata, preferred etypes, no
/// addresses / from / enc-ad / till / subkey.
#[must_use]
pub struct TgsReqBuilder {
    ticket: Ticket,
    session: ProtocolKey,
    crealm: String,
    cname: PrincipalName,
    sname: PrincipalName,
    realm: String,
    nonce: u32,
    options: KdcOptions,
    additional: Option<Vec<Ticket>>,
    padata: Vec<PaData>,
    etypes: Vec<i32>,
    addresses: Option<HostAddresses>,
    from: Option<KerberosTime>,
    enc_ad: Option<EncryptedData>,
    till: Option<KerberosTime>,
    subkey: Option<ProtocolKey>,
}

impl TgsReqBuilder {
    /// Required fields shared by every `tgs_req_ex*` site.
    pub fn new(
        ticket: Ticket,
        session: &ProtocolKey,
        crealm: impl Into<String>,
        cname: &PrincipalName,
        sname: PrincipalName,
        realm: impl Into<String>,
        nonce: u32,
    ) -> Self {
        Self {
            ticket,
            session: session.clone(),
            crealm: crealm.into(),
            cname: cname.clone(),
            sname,
            realm: realm.into(),
            nonce,
            options: KdcOptions::forwardable(),
            additional: None,
            padata: Vec::new(),
            etypes: pref_etypes(),
            addresses: None,
            from: None,
            enc_ad: None,
            till: None,
            subkey: None,
        }
    }

    /// `kdc-options`.
    pub fn options(mut self, options: KdcOptions) -> Self {
        self.options = options;
        self
    }

    /// Additional tickets (U2U / S4U2Proxy).
    pub fn additional_tickets(mut self, tickets: Option<Vec<Ticket>>) -> Self {
        self.additional = tickets;
        self
    }

    /// Extra padata after PA-TGS-REQ.
    pub fn padata(mut self, padata: Vec<PaData>) -> Self {
        self.padata = padata;
        self
    }

    /// Requested etypes.
    pub fn etypes(mut self, etypes: Vec<i32>) -> Self {
        self.etypes = etypes;
        self
    }

    /// Request addresses.
    pub fn addresses(mut self, addresses: Option<HostAddresses>) -> Self {
        self.addresses = addresses;
        self
    }

    /// `from` (POSTDATED).
    pub fn from(mut self, from: Option<KerberosTime>) -> Self {
        self.from = from;
        self
    }

    /// Encrypted authorization-data.
    pub fn enc_authorization_data(mut self, enc_ad: Option<EncryptedData>) -> Self {
        self.enc_ad = enc_ad;
        self
    }

    /// Explicit `till`.
    pub fn till(mut self, till: Option<KerberosTime>) -> Self {
        self.till = till;
        self
    }

    /// Authenticator subkey.
    pub fn subkey(mut self, subkey: Option<&ProtocolKey>) -> Self {
        self.subkey = subkey.cloned();
        self
    }

    /// Build the TGS-REQ.
    ///
    /// # Errors
    ///
    /// An encode failure or a key failure.
    pub fn build(self) -> Result<TgsReq, krb5_protocol::Error> {
        tgs_req_ex(TgsReqParams {
            ticket: self.ticket,
            session: &self.session,
            crealm: &self.crealm,
            cname: &self.cname,
            sname: self.sname,
            realm: &self.realm,
            nonce: self.nonce,
            kdc_options: self.options,
            additional_tickets: self.additional,
            extra_padata: self.padata,
            etypes: self.etypes,
            addresses: self.addresses,
            from: self.from,
            enc_authorization_data: self.enc_ad,
            till: self.till,
            subkey: self.subkey.as_ref(),
        })
    }
}
