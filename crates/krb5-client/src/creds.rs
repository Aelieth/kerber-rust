//! MIT `krb5_get_credentials` and its S4U and user-to-user forms over one open cache, as `kvno`
//! runs them: the cache is asked first, then the KDC, and what the KDC issued is stored back.

use krb5_asn1::decode;
use krb5_config::{CanonPrinc, CcSpec};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt};
use krb5_protocol::{
    AsOutcome, CcacheCred, FileCcache, KdcAddr, Keytab, TgsCredsOptions, TgsOutcome,
    tgs_exchange_path, tgs_s4u, tgs_s4u2proxy, tgt_cred,
};
use krb5_types::{
    EncKdcRepPart, EncTicketPart, EncryptionKey, KerberosTime, PrincipalName, Realm, Ticket,
    TicketFlags, ku,
};

use crate::errmsg::{Code, Krb5Error};

/// A principal and its realm, as a cache keeps them.
pub type Princ = (Realm, PrincipalName);

/// MIT `krb5_principal_compare`: the realms and the components are equal; the name type is not
/// compared.
#[must_use]
pub fn princ_eq(a: &Princ, b: &Princ) -> bool {
    a.0.as_bytes() == b.0.as_bytes() && a.1.name_string == b.1.name_string
}

/// MIT `krb5_unparse_name` of a cache principal.
#[must_use]
pub fn unparse(p: &Princ) -> String {
    p.1.unparse_with_realm(&realm_str(&p.0))
}

fn realm_str(r: &Realm) -> String {
    String::from_utf8_lossy(r.as_bytes()).into_owned()
}

/// `[libdefaults] default_realm`.
#[must_use]
pub fn default_realm() -> Option<String> {
    krb5_config::load_krb5_conf().and_then(|c| c.default_realm)
}

/// MIT `krb5_parse_name_flags`: `name` in the default realm unless it names one, as one
/// NT-ENTERPRISE component for `enterprise`.
///
/// # Errors
///
/// [`Krb5Error`] `KRB5_PARSE_MALFORMED` for a malformed name, `KRB5_CONFIG_NODEFREALM` for a name
/// with no realm when the profile names no default realm.
pub fn parse_name(name: &str, enterprise: bool) -> Result<Princ, Krb5Error> {
    let p = krb5_types::parse_name_ex(name, "", enterprise)
        .map_err(|_| Krb5Error::of(Code::ParseMalformed))?;
    let realm = if p.has_realm {
        p.realm
    } else {
        default_realm().ok_or_else(|| Krb5Error::of(Code::NoDefRealm))?
    };
    let (n, _) = krb5_types::principal_from_unparsed_ex(name, &realm, enterprise)
        .map_err(|_| Krb5Error::of(Code::ParseMalformed))?;
    Ok((krb5_protocol::realm(&realm), n))
}

/// What a cached credential must match.
/// MIT `construct_matching_creds` (`get_creds.c:52-108`): the client and server, still valid,
/// the session-key enctype when one was asked for, and for user-to-user the same second ticket.
/// MIT `construct_matching_creds` (`get_creds.c:89-105`): S4U2Proxy matches the evidence ticket
/// as the second ticket, and any client.
pub struct MatchCreds<'a> {
    /// The client; `None` matches any (S4U2Proxy).
    pub client: Option<&'a Princ>,
    /// The server.
    pub server: &'a Princ,
    /// The asked-for session-key enctype.
    pub enctype: Option<i32>,
    /// A user-to-user credential is asked for (`KRB5_TC_MATCH_IS_SKEY`).
    pub is_skey: bool,
    /// The second ticket (DER) a user-to-user or S4U2Proxy credential carries.
    pub second_ticket: Option<&'a [u8]>,
    /// Now, as a Unix time.
    pub now: u32,
}

impl MatchCreds<'_> {
    /// MIT `krb5int_cc_creds_match_request` (`cc_retr.c:151-191`): a user-to-user credential
    /// matches only a user-to-user request, and only with the same second ticket.
    fn matches(&self, c: &CcacheCred) -> bool {
        if c.is_config() || c.is_removed() {
            return false;
        }
        if self.client.is_some_and(|cl| !princ_eq(cl, &c.client))
            || !princ_eq(self.server, &c.server)
        {
            return false;
        }
        if c.is_skey != u8::from(self.is_skey) {
            return false;
        }
        if self.now > c.endtime || !c.authdata.is_empty() {
            return false;
        }
        if self
            .second_ticket
            .is_some_and(|t| t != c.second_ticket.as_slice())
        {
            return false;
        }
        self.enctype.is_none_or(|e| e == i32::from(c.key.etype))
    }
}

/// One cache, open: its contents as read, and each credential [`OpenCache::store`] has stored
/// since.
pub struct OpenCache {
    /// The resolved name.
    pub spec: CcSpec,
    /// Its contents.
    pub cc: FileCcache,
}

impl OpenCache {
    /// Read `spec`.
    ///
    /// # Errors
    ///
    /// [`Krb5Error`] as MIT's `krb5_cc_get_principal` reports a cache that cannot be read: no
    /// cache is `KRB5_FCC_NOFILE` (with the file name for a FILE or DIR cache).
    pub fn open(spec: CcSpec) -> Result<Self, Krb5Error> {
        let cc =
            crate::load_ccache(&spec).map_err(|e| crate::cache_read_error(&spec, e.as_ref()))?;
        Ok(Self { spec, cc })
    }

    /// The cache's default principal.
    #[must_use]
    pub fn principal(&self) -> Princ {
        self.cc.primary.clone()
    }

    /// MIT `cache_get` (`get_creds.c:114-133`): the first credential matching `m`.
    #[must_use]
    pub fn retrieve(&self, m: &MatchCreds<'_>) -> Option<&CcacheCred> {
        self.cc.creds.iter().find(|c| m.matches(c))
    }

    /// After [`Self::retrieve`] found nothing for `m`: for a server in the referral realm and a
    /// named client, the first credential matching it in the client's realm, the lookup traced.
    /// MIT `krb5_cc_retrieve_cred` (`lib/krb5/ccache/ccfns.c:97-111`): a lookup that finds nothing for a server in the referral realm is made again with the client's realm.
    #[must_use]
    pub fn retrieve_referral(&self, m: &MatchCreds<'_>) -> Option<&CcacheCred> {
        let client = m.client?;
        if !m.server.0.as_bytes().is_empty() {
            return None;
        }
        let server = (client.0.clone(), m.server.1.clone());
        let again = MatchCreds {
            client: m.client,
            server: &server,
            enctype: m.enctype,
            is_skey: m.is_skey,
            second_ticket: m.second_ticket,
            now: m.now,
        };
        let found = self.retrieve(&again);
        crate::trace::retrieve_ref(self, client, &server, found.is_some());
        found
    }

    /// The realm a request for a server in the referral realm starts in: the cache's
    /// `start_realm` configuration, else `client`'s realm.
    /// MIT `krb5_tkt_creds_init` (`lib/krb5/krb/get_creds.c:1143-1151`): the start realm is the cache's `start_realm` configuration, else the client's realm.
    fn start_realm(&self, client: &Princ) -> String {
        self.cc
            .get_config(None, "start_realm")
            .map_or_else(|| realm_str(&client.0), |r| String::from_utf8_lossy(r).into_owned())
    }

    /// MIT `krb5_cc_store_cred`: `cred` joins the cache now: appended to a FILE or DIR cache's
    /// file under its lock ([`krb5_protocol::fcc_store`]), one STORE to a KCM cache, the MEMORY
    /// cache replaced. A credential the store refused is not kept here either, so a later lookup
    /// in this run asks the KDC again, as MIT's would.
    /// MIT `fcc_store` (`cc_file.c:987-1026`): one append write of the record, under the file's exclusive lock; the error names the file.
    ///
    /// # Errors
    ///
    /// [`Krb5Error`] as MIT reports the store's failure: for a file, its code and text with the
    /// file name (`KRB5_FCC_NOFILE` for a file gone since it was read, the lock's errno text for
    /// a refused lock); for KCM, as [`Krb5Error::from_kcm`].
    pub fn store(&mut self, cred: CcacheCred) -> Result<(), Krb5Error> {
        crate::trace::store(&self.spec, &cred);
        let stored = match &self.spec {
            CcSpec::Kcm(n) => krb5_protocol::kcm_store_creds(n, std::slice::from_ref(&cred))
                .map_err(|e| Krb5Error::from_kcm(&e)),
            CcSpec::Memory(_) => {
                let mut cc = self.cc.clone();
                cc.creds.push(cred.clone());
                crate::store_ccache_keep_default(&self.spec, cc)
                    .map_err(|e| Krb5Error::new(Code::Other, e.to_string()))
            }
            CcSpec::File(_) | CcSpec::Dir(_) => match crate::cache_file_path(&self.spec) {
                Some(path) => krb5_protocol::fcc_store(&path, &cred)
                    .map_err(|e| Krb5Error::from_file_cache(&e, &path)),
                None => Err(Krb5Error::of(Code::FccNofile)),
            },
        };
        stored.map(|()| self.cc.creds.push(cred))
    }

    /// The `KRB5_CC_NOTFOUND` of a lookup in this cache, with the file name MIT adds for a file.
    #[must_use]
    pub fn not_found(&self) -> Krb5Error {
        match crate::cache_file_path(&self.spec) {
            Some(p) => Krb5Error::new(
                Code::CcNotfound,
                format!("Matching credential not found (filename: {})", p.display()),
            ),
            None => Krb5Error::of(Code::CcNotfound),
        }
    }

    /// The TGT to present for `srealm`: a cached `krbtgt/<srealm>`, else the local TGT, and the
    /// realm whose KDC it is for.
    fn tgt_for(&self, srealm: &str) -> Result<(CcacheCred, String), Krb5Error> {
        let creds = self.cc.list();
        let crealm = realm_str(&self.cc.primary.0);
        let local = creds
            .iter()
            .copied()
            .find(|c| c.server.1.is_krbtgt_for(&crealm))
            .or_else(|| creds.iter().copied().find(|c| c.server.1.is_krbtgt()))
            .ok_or_else(|| self.not_found())?;
        let cred = creds
            .iter()
            .copied()
            .find(|c| c.server.1.is_krbtgt_for(srealm))
            .unwrap_or(local)
            .clone();
        let hop = krb5_protocol::referral_hop_realm(&cred.server.1).unwrap_or(crealm);
        Ok((cred, hop))
    }
}

/// The KDC of `realm`.
/// MIT `k5_locate_server` (`locate_kdc.c:853-878`): a realm with no KDC is
/// `KRB5_REALM_UNKNOWN` "Cannot find KDC for realm "\<realm\>"".
///
/// # Errors
///
/// [`Krb5Error`] `KRB5_REALM_UNKNOWN` when neither `krb5.conf` nor DNS names a KDC.
pub fn kdc_for_realm(realm: &str) -> Result<KdcAddr, Krb5Error> {
    let found = krb5_config::discover_kdc(realm);
    let Some(ep) = found.first() else {
        krb5_config::clear_handed();
        return Err(Krb5Error::new(
            Code::RealmUnknown,
            format!("Cannot find KDC for realm \"{realm}\""),
        ));
    };
    let addr = KdcAddr {
        host: ep.host.clone(),
        port: ep.port,
    };
    // The send consumes this list. A second discover would repeat the SRV queries.
    krb5_config::hand_kdcs(realm, found);
    Ok(addr)
}

/// A cached credential as the TGT [`AsOutcome`] a TGS request presents.
///
/// # Errors
///
/// [`Krb5Error`] when the session key or the ticket of `cred` does not decode.
pub fn outcome_from_cred(cred: &CcacheCred) -> Result<AsOutcome, Krb5Error> {
    let session = cred
        .session_key()
        .map_err(|e| Krb5Error::new(Code::Other, e.to_string()))?;
    let ticket: Ticket =
        decode(&cred.ticket).map_err(|e| Krb5Error::new(Code::Other, e.to_string()))?;
    Ok(AsOutcome {
        ticket,
        enc_part: EncKdcRepPart {
            key: EncryptionKey {
                keytype: session.etype().to_iana(),
                keyvalue: session.as_bytes().to_vec().into(),
            },
            last_req: Vec::new(),
            nonce: 0,
            key_expiration: None,
            flags: TicketFlags::from_u32(cred.ticket_flags),
            authtime: KerberosTime::from_unix_seconds(cred.authtime),
            starttime: Some(KerberosTime::from_unix_seconds(cred.starttime)),
            endtime: KerberosTime::from_unix_seconds(cred.endtime),
            renew_till: (cred.renew_till > 0)
                .then(|| KerberosTime::from_unix_seconds(cred.renew_till)),
            srealm: cred.server.0.clone(),
            sname: cred.server.1.clone(),
            caddr: None,
            encrypted_pa_data: None,
        },
        client_key: session.clone(),
        session_key: session,
        cname: cred.client.1.clone(),
        crealm: cred.client.0.clone(),
        fast_avail: false,
        used_fast: false,
        pa_type: None,
    })
}

/// A credential for `client` from a TGS reply.
///
/// # Errors
///
/// [`Krb5Error`] when the ticket does not encode.
pub fn cred_from_tgs(client: &Princ, out: &TgsOutcome) -> Result<CcacheCred, Krb5Error> {
    tgt_cred(
        &client.0,
        &client.1,
        &out.ticket,
        &out.session_key,
        &out.enc_part,
    )
    .map_err(|e| Krb5Error::new(Code::Other, e.to_string()))
}

/// The `KRB5_GC_*` options of one `krb5_get_credentials` call.
#[derive(Clone, Debug, Default)]
pub struct GetCredsOptions {
    /// `KRB5_GC_CACHED` (`kvno --cached-only`).
    pub cached_only: bool,
    /// `KRB5_GC_NO_STORE` (`kvno --no-store`, `--out-cache`).
    pub no_store: bool,
    /// The TGS requests' options.
    pub tgs: TgsCredsOptions,
    /// The gates' KDC for the first request (`kvno <host> <service>`), in a `test-hooks` build.
    #[cfg(feature = "test-hooks")]
    pub kdc: Option<KdcAddr>,
}

impl GetCredsOptions {
    /// The KDC of `realm` for the first request.
    #[cfg_attr(
        not(feature = "test-hooks"),
        expect(
            clippy::unused_self,
            reason = "the override exists in a test-hooks build only"
        )
    )]
    fn kdc(&self, realm: &str) -> Result<KdcAddr, Krb5Error> {
        #[cfg(feature = "test-hooks")]
        if let Some(k) = &self.kdc {
            return Ok(k.clone());
        }
        kdc_for_realm(realm)
    }
}

/// MIT `krb5_get_credentials` (`get_creds.c:1309-1347`): a cached credential matching `me` and
/// `server`, else the KDC's, stored with the cross-realm TGTs it took unless `no_store`.
/// MIT `check_cache` (`get_creds.c:1042-1065`): with `cached_only`, a credential missing from the
/// cache is `KRB5_CC_NOTFOUND`.
/// MIT `complete` (`get_creds.c:468-471`): the store's failure is ignored; so is a cross-realm TGT's.
/// MIT `step_get_tgt` (`get_creds.c:952-954`): a cross-realm TGT asked for on the path is stored, its failure ignored.
/// MIT `krb5_tkt_creds_init` (`lib/krb5/krb/get_creds.c:1124-1134`): the KDC is asked for the server's first candidate name ([`CanonPrinc`]), while the cache is searched for the server as asked for.
/// MIT `krb5_tkt_creds_step` (`lib/krb5/krb/get_creds.c:1292-1305`): a request the KDC answers with an unknown server is made again for the next candidate; with none left that error stands.
/// MIT `complete` (`lib/krb5/krb/get_creds.c:458-462`): the credential is stored and returned under the server asked for.
///
/// # Errors
///
/// [`Krb5Error`] `KRB5_CC_NOTFOUND` when `cached_only` finds nothing or the cache holds no TGT;
/// the KDC's refusal or the transport failure as [`Krb5Error::from_tgs`] reports it;
/// `KRB5_CONFIG_NODEFREALM` or a malformed name when a candidate cannot be made.
pub fn get_credentials(
    cache: &mut OpenCache,
    me: &Princ,
    server: &Princ,
    opts: &GetCredsOptions,
) -> Result<CcacheCred, Krb5Error> {
    let second = opts
        .tgs
        .second_ticket
        .as_ref()
        .map(krb5_asn1::encode)
        .transpose()
        .map_err(|e| Krb5Error::new(Code::Other, e.to_string()))?;
    let now = unix_now();
    let m = MatchCreds {
        client: Some(me),
        server,
        enctype: opts.tgs.enctype,
        is_skey: second.is_some(),
        second_ticket: second.as_deref(),
        now,
    };
    crate::trace::tkt_creds_begin(cache, me, server);
    let conf = krb5_config::load_krb5_conf().unwrap_or_default();
    let mut candidates = CanonPrinc::new(&conf, server);
    let mut candidate = candidates
        .next_candidate()
        .map_err(|e| Krb5Error::from_sname(&e))?
        .ok_or_else(|| {
            let code = krb5_types::err::S_PRINCIPAL_UNKNOWN;
            Krb5Error::new(Code::Kdc(code), crate::errmsg::kdc_error_text(code))
        })?;
    let found = crate::trace::retrieved(cache, me, server, cache.retrieve(&m))
        .or_else(|| cache.retrieve_referral(&m));
    if let Some(c) = found {
        return Ok(c.clone());
    }
    if opts.cached_only {
        return Err(cache.not_found());
    }
    let start_realm = cache.start_realm(me);
    let (out, path) = loop {
        match request_service(cache, &candidate, &start_realm, opts) {
            Err(e) if e.code == Code::Kdc(krb5_types::err::S_PRINCIPAL_UNKNOWN) => match candidates
                .next_candidate()
                .map_err(|e| Krb5Error::from_sname(&e))?
            {
                Some(next) => candidate = next,
                None => return Err(e),
            },
            got => break got?,
        }
    };
    let mut cred = cred_from_tgs(me, &out)?;
    cred.server = server.clone();
    if let Some(t) = second {
        cred.is_skey = 1;
        cred.second_ticket = t;
    }
    if !opts.no_store {
        for p in path {
            let hop_cred = tgt_cred(&p.crealm, &p.cname, &p.ticket, &p.session_key, &p.enc_part)
                .map_err(|e| Krb5Error::new(Code::Other, e.to_string()))?;
            let _ = cache.store(hop_cred);
        }
        let _ = cache.store(cred.clone());
    }
    Ok(cred)
}

/// One candidate `server` asked of the KDC: a server in the referral realm in `start_realm`, as a
/// referral request; the TGT for its realm presented.
/// MIT `begin` (`lib/krb5/krb/get_creds.c:1074-1087`): a server in the referral realm takes the start realm, and the request starts with the TGT for the server's realm.
fn request_service(
    cache: &OpenCache,
    server: &Princ,
    start_realm: &str,
    opts: &GetCredsOptions,
) -> Result<(TgsOutcome, Vec<AsOutcome>), Krb5Error> {
    let mut srealm = realm_str(&server.0);
    let mut tgs = opts.tgs.clone();
    if srealm.is_empty() {
        start_realm.clone_into(&mut srealm);
        tgs.referral_realm = true;
    }
    let named = (
        krb5_types::try_ascii(&srealm).map_err(|e| Krb5Error::new(Code::Other, e.to_string()))?,
        server.1.clone(),
    );
    if tgs.referral_realm {
        crate::trace::referral_realm(&named);
    }
    crate::trace::tgt_for(cache, &srealm);
    let (presented, hop) = cache.tgt_for(&srealm)?;
    let kdc = opts.kdc(&hop)?;
    let tgt = outcome_from_cred(&presented)?;
    tgs_exchange_path(&kdc, &tgt, server.1.clone(), &srealm, &tgs)
        .map_err(|e| Krb5Error::from_tgs(&e, &hop))
}

/// MIT `krb5_get_credentials_for_user` (`s4u_creds.c:648-730`): for `for_user` to `me`'s service
/// `self_sname`, a matching cached credential, else S4U2Self from the KDC, stored unless
/// `no_store`. The enterprise realm discovery of `s4u_identify_user` is not made: the user's realm
/// is the one given or the server's.
/// MIT `krb5_get_credentials_for_user` (`s4u_creds.c:723-727`): unlike the other lookups, a store that fails is the error.
///
/// # Errors
///
/// As [`get_credentials`], and the store's failure as [`OpenCache::store`] reports it.
pub fn get_credentials_for_user(
    cache: &mut OpenCache,
    for_user: &Princ,
    self_sname: &Princ,
    opts: &GetCredsOptions,
) -> Result<CcacheCred, Krb5Error> {
    let m = MatchCreds {
        client: Some(for_user),
        server: self_sname,
        enctype: opts.tgs.enctype,
        is_skey: false,
        second_ticket: None,
        now: unix_now(),
    };
    crate::trace::tkt_creds_begin(cache, for_user, self_sname);
    if let Some(c) = crate::trace::retrieved(cache, for_user, self_sname, cache.retrieve(&m)) {
        return Ok(c.clone());
    }
    if opts.cached_only {
        return Err(cache.not_found());
    }
    let srealm = realm_str(&self_sname.0);
    crate::trace::tgt_creds(cache, &srealm);
    let (presented, hop) = cache.tgt_for(&srealm)?;
    let kdc = opts.kdc(&hop)?;
    let tgt = outcome_from_cred(&presented)?;
    let out = tgs_s4u(
        &kdc,
        &tgt,
        self_sname.1.clone(),
        &hop,
        &for_user.1,
        &realm_str(&for_user.0),
    )
    .map_err(|e| Krb5Error::from_tgs(&e, &hop))?;
    let cred = cred_from_tgs(for_user, &out)?;
    if !opts.no_store {
        cache.store(cred.clone())?;
    }
    Ok(cred)
}

/// MIT `krb5_get_credentials_for_proxy` (`s4u_creds.c:1201-1260`): S4U2Proxy for `client` (the
/// evidence ticket's) to `server`, cached if a credential with that evidence is, stored unless
/// `no_store`.
/// MIT `k5_get_proxy_cred_from_kdc` (`s4u_creds.c:1179-1188`): the KDC's credential is stored
/// under the server asked for, a failed store ignored.
/// MIT `kdcrep2creds` (`gc_via_tkt.c:64-74`): its client is the reply's, and it keeps the evidence
/// ticket as its second ticket.
/// MIT `krb5_get_credentials_for_proxy` (`s4u_creds.c:1248-1252`): a client other than the
/// evidence ticket's is `KRB5_KDCREP_MODIFIED`.
///
/// # Errors
///
/// [`Krb5Error`] `KRB5_CC_NOTFOUND` when the cache holds no TGT; the KDC's refusal or the
/// transport failure as [`Krb5Error::from_tgs`] reports it; `KRB5_KDCREP_MODIFIED` when the
/// credential's client is not `client`.
pub fn get_credentials_for_proxy(
    cache: &mut OpenCache,
    client: &Princ,
    server: &Princ,
    evidence: &CcacheCred,
    opts: &GetCredsOptions,
) -> Result<CcacheCred, Krb5Error> {
    let m = MatchCreds {
        client: None,
        server,
        enctype: opts.tgs.enctype,
        is_skey: false,
        second_ticket: Some(&evidence.ticket),
        now: unix_now(),
    };
    if krb5_protocol::trace::enabled() {
        crate::trace::proxy_lookup(
            cache,
            server,
            cache.retrieve(&m).is_some(),
            &realm_str(&server.0),
        );
    }
    let cred = if let Some(c) = cache.retrieve(&m) {
        c.clone()
    } else {
        let srealm = realm_str(&server.0);
        let (presented, hop) = cache.tgt_for(&srealm)?;
        let kdc = opts.kdc(&hop)?;
        let tgt = outcome_from_cred(&presented)?;
        let ticket: Ticket =
            decode(&evidence.ticket).map_err(|e| Krb5Error::new(Code::Other, e.to_string()))?;
        let out = tgs_s4u2proxy(&kdc, &tgt, server.1.clone(), &hop, ticket)
            .map_err(|e| Krb5Error::from_tgs(&e, &hop))?;
        let mut cred = cred_from_tgs(&(out.crealm.clone(), out.cname.clone()), &out)?;
        cred.server = server.clone();
        cred.second_ticket.clone_from(&evidence.ticket);
        if !opts.no_store {
            let _ = cache.store(cred.clone());
        }
        cred
    };
    if !princ_eq(&cred.client, client) {
        return Err(Krb5Error::of(Code::KdcrepModified));
    }
    Ok(cred)
}

/// The renewed (or validated) credential for `client` in `cache`: `kinit -R` / `kinit -v`.
/// MIT `get_valrenewed_creds` (`val_renew.c:136-179`): the server is `in_tkt_service` in the
/// client's realm, else `krbtgt/<client realm>`.
/// MIT `get_new_creds` (`val_renew.c:47-74`): the cache's credential for that client and server,
/// whatever its times, is presented to the KDC of its server's realm.
///
/// # Errors
///
/// [`Krb5Error`] when the cache cannot be read, holds no credential for that client and server
/// (`KRB5_CC_NOTFOUND`, with the file name for a file cache), or the KDC refuses or cannot be
/// reached.
pub fn get_valrenewed_creds(
    spec: &CcSpec,
    client: &Princ,
    service: Option<&str>,
    validate: bool,
) -> Result<CcacheCred, Krb5Error> {
    let server = match service {
        Some(s) => {
            let (_, name) = parse_name(s, false)?;
            (client.0.clone(), name)
        }
        None => (
            client.0.clone(),
            PrincipalName::krbtgt(&realm_str(&client.0)),
        ),
    };
    let cache = OpenCache::open(spec.clone())?;
    let old = cache.cc.creds.iter().find(|c| {
        !c.is_config()
            && !c.is_removed()
            && princ_eq(&c.client, client)
            && princ_eq(&c.server, &server)
    });
    // MIT `get_new_creds` (`val_renew.c:47-74`): the cache lookup is traced with its result.
    let old =
        crate::trace::retrieved(&cache, client, &server, old).ok_or_else(|| cache.not_found())?;
    let realm = realm_str(&old.server.0);
    let kdc = kdc_for_realm(&realm)?;
    let tgt = outcome_from_cred(old)?;
    let out = if validate {
        krb5_protocol::tgs_validate(&kdc, &tgt)
    } else {
        krb5_protocol::tgs_renew(&kdc, &tgt)
    }
    .map_err(|e| Krb5Error::from_tgs(&e, &realm))?;
    cred_from_tgs(client, &out)
}

/// MIT `get_u2u_ticket` (`kvno.c:414-450`): the local TGT of the cache `spec`'s principal, its
/// ticket taken from the cache only.
///
/// # Errors
///
/// [`Krb5Error`] when the cache cannot be read or holds no `krbtgt/<realm>@<realm>`.
pub fn get_u2u_ticket(spec: CcSpec) -> Result<Ticket, Krb5Error> {
    let cache = OpenCache::open(spec)?;
    let me = cache.principal();
    let tgs = (me.0.clone(), PrincipalName::krbtgt(&realm_str(&me.0)));
    let m = MatchCreds {
        client: Some(&me),
        server: &tgs,
        enctype: None,
        is_skey: false,
        second_ticket: None,
        now: unix_now(),
    };
    let cred = cache.retrieve(&m).ok_or_else(|| cache.not_found())?;
    decode(&cred.ticket).map_err(|e| Krb5Error::new(Code::Other, e.to_string()))
}

/// MIT `krb5_server_decrypt_ticket_keytab` (`srv_dec_tkt.c:73-139`): `ticket` decrypts under a
/// keytab key of its enctype; none doing so is `KRB5KRB_AP_WRONG_PRINC`.
/// MIT `decrypt_ticket_keyblock` (`srv_dec_tkt.c:43-70`): a ticket with the invalid flag set is
/// `KRB5KRB_AP_ERR_TKT_INVALID`. The transited-path check of a cross-realm ticket is not made.
///
/// # Errors
///
/// [`Krb5Error`] `ENOENT` "Key table file '\<path\>' not found" for a missing keytab,
/// `KRB5KRB_AP_WRONG_PRINC` when no entry decrypts the ticket, `KRB5KRB_AP_ERR_TKT_INVALID` for a
/// postdated ticket not yet validated, or the read error of an unreadable keytab.
pub fn server_decrypt_ticket_keytab(keytab: &str, ticket: &Ticket) -> Result<(), Krb5Error> {
    let crate::KeytabName::File(path) = crate::kt_resolve(keytab)? else {
        return Err(Krb5Error::of(Code::WrongPrinc));
    };
    let bytes = krb5_protocol::read_secret_file(&path)
        .map_err(|e| crate::keytab_read_error(&e, &path.display().to_string()))?;
    let kt = Keytab::parse(&bytes).map_err(|e| Krb5Error::new(Code::Other, e.to_string()))?;
    let usage =
        KeyUsage::new(ku::TICKET).map_err(|e| Krb5Error::new(Code::Other, e.to_string()))?;
    for entry in &kt.entries {
        if entry.key.etype().to_iana() != ticket.enc_part.etype {
            continue;
        }
        let Some(part) = decrypt_ticket(&entry.key, usage, ticket) else {
            continue;
        };
        if part.flags.invalid() {
            return Err(Krb5Error::of(Code::TktInvalid));
        }
        return Ok(());
    }
    Err(Krb5Error::of(Code::WrongPrinc))
}

fn decrypt_ticket(key: &ProtocolKey, usage: KeyUsage, ticket: &Ticket) -> Option<EncTicketPart> {
    let plain = decrypt(key, usage, ticket.enc_part.cipher.as_ref()).ok()?;
    decode(&plain).ok()
}

/// MIT `krb5_string_to_enctype`: an enctype name or number; anything else is `EINVAL`.
///
/// # Errors
///
/// [`Krb5Error`] `EINVAL` for a name no enctype has.
pub fn string_to_enctype(name: &str) -> Result<i32, Krb5Error> {
    EncryptionType::from_mit_name(name)
        .map(EncryptionType::to_iana)
        .map_err(|_| Krb5Error::of(Code::Einval))
}

/// Now as a Unix time.
#[must_use]
pub fn unix_now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_protocol::{CcacheKeyblock, realm};

    fn cred(server: &str, end: u32, skey: u8, etype: i16) -> CcacheCred {
        CcacheCred {
            client: (
                realm("KERBER.TEST"),
                PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["alice"]),
            ),
            server: (
                realm("KERBER.TEST"),
                PrincipalName::new(PrincipalName::NT_PRINCIPAL, server.split('/')),
            ),
            key: CcacheKeyblock {
                etype,
                contents: vec![0; 16],
            },
            authtime: 1,
            starttime: 1,
            endtime: end,
            renew_till: 0,
            is_skey: skey,
            ticket_flags: 0,
            addresses: Vec::new(),
            authdata: Vec::new(),
            ticket: vec![1],
            second_ticket: if skey == 1 { vec![9] } else { Vec::new() },
        }
    }

    /// MIT `krb5int_cc_creds_match_request`: live MIT `kvno --cached-only` finds the cached
    /// ticket and reports a missing one; a user-to-user ticket answers only a `--u2u` request.
    #[test]
    fn retrieve_matches_server_time_enctype_and_u2u() {
        let me = (
            realm("KERBER.TEST"),
            PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["alice"]),
        );
        let host = (
            realm("KERBER.TEST"),
            PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "x"]),
        );
        let cache = OpenCache {
            spec: CcSpec::Memory("t".into()),
            cc: FileCcache::new(
                me.clone(),
                vec![cred("host/x", 50, 1, 18), cred("host/x", 100, 0, 18)],
            ),
        };
        let m = |now, enctype, second: Option<&'static [u8]>| MatchCreds {
            client: Some(&me),
            server: &host,
            enctype,
            is_skey: second.is_some(),
            second_ticket: second,
            now,
        };
        assert_eq!(
            cache.retrieve(&m(10, None, None)).map(|c| c.endtime),
            Some(100)
        );
        assert_eq!(
            cache.retrieve(&m(10, None, Some(&[9]))).map(|c| c.endtime),
            Some(50)
        );
        assert!(cache.retrieve(&m(10, None, Some(&[8]))).is_none());
        assert!(cache.retrieve(&m(101, None, None)).is_none());
        assert!(cache.retrieve(&m(10, Some(17), None)).is_none());
        assert_eq!(cache.not_found().message, "Matching credential not found");
    }

    /// MIT `construct_matching_creds`: an S4U2Proxy lookup asks for the evidence ticket as the
    /// second ticket, so the S4U2Self ticket that is the evidence does not answer it (live MIT
    /// `kvno -U user -P` sends the S4U2Proxy request), while a proxy ticket with that evidence does.
    #[test]
    fn s4u2proxy_lookup_matches_the_evidence_not_the_client() {
        let me = (
            realm("KERBER.TEST"),
            PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["alice"]),
        );
        let host = (
            realm("KERBER.TEST"),
            PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "x"]),
        );
        let evidence = cred("host/x", 100, 0, 18);
        let mut proxied = cred("host/x", 90, 0, 18);
        proxied.second_ticket.clone_from(&evidence.ticket);
        let m = MatchCreds {
            client: None,
            server: &host,
            enctype: None,
            is_skey: false,
            second_ticket: Some(&evidence.ticket),
            now: 10,
        };
        let only_evidence = OpenCache {
            spec: CcSpec::Memory("t".into()),
            cc: FileCcache::new(me.clone(), vec![evidence.clone()]),
        };
        assert!(only_evidence.retrieve(&m).is_none());
        let both = OpenCache {
            spec: CcSpec::Memory("t".into()),
            cc: FileCcache::new(me, vec![evidence.clone(), proxied]),
        };
        assert_eq!(both.retrieve(&m).map(|c| c.endtime), Some(90));
    }

    /// MIT `fcc_store`: a stored credential is appended to the FILE cache, the bytes already
    /// there kept as they were; a store into a file gone since it was read fails naming it, and
    /// the credential is not kept.
    #[test]
    fn store_appends_to_a_file_cache_and_names_a_file_gone_since() {
        let me = (
            realm("KERBER.TEST"),
            PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["alice"]),
        );
        let dir = krb5_testkit::scratch_dir("krb5-client-store");
        let path = dir.join("cc");
        FileCcache::new(me, vec![cred("host/x", 100, 0, 18)])
            .write_file(&path)
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        let mut cache = OpenCache::open(CcSpec::File(path.clone())).unwrap();
        cache.store(cred("host/y", 100, 0, 18)).unwrap();
        let after = std::fs::read(&path).unwrap();
        assert_eq!(&after[..before.len()], before.as_slice());
        assert_eq!(FileCcache::parse(&after).unwrap().creds.len(), 2);
        assert_eq!(cache.cc.creds.len(), 2);
        std::fs::remove_file(&path).unwrap();
        let e = cache.store(cred("host/z", 100, 0, 18)).unwrap_err();
        assert_eq!(e.code, Code::FccNofile);
        assert_eq!(
            e.message,
            format!("No credentials cache found (filename: {})", path.display())
        );
        assert_eq!(cache.cc.creds.len(), 2);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// MIT `krb5_cc_retrieve_cred` (`lib/krb5/ccache/ccfns.c:97-111`): a lookup that finds nothing for a server in the referral realm is made again with the client's realm.
    /// MIT `krb5_tkt_creds_init` (`lib/krb5/krb/get_creds.c:1143-1151`): the start realm is the cache's `start_realm` configuration, else the client's realm.
    #[test]
    fn a_server_in_the_referral_realm_is_looked_up_in_the_clients_realm() {
        let me = (
            realm("KERBER.TEST"),
            PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["alice"]),
        );
        let referral = (
            realm(""),
            PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "x"]),
        );
        let mut cache = OpenCache {
            spec: CcSpec::Memory("t".into()),
            cc: FileCcache::new(me.clone(), vec![cred("host/x", 100, 0, 18)]),
        };
        let m = |client| MatchCreds {
            client,
            server: &referral,
            enctype: None,
            is_skey: false,
            second_ticket: None,
            now: 10,
        };
        assert!(cache.retrieve(&m(Some(&me))).is_none());
        assert_eq!(
            cache.retrieve_referral(&m(Some(&me))).map(|c| c.endtime),
            Some(100)
        );
        assert!(cache.retrieve_referral(&m(None)).is_none());
        let other = (realm("OTHER.TEST"), referral.1.clone());
        let named = MatchCreds {
            server: &other,
            ..m(Some(&me))
        };
        assert!(cache.retrieve_referral(&named).is_none());
        assert_eq!(cache.start_realm(&me), "KERBER.TEST");
        cache.cc.set_config(None, "start_realm", b"OTHER.TEST");
        assert_eq!(cache.start_realm(&me), "OTHER.TEST");
    }

    /// Live MIT 1.22.2 `kvno -e bogus-etype`: "Invalid argument while converting etype".
    #[test]
    fn string_to_enctype_is_einval_for_an_unknown_name() {
        assert_eq!(string_to_enctype("aes128-cts-hmac-sha1-96").ok(), Some(17));
        assert_eq!(string_to_enctype("18").ok(), Some(18));
        assert_eq!(
            string_to_enctype("bogus-etype").unwrap_err().message,
            "Invalid argument"
        );
    }
}
