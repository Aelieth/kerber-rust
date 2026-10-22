use krb5_asn1::decode;
use krb5_config::{CanonPrinc, CcSpec, ClientContext, Krb5Conf};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt_enc_data};
use krb5_protocol::{
    AsOutcome, AsRequest, AsTicketOpts, CcacheCred, FileCcache, IdentifyReply, KdcAddr, Keytab,
    TgsCredsOptions, TgsOutcome, as_identify_realm, tgs_exchange_path, tgs_s4u, tgs_s4u2proxy,
    tgt_cred,
};
use krb5_types::{
    EncKdcRepPart, EncTicketPart, EncryptionKey, KerberosTime, PrincipalName, Realm, Ticket,
    TicketFlags, ku,
};

use crate::errmsg::{Code, Krb5Error};

pub type Princ = (Realm, PrincipalName);

#[must_use]
pub fn princ_eq(a: &Princ, b: &Princ) -> bool {
    a.0.as_bytes() == b.0.as_bytes() && a.1.name_string == b.1.name_string
}

#[must_use]
pub fn unparse(p: &Princ) -> String {
    p.1.unparse_with_realm(&realm_str(&p.0))
}

fn realm_str(r: &Realm) -> String {
    String::from_utf8_lossy(r.as_bytes()).into_owned()
}

#[must_use]
pub fn default_realm(ctx: &ClientContext) -> Option<String> {
    ctx.profile.default_realm.clone()
}

pub fn parse_name(ctx: &ClientContext, name: &str, enterprise: bool) -> Result<Princ, Krb5Error> {
    let p = krb5_types::parse_name_ex(name, "", enterprise)
        .map_err(|_| Krb5Error::of(Code::ParseMalformed))?;
    let realm = if p.has_realm {
        p.realm
    } else {
        default_realm(ctx).ok_or_else(|| Krb5Error::of(Code::NoDefRealm))?
    };
    let (n, _) = krb5_types::principal_from_unparsed_ex(name, &realm, enterprise)
        .map_err(|_| Krb5Error::of(Code::ParseMalformed))?;
    Ok((krb5_protocol::realm(&realm), n))
}

// MIT `construct_matching_creds` (`get_creds.c:52-108`): the client and server, still valid,
pub struct MatchCreds<'a> {
    pub client: Option<&'a Princ>,
    pub server: &'a Princ,
    pub enctype: Option<i32>,
    pub is_skey: bool,
    pub second_ticket: Option<&'a [u8]>,
    pub now: u32,
}

impl MatchCreds<'_> {
    // MIT `krb5int_cc_creds_match_request` (`cc_retr.c:151-191`): a user-to-user credential
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

pub struct OpenCache<'c> {
    pub ctx: &'c ClientContext,
    pub spec: CcSpec,
    pub cc: FileCcache,
}

impl<'c> OpenCache<'c> {
    pub fn open(ctx: &'c ClientContext, spec: CcSpec) -> Result<Self, Krb5Error> {
        let cc = crate::load_ccache(ctx, &spec)
            .map_err(|e| crate::cache_read_error(ctx, &spec, e.as_ref()))?;
        Ok(Self { ctx, spec, cc })
    }

    #[must_use]
    pub fn principal(&self) -> Princ {
        self.cc.primary.clone()
    }

    // MIT `cache_get` (`get_creds.c:114-133`): the first credential matching `m`.
    #[must_use]
    pub fn retrieve(&self, m: &MatchCreds<'_>) -> Option<&CcacheCred> {
        self.cc.creds.iter().find(|c| m.matches(c))
    }

    // MIT `krb5_cc_retrieve_cred` (`lib/krb5/ccache/ccfns.c:97-111`): a lookup that finds nothing for a server in the referral realm is made again with the client's realm.
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

    // MIT `krb5_tkt_creds_init` (`lib/krb5/krb/get_creds.c:1143-1151`): the start realm is the cache's `start_realm` configuration, else the client's realm.
    fn start_realm(&self, client: &Princ) -> String {
        self.cc.get_config(None, "start_realm").map_or_else(
            || realm_str(&client.0),
            |r| String::from_utf8_lossy(r).into_owned(),
        )
    }

    // MIT `fcc_store` (`cc_file.c:987-1026`): one append write of the record, under the file's exclusive lock; the error names the file.
    pub fn store(&mut self, cred: CcacheCred) -> Result<(), Krb5Error> {
        crate::trace::store(self.ctx, &self.spec, &cred);
        let stored = match &self.spec {
            CcSpec::Kcm(n) => {
                krb5_protocol::kcm_store_creds(&self.ctx.profile, n, std::slice::from_ref(&cred))
                    .map_err(|e| Krb5Error::from_kcm(&e))
            }
            CcSpec::Memory(_) => {
                let mut cc = self.cc.clone();
                cc.creds.push(cred.clone());
                crate::store_ccache_keep_default(self.ctx, &self.spec, cc)
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

// MIT `k5_locate_server` (`locate_kdc.c:853-878`): a realm with no KDC is
pub fn kdc_for_realm(profile: &Krb5Conf, realm: &str) -> Result<KdcAddr, Krb5Error> {
    let found = profile.kdcs_for(realm).unwrap_or_default();
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
    krb5_config::hand_kdcs(realm, found);
    Ok(addr)
}

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
        pa_config: None,
    })
}

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

#[derive(Clone, Debug, Default)]
pub struct GetCredsOptions {
    pub cached_only: bool,
    pub no_store: bool,
    pub tgs: TgsCredsOptions,
    #[cfg(feature = "test-hooks")]
    pub kdc: Option<KdcAddr>,
}

impl GetCredsOptions {
    #[cfg_attr(
        not(feature = "test-hooks"),
        expect(
            clippy::unused_self,
            reason = "the override exists in a test-hooks build only"
        )
    )]
    fn kdc(&self, profile: &Krb5Conf, realm: &str) -> Result<KdcAddr, Krb5Error> {
        #[cfg(feature = "test-hooks")]
        if let Some(k) = &self.kdc {
            return Ok(k.clone());
        }
        kdc_for_realm(profile, realm)
    }
}

// MIT krb5_get_credentials; see docs/parity/b1-client.md
// MIT `check_cache` (`get_creds.c:1042-1065`): with `cached_only`, a credential missing from the
// MIT `complete` (`get_creds.c:468-471`): the store's failure is ignored; so is a cross-realm TGT's.
// MIT `step_get_tgt` (`get_creds.c:952-954`): a cross-realm TGT asked for on the path is stored, its failure ignored.
// MIT `krb5_tkt_creds_step` (`lib/krb5/krb/get_creds.c:1292-1305`): a request the KDC answers with an unknown server is made again for the next candidate; with none left that error stands.
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
    let ctx = cache.ctx;
    let mut candidates = CanonPrinc::new(&ctx.profile, server);
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

// MIT `begin` (`lib/krb5/krb/get_creds.c:1074-1087`): a server in the referral realm takes the start realm, and the request starts with the TGT for the server's realm.
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
    let kdc = opts.kdc(&cache.ctx.profile, &hop)?;
    let tgt = outcome_from_cred(&presented)?;
    tgs_exchange_path(
        &cache.ctx.profile,
        &kdc,
        &tgt,
        server.1.clone(),
        &srealm,
        &tgs,
    )
    .map_err(|e| Krb5Error::from_tgs(&e, &hop))
}

// MIT krb5_get_credentials_for_user; see docs/parity/b1-client.md
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
    let user = s4u_identify_user(&cache.ctx.profile, for_user, self_sname, opts)?;
    if for_user.1.name_type == PrincipalName::NT_ENTERPRISE {
        crate::trace::tkt_creds_begin(cache, &user, self_sname);
        let identified = MatchCreds {
            client: Some(&user),
            server: self_sname,
            enctype: opts.tgs.enctype,
            is_skey: false,
            second_ticket: None,
            now: unix_now(),
        };
        if let Some(c) =
            crate::trace::retrieved(cache, &user, self_sname, cache.retrieve(&identified))
        {
            return Ok(c.clone());
        }
    }
    let srealm = realm_str(&self_sname.0);
    crate::trace::tgt_creds(cache, &srealm);
    let (presented, hop) = cache.tgt_for(&srealm)?;
    let kdc = opts.kdc(&cache.ctx.profile, &hop)?;
    let tgt = outcome_from_cred(&presented)?;
    let out = tgs_s4u(
        &cache.ctx.profile,
        &kdc,
        &tgt,
        self_sname.1.clone(),
        &hop,
        &for_user.1,
        &realm_str(&user.0),
    )
    .map_err(|e| Krb5Error::from_tgs(&e, &hop))?;
    let client = (out.crealm.clone(), out.cname.clone());
    let cred = cred_from_tgs(&client, &out)?;
    if !princ_eq(&client, for_user) {
        crate::trace::tkt_creds_begin(cache, &client, self_sname);
        let replied = MatchCreds {
            client: Some(&client),
            server: self_sname,
            enctype: opts.tgs.enctype,
            is_skey: false,
            second_ticket: None,
            now: unix_now(),
        };
        if let Some(c) =
            crate::trace::retrieved(cache, &client, self_sname, cache.retrieve(&replied))
        {
            return Ok(c.clone());
        }
    }
    if !opts.no_store {
        cache.store(cred.clone())?;
    }
    Ok(cred)
}

fn s4u_identify_user(
    profile: &Krb5Conf,
    user: &Princ,
    server: &Princ,
    opts: &GetCredsOptions,
) -> Result<Princ, Krb5Error> {
    if user.1.name_type != PrincipalName::NT_ENTERPRISE {
        let anonymous = user.0.as_bytes() == b"WELLKNOWN:ANONYMOUS"
            && user
                .1
                .name_string
                .iter()
                .map(krb5_types::KerberosString::as_bytes)
                .eq([&b"WELLKNOWN"[..], &b"ANONYMOUS"[..]]);
        return Ok(if anonymous { server } else { user }.clone());
    }
    identify_realm(profile, &user.1, &realm_str(&server.0), opts)
}

// MIT `k5_identify_realm` (`lib/krb5/krb/get_in_tkt.c:2062-2083`): the request asks for a 15-second ticket, neither renewable nor forwardable nor proxiable, canonicalized, and the realm it ends in is the client's.
// MIT init_creds_step_request; see docs/parity/b1-client-preauth.md
fn identify_realm(
    profile: &Krb5Conf,
    client: &PrincipalName,
    realm: &str,
    opts: &GetCredsOptions,
) -> Result<Princ, Krb5Error> {
    let etypes = krb5_protocol::conf_etypes(profile, false);
    let mut realm = realm.to_owned();
    crate::trace::init_creds(client, &realm, None);
    for _ in 0..16 {
        let kdc = opts.kdc(profile, &realm)?;
        let req = AsRequest {
            cname: client.clone(),
            realm: &realm,
            password: b"",
            kdc: &kdc,
            profile,
            want_spake: false,
            fast_armor: None,
            pkinit: None,
            canonicalize: true,
            sname: None,
            etypes: Some(&etypes),
            ticket: AsTicketOpts {
                lifetime: Some(15),
                forwardable: false,
                proxiable: false,
                ..AsTicketOpts::default()
            },
        };
        match as_identify_realm(&req) {
            Ok(IdentifyReply::Here) => {
                let r = krb5_types::try_ascii(&realm)
                    .map_err(|e| Krb5Error::new(Code::Other, e.to_string()))?;
                return Ok((r, client.clone()));
            }
            Ok(IdentifyReply::Referral(next)) => realm = next,
            Err(e) => {
                return Err(Krb5Error::from_as(
                    &e,
                    &client.unparse_with_realm(&realm),
                    &realm,
                ));
            }
        }
    }
    Err(Krb5Error::new(
        Code::Other,
        "Looping detected inside krb5_get_in_tkt",
    ))
}

// MIT `krb5_get_credentials_for_proxy` (`s4u_creds.c:1201-1260`): S4U2Proxy for `client` (the
// MIT `k5_get_proxy_cred_from_kdc` (`s4u_creds.c:1179-1188`): the KDC's credential is stored
// MIT `kdcrep2creds` (`gc_via_tkt.c:64-74`): its client is the reply's, and it keeps the evidence
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
        let kdc = opts.kdc(&cache.ctx.profile, &hop)?;
        let tgt = outcome_from_cred(&presented)?;
        let ticket: Ticket =
            decode(&evidence.ticket).map_err(|e| Krb5Error::new(Code::Other, e.to_string()))?;
        let out = tgs_s4u2proxy(
            &cache.ctx.profile,
            &kdc,
            &tgt,
            server.1.clone(),
            &hop,
            ticket,
        )
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

// MIT `get_valrenewed_creds` (`val_renew.c:136-179`): the server is `in_tkt_service` in the
// MIT `get_new_creds` (`val_renew.c:47-74`): the cache's credential for that client and server,
pub fn get_valrenewed_creds(
    ctx: &ClientContext,
    spec: &CcSpec,
    client: &Princ,
    service: Option<&str>,
    validate: bool,
) -> Result<CcacheCred, Krb5Error> {
    let server = match service {
        Some(s) => {
            let (_, name) = parse_name(ctx, s, false)?;
            (client.0.clone(), name)
        }
        None => (
            client.0.clone(),
            PrincipalName::krbtgt(&realm_str(&client.0)),
        ),
    };
    let cache = OpenCache::open(ctx, spec.clone())?;
    let old = cache.cc.creds.iter().find(|c| {
        !c.is_config()
            && !c.is_removed()
            && princ_eq(&c.client, client)
            && princ_eq(&c.server, &server)
    });
    let old =
        crate::trace::retrieved(&cache, client, &server, old).ok_or_else(|| cache.not_found())?;
    let realm = realm_str(&old.server.0);
    let kdc = kdc_for_realm(&ctx.profile, &realm)?;
    let tgt = outcome_from_cred(old)?;
    let out = if validate {
        krb5_protocol::tgs_validate(&ctx.profile, &kdc, &tgt)
    } else {
        krb5_protocol::tgs_renew(&ctx.profile, &kdc, &tgt)
    }
    .map_err(|e| Krb5Error::from_tgs(&e, &realm))?;
    cred_from_tgs(client, &out)
}

// MIT `get_u2u_ticket` (`kvno.c:414-450`): the local TGT of the cache `spec`'s principal, its
pub fn get_u2u_ticket(ctx: &ClientContext, spec: CcSpec) -> Result<Ticket, Krb5Error> {
    let cache = OpenCache::open(ctx, spec)?;
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

// MIT `krb5_server_decrypt_ticket_keytab` (`srv_dec_tkt.c:73-139`): `ticket` decrypts under a
// MIT `decrypt_ticket_keyblock` (`srv_dec_tkt.c:43-70`): a ticket with the invalid flag set is
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
    let plain = decrypt_enc_data(
        key,
        usage,
        ticket.enc_part.etype,
        ticket.enc_part.cipher.as_ref(),
    )
    .ok()?;
    decode(&plain).ok()
}

pub fn string_to_enctype(name: &str) -> Result<i32, Krb5Error> {
    EncryptionType::from_mit_name(name)
        .map(EncryptionType::to_iana)
        .map_err(|_| Krb5Error::of(Code::Einval))
}

#[must_use]
pub fn unix_now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX))
}
