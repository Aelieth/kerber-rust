//! The client tools' halves of MIT's trace points ([`krb5_protocol::trace`]): cache names as MIT
//! prints them, and the cache reads and writes of a credentials request.

use krb5_config::CcSpec;
use krb5_protocol::{CcacheCred, trace};
use krb5_types::PrincipalName;

use crate::creds::{OpenCache, Princ};

/// MIT `krb5_cc_get_type` and `krb5_cc_get_name` as `{ccache}` prints them: `TYPE:name`, a DIR
/// collection's cache as `DIR::<file>`, the default KCM cache under its primary's name.
#[must_use]
pub fn ccname(spec: &CcSpec) -> String {
    match spec {
        CcSpec::File(p) => format!("FILE:{}", p.display()),
        CcSpec::Dir(r) if r.starts_with(':') => format!("DIR:{r}"),
        CcSpec::Dir(r) => crate::dir_read_path(r)
            .map_or_else(|_| format!("DIR:{r}"), |p| format!("DIR::{}", p.display())),
        CcSpec::Memory(n) => format!("MEMORY:{n}"),
        CcSpec::Kcm(n) if n.is_empty() => format!(
            "KCM:{}",
            krb5_protocol::kcm_primary_name().unwrap_or_default()
        ),
        CcSpec::Kcm(n) => format!("KCM:{n}"),
    }
}

/// A cache principal as the trace prints it.
#[must_use]
pub fn princ(p: &Princ) -> trace::Princ<'_> {
    trace::Princ::new(&p.1, p.0.as_bytes())
}

/// MIT `krb5_init_creds_init` (`lib/krb5/krb/get_in_tkt.c:850-1054`): an initial-credentials
/// request is traced with its client.
/// MIT `krb5_init_creds_set_service` (`lib/krb5/krb/get_in_tkt.c:1055-1071`): then its service, when
/// it names one.
pub fn init_creds(cname: &PrincipalName, realm: &str, service: Option<&str>) {
    trace::init_creds(trace::Princ::new(cname, realm.as_bytes()));
    if let Some(s) = service {
        trace::init_creds_service(s);
    }
}

/// MIT `krb5_init_creds_set_keytab` (`lib/krb5/krb/gic_keytab.c:176-232`): a keytab whose
/// entries cannot be listed is traced, as `errno` with the keytab's message.
pub fn keytab_lookup_failed(e: &std::io::Error, path: &std::path::Path) {
    if !trace::enabled() {
        return;
    }
    let code = i64::from(e.raw_os_error().unwrap_or_default());
    let msg = (e.kind() == std::io::ErrorKind::NotFound)
        .then(|| format!("Key table file '{}' not found", path.display()));
    trace::init_creds_keytab_lookup_failed(code, msg.as_deref());
}

/// MIT `krb5int_fast_as_armor` (`lib/krb5/krb/fast.c:171-221`): the armor cache is named, its
/// `fast_avail` entry for the realm's TGS read, and FAST chosen when it is there.
/// MIT `fast_armor_ap_request` (`lib/krb5/krb/fast.c:52-108`): the armor TGT is then got from that
/// cache as a credentials request.
pub fn fast_armor(spec: &CcSpec, realm: &str, armor: &krb5_protocol::FastArmor) {
    if !trace::enabled() {
        return;
    }
    // A FILE armor name stays the residual path already traced for `-T FILE:`.
    let traced = match spec {
        CcSpec::File(p) => p.display().to_string(),
        other => ccname(other),
    };
    trace::fast_armor_ccache(&traced);
    let Ok(cache) = OpenCache::open(spec.clone()) else {
        return;
    };
    let name = ccname(&cache.spec);
    let tgs = PrincipalName::krbtgt(realm);
    let tgs_name = tgs.unparse_with_realm(realm);
    let avail = cache.cc.creds.iter().find(|c| {
        c.is_config()
            && c.server.1.name_string.len() == 3
            && c.server.1.name_string[1].as_bytes() == b"fast_avail"
            && c.server.1.name_string[2].as_bytes() == tgs_name.as_bytes()
    });
    trace::get_config(
        &name,
        princ(&cache.principal()),
        Some(&tgs_name),
        "fast_avail",
        avail.map(|c| c.ticket.as_slice()),
        &cache.not_found().message,
    );
    if avail.is_some() {
        trace::fast_ccache_config();
    }
    let me = (armor.crealm.clone(), armor.cname.clone());
    let server = (krb5_protocol::realm(realm), tgs);
    tkt_creds_begin(&cache, &me, &server);
    retrieve(&cache, Some(&me), &server, true);
}

/// MIT `krb5_tkt_creds_init` (`lib/krb5/krb/get_creds.c:1094-1162`): a credentials request is
/// traced with its client, server and cache, then reads the cache's start realm.
pub fn tkt_creds_begin(cache: &OpenCache, me: &Princ, server: &Princ) {
    if !trace::enabled() {
        return;
    }
    let name = ccname(&cache.spec);
    trace::tkt_creds(princ(me), princ(server), &name);
    let start_realm = cache.cc.creds.iter().find(|c| {
        c.is_config()
            && c.server.1.name_string.len() == 2
            && c.server.1.name_string[1].as_bytes() == b"start_realm"
    });
    trace::get_config(
        &name,
        princ(&cache.principal()),
        None,
        "start_realm",
        start_realm.map(|c| c.ticket.as_slice()),
        &cache.not_found().message,
    );
}

/// MIT `krb5_cc_retrieve_cred` (`lib/krb5/ccache/ccfns.c:86-112`): a cache lookup is traced with
/// its result, the cache's own message for a credential it does not hold; no client is a lookup
/// that matches any.
pub fn retrieve(cache: &OpenCache, client: Option<&Princ>, server: &Princ, found: bool) {
    if !trace::enabled() {
        return;
    }
    let msg = cache.not_found().message;
    let (code, msg) = if found {
        (0, None)
    } else {
        (trace::KRB5_CC_NOTFOUND, Some(msg.as_str()))
    };
    trace::cc_retrieve(
        &ccname(&cache.spec),
        client.map(princ),
        princ(server),
        code,
        msg,
    );
}

/// MIT `krb5_cc_retrieve_cred` (`lib/krb5/ccache/ccfns.c:103-110`): the lookup again with the client's realm for a server in the referral realm, traced with its result.
pub fn retrieve_ref(cache: &OpenCache, client: &Princ, server: &Princ, found: bool) {
    if !trace::enabled() {
        return;
    }
    let msg = cache.not_found().message;
    let (code, msg) = if found {
        (0, None)
    } else {
        (trace::KRB5_CC_NOTFOUND, Some(msg.as_str()))
    };
    trace::cc_retrieve_ref(Some(princ(client)), princ(server), code, msg);
}

/// MIT `begin` (`lib/krb5/krb/get_creds.c:1076-1080`): a server in the referral realm starts in the start realm, traced with that realm.
pub fn referral_realm(server: &Princ) {
    if trace::enabled() {
        trace::tkt_creds_referral_realm(princ(server));
    }
}

/// [`retrieve`] of the lookup whose result is `found`, which is handed back.
#[must_use]
pub fn retrieved<'c>(
    cache: &OpenCache,
    client: &Princ,
    server: &Princ,
    found: Option<&'c CcacheCred>,
) -> Option<&'c CcacheCred> {
    retrieve(cache, Some(client), server, found.is_some());
    found
}

/// The cache's TGT for `realm`, as the lookups below see it.
fn cached_tgt<'c>(cache: &'c OpenCache, realm: &str) -> Option<&'c CcacheCred> {
    cache
        .cc
        .list()
        .into_iter()
        .find(|c| c.server.1.is_krbtgt_for(realm))
}

/// MIT `begin_get_tgt` (`lib/krb5/krb/get_creds.c:986-1031`): for a service in another realm, a
/// cached TGT for that realm is looked for first; otherwise the client realm's TGT is looked up
/// and traced as the one the request starts with.
pub fn tgt_for(cache: &OpenCache, srealm: &str) {
    if !trace::enabled() {
        return;
    }
    let me = cache.principal();
    let crealm = String::from_utf8_lossy(me.0.as_bytes()).into_owned();
    let tgt = |realm: &str| (krb5_protocol::realm(realm), PrincipalName::krbtgt(realm));
    if srealm != crealm {
        let service = cached_tgt(cache, srealm);
        retrieve(cache, Some(&me), &tgt(srealm), service.is_some());
        if let Some(c) = service {
            trace::tkt_creds_cached_service_tgt(princ(&c.client), princ(&c.server));
            return;
        }
    }
    let local = cached_tgt(cache, &crealm);
    retrieve(cache, Some(&me), &tgt(&crealm), local.is_some());
    if let Some(c) = local {
        trace::tkt_creds_local_tgt(princ(&c.client), princ(&c.server));
    }
}

/// MIT `krb5_get_self_cred_from_kdc` (`lib/krb5/krb/s4u_creds.c:419-645`): the TGT an S4U request
/// presents is got with `krb5_get_credentials` from the cache, traced as such a request.
pub fn tgt_creds(cache: &OpenCache, srealm: &str) {
    if !trace::enabled() {
        return;
    }
    let me = cache.principal();
    let tgt = (krb5_protocol::realm(srealm), PrincipalName::krbtgt(srealm));
    tkt_creds_begin(cache, &me, &tgt);
    retrieve(cache, Some(&me), &tgt, cached_tgt(cache, srealm).is_some());
}

/// MIT `k5_get_proxy_cred_from_kdc` (`lib/krb5/krb/s4u_creds.c:1147-1192`): an S4U2Proxy
/// credential is looked up in the cache for any client, then the TGT is got as for S4U2Self.
pub fn proxy_lookup(cache: &OpenCache, server: &Princ, found: bool, srealm: &str) {
    retrieve(cache, None, server, found);
    if !found {
        tgt_creds(cache, srealm);
    }
}

/// MIT `krb5_cc_store_cred` (`lib/krb5/ccache/ccfns.c:80-85`): a credential stored in the cache.
pub fn store(spec: &CcSpec, cred: &CcacheCred) {
    if trace::enabled() {
        trace::store_creds(&ccname(spec), std::slice::from_ref(cred));
    }
}

/// MIT `krb5_cc_cache_match` (`lib/krb5/ccache/cccursor.c:183-219`): the match is traced with its
/// result, a principal no cache holds under MIT's message for it.
pub fn cache_match(client: &Princ, found: bool) {
    if !trace::enabled() {
        return;
    }
    if found {
        trace::cc_cache_match(princ(client), 0, None);
    } else {
        let msg = format!(
            "Can't find client principal {} in cache collection",
            crate::creds::unparse(client)
        );
        trace::cc_cache_match(princ(client), trace::KRB5_CC_NOTFOUND, Some(&msg));
    }
}
