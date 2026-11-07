use krb5_config::{CcSpec, ClientContext};
use krb5_protocol::{CcacheCred, trace};
use krb5_types::PrincipalName;

use crate::creds::{OpenCache, Princ};

#[must_use]
pub fn ccname(ctx: &ClientContext, spec: &CcSpec) -> String {
    match spec {
        CcSpec::File(p) => format!("FILE:{}", p.display()),
        CcSpec::Dir(r) if r.starts_with(':') => format!("DIR:{r}"),
        CcSpec::Dir(r) => krb5_protocol::dir_cache_path(r)
            .map_or_else(|_| format!("DIR:{r}"), |p| format!("DIR::{}", p.display())),
        CcSpec::Memory(n) => format!("MEMORY:{n}"),
        CcSpec::Kcm(n) if n.is_empty() => format!(
            "KCM:{}",
            krb5_protocol::kcm_primary_name(&ctx.profile).unwrap_or_default()
        ),
        CcSpec::Kcm(n) => format!("KCM:{n}"),
    }
}

#[must_use]
pub fn princ(p: &Princ) -> trace::Princ<'_> {
    trace::Princ::new(&p.1, p.0.as_bytes())
}

fn static_tgt(realm: &str) -> Option<(krb5_types::Realm, PrincipalName)> {
    let ks = krb5_types::try_ascii(realm).ok()?;
    let name = PrincipalName::try_new(PrincipalName::NT_SRV_INST, ["krbtgt", realm]).ok()?;
    Some((ks, name))
}

// MIT: `krb5_init_creds_set_service` (lib/krb5/krb/get_in_tkt.c:1056-1073)
thread_local! {
    static SKIP_NEXT_INIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub fn init_creds(cname: &PrincipalName, realm: &str, service: Option<&str>) {
    if SKIP_NEXT_INIT.with(std::cell::Cell::take) {
        return;
    }
    trace::init_creds(trace::Princ::new(cname, realm.as_bytes()));
    if let Some(s) = service {
        trace::init_creds_service(s);
    }
}

pub fn skip_next_init_creds() {
    SKIP_NEXT_INIT.with(|c| c.set(true));
}

pub(crate) fn dns_srv(ev: krb5_config::DnsSrv) {
    match ev {
        krb5_config::DnsSrv::Send(name) => trace::dns_srv_send(&name),
        krb5_config::DnsSrv::Answer {
            priority,
            weight,
            port,
            host,
        } => trace::dns_srv_ans(
            i64::from(priority),
            i64::from(weight),
            i64::from(port),
            &host,
        ),
        krb5_config::DnsSrv::NotFound => trace::dns_srv_notfound(),
    }
}

pub fn keytab_lookup_failed(e: &std::io::Error, path: &std::path::Path) {
    if !trace::enabled() {
        return;
    }
    let code = i64::from(e.raw_os_error().unwrap_or_default());
    let msg = (e.kind() == std::io::ErrorKind::NotFound)
        .then(|| format!("Key table file '{}' not found", path.display()));
    trace::init_creds_keytab_lookup_failed(code, msg.as_deref());
}

pub fn fast_armor(ctx: &ClientContext, cc: &crate::ArmorCcache, realm: &str) {
    if !trace::enabled() {
        return;
    }
    trace::fast_armor_ccache(&cc.name);
    let Ok(cache) = OpenCache::open(ctx, cc.spec.clone()) else {
        return;
    };
    let name = ccname(cache.ctx, &cache.spec);
    let Some((_, tgs)) = static_tgt(realm) else {
        return;
    };
    let tgs_name = tgs.unparse_with_realm_lossy(realm);
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
}

pub fn tkt_creds_begin(cache: &OpenCache, me: &Princ, server: &Princ) {
    if !trace::enabled() {
        return;
    }
    let name = ccname(cache.ctx, &cache.spec);
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

pub fn retrieve(cache: &OpenCache, client: Option<&Princ>, server: &Princ, code: i64) {
    if !trace::enabled() {
        return;
    }
    let msg = (code != 0).then(|| cache.miss(code).message);
    trace::cc_retrieve(
        &ccname(cache.ctx, &cache.spec),
        client.map(princ),
        princ(server),
        code,
        msg.as_deref(),
    );
}

pub fn retrieve_ref(cache: &OpenCache, client: &Princ, server: &Princ, code: i64) {
    if !trace::enabled() {
        return;
    }
    let msg = (code != 0).then(|| cache.miss(code).message);
    trace::cc_retrieve_ref(Some(princ(client)), princ(server), code, msg.as_deref());
}

pub fn referral_realm(server: &Princ) {
    if trace::enabled() {
        trace::tkt_creds_referral_realm(princ(server));
    }
}

pub fn retrieved<'c>(
    cache: &OpenCache,
    client: &Princ,
    server: &Princ,
    found: Result<&'c CcacheCred, i64>,
) -> Result<&'c CcacheCred, i64> {
    retrieve(cache, Some(client), server, found.err().unwrap_or(0));
    found
}

fn tgt_code(found: &Result<Option<&CcacheCred>, krb5_protocol::Error>) -> i64 {
    match found {
        Ok(Some(_)) => 0,
        Err(krb5_protocol::Error::CcNotKtype) => trace::KRB5_CC_NOT_KTYPE,
        Err(krb5_protocol::Error::ConfigEtypeNosupp) => trace::KRB5_CONFIG_ETYPE_NOSUPP,
        _ => trace::KRB5_CC_NOTFOUND,
    }
}

// MIT: `begin_get_tgt` (lib/krb5/krb/get_creds.c:986-1014)
pub fn tgt_for(cache: &OpenCache, srealm: &str) {
    if !trace::enabled() {
        return;
    }
    let me = cache.principal();
    let start = cache.start_realm(&me);
    let Some(service_tgt) = static_tgt(srealm) else {
        return;
    };
    let Some(local_tgt) = static_tgt(&start) else {
        return;
    };
    if srealm != start {
        let service = cache.cached_tgt(srealm);
        retrieve(cache, Some(&me), &service_tgt, tgt_code(&service));
        match service {
            Ok(Some(c)) => {
                trace::tkt_creds_cached_service_tgt(princ(&c.client), princ(&c.server));
                return;
            }
            Err(krb5_protocol::Error::CcNotKtype) => return,
            _ => {}
        }
    }
    // MIT: `get_cached_local_tgt` (lib/krb5/krb/get_creds.c:796-841)
    let local = cache.local_tgt(&start);
    retrieve(cache, Some(&me), &local_tgt, local.err().unwrap_or(0));
    if let Ok(c) = local
        && cache.now() <= c.endtime
    {
        trace::tkt_creds_local_tgt(princ(&c.client), princ(&c.server));
    }
}

// MIT: `krb5_get_self_cred_from_kdc` (lib/krb5/krb/s4u_creds.c:419-645)
pub fn tgt_creds(cache: &OpenCache, srealm: &str) {
    if !trace::enabled() {
        return;
    }
    let me = cache.principal();
    let Some(tgt) = static_tgt(srealm) else {
        return;
    };
    tkt_creds_begin(cache, &me, &tgt);
    retrieve(cache, Some(&me), &tgt, tgt_code(&cache.cached_tgt(srealm)));
}

pub fn proxy_lookup(cache: &OpenCache, server: &Princ, code: i64, srealm: &str) {
    retrieve(cache, None, server, code);
    if code != 0 {
        tgt_creds(cache, srealm);
    }
}

// MIT: `krb5_cc_store_cred` (lib/krb5/ccache/ccfns.c:80-85)
pub fn store(ctx: &ClientContext, spec: &CcSpec, cred: &CcacheCred) {
    if trace::enabled() {
        trace::store_creds(&ccname(ctx, spec), std::slice::from_ref(cred));
    }
}

pub fn cache_match(client: &Princ, found: Result<bool, &krb5_config::SnameError>) {
    if !trace::enabled() {
        return;
    }
    if let Err(e) = found {
        let failure = krb5_protocol::KeytabFailure::from_sname(e);
        trace::cc_cache_match(princ(client), failure.code, Some(&failure.text));
    } else if found == Ok(true) {
        trace::cc_cache_match(princ(client), 0, None);
    } else {
        let msg = format!(
            "Can't find client principal {} in cache collection",
            crate::creds::unparse(client)
        );
        trace::cc_cache_match(princ(client), trace::KRB5_CC_NOTFOUND, Some(&msg));
    }
}
