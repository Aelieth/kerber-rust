//! MIT `kinit`: obtain and cache a ticket-granting ticket, or renew or validate the cached one.
//!
//! Usage: `kinit [-V] [-l lifetime] [-s start_time] [-r renewable_life] [-f | -F] [-p | -P] [-n]
//! [-a | -A] [-C] [-E] [-v] [-R] [-k [-i|-t keytab_file]] [-c cachename] [-S service_name]
//! [-T ticket_armor_cache] [-X <attribute>[=<value>]] [principal]` (MIT's `-I`, `--request-pac`
//! and `--no-request-pac` are not taken). A `test-hooks` build also takes the gates' options and
//! prints the gates' log lines and an `ok` line on stdout.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::path::Path;

use krb5_client::ccol::{Cache, cache_match, new_unique, resolve, store_spec};
use krb5_client::cli::{
    KinitAction, KinitArgs, KinitParseError, kinit_usage, parse_kinit, progname,
    read_password_line, read_prompt_line,
};
use krb5_client::creds::{
    Princ, default_realm, get_valrenewed_creds, kdc_for_realm, parse_name, unparse,
};
use krb5_client::errmsg::{Code, Krb5Error};
use krb5_client::{
    FileCcache, KeyExpNotice, KeytabName, KinitParams, NewPasswordPrompter, kinit_prompted,
    kinit_with, kt_client_default_name, kt_default_name, kt_resolve, local_host_addresses,
    mit_error_code, store_ccache_keep_default,
};
use krb5_config::{CcSpec, env_new_password, env_password, parse_ccspec, resolve_ccspec};
use krb5_protocol::{AsTicketOpts, KdcAddr, Keytab};
use krb5_types::PrincipalName;
use zeroize::Zeroize;

fn main() {
    #[cfg(feature = "test-hooks")]
    gate::init_logging();
    let argv: Vec<String> = std::env::args().collect();
    let argv0 = argv.first().map_or("kinit", String::as_str);
    let prog = progname(argv0);
    let opts = match parse_kinit(argv.get(1..).unwrap_or_default()) {
        Ok(o) => o,
        Err(KinitParseError::Krb4) => {
            eprintln!("Kerberos 4 is no longer supported");
            std::process::exit(3);
        }
        Err(KinitParseError::Usage(e)) => {
            for line in e.lines(argv0) {
                eprintln!("{line}");
            }
            eprint!("{}", kinit_usage(prog));
            std::process::exit(2);
        }
    };
    for notice in &opts.notices {
        eprintln!("{notice}");
    }
    #[cfg(feature = "test-hooks")]
    if let Some(code) = gate::refuse(&opts) {
        std::process::exit(code);
    }
    let authed = k5_begin(prog, &opts).is_some_and(|k5| k5_kinit(prog, &opts, &k5));
    if authed && opts.verbose {
        eprintln!("Authenticated to Kerberos v5");
    }
    std::process::exit(i32::from(!authed));
}

/// What `k5_begin` chose.
struct K5 {
    /// The client.
    me: Princ,
    /// Its unparsed name.
    name: String,
    /// The cache the credentials go to.
    out: Cache,
    /// The name they are written under ([`store_spec`]).
    out_spec: CcSpec,
    /// Whether that cache becomes its collection's primary.
    switch_to_cache: bool,
}

/// MIT `k5_begin` (`kinit.c:413-605`): the output cache (`-c`, else the default cache) and the
/// client: the argument, the anonymous principal, the client keytab's first principal (`-k -i`),
/// the host principal (`-k`), the output cache's principal, the default cache's principal, else
/// the login name. When the default cache's type has a collection, the client's own cache in it
/// is used, else a new one when the default cache holds another principal; either becomes the
/// primary once the credentials are stored.
fn k5_begin(prog: &str, opts: &KinitArgs) -> Option<K5> {
    let fail = |e: &Krb5Error, doing: &str| {
        eprintln!("{prog}: {e} {doing}");
        None
    };
    if let Err(e) = krb5_client::init_context() {
        return fail(&e, "while initializing Kerberos 5 library");
    }
    let mut out: Option<Cache> = None;
    let mut out_spec: Option<CcSpec> = None;
    let mut defcache: Option<(CcSpec, Cache)> = None;
    let mut defcache_princ: Option<Princ> = None;
    if let Some(name) = out_cache_name(opts) {
        match parse_ccspec(&name)
            .map_err(|e| Krb5Error::from_ccname(&e))
            .and_then(|s| resolve(&s).map(|c| (s, c)))
        {
            Ok((s, c)) => {
                out_spec = Some(store_spec(&s, &c));
                out = Some(c);
            }
            Err(e) => return fail(&e, &format!("resolving ccache {name}")),
        }
        if opts.verbose {
            eprintln!("Using specified cache: {name}");
        }
    } else {
        let resolved = resolve_ccspec(None)
            .map_err(|e| Krb5Error::from_ccname(&e))
            .and_then(|spec| resolve(&spec).map(|c| (spec, c)));
        match resolved {
            Ok((spec, c)) => {
                defcache_princ = c.principal().ok();
                defcache = Some((spec, c));
            }
            Err(e) => return fail(&e, "while getting default ccache"),
        }
    }
    let mut me: Option<Princ> = None;
    if let Some(name) = &opts.principal {
        match parse_name(name, opts.enterprise) {
            Ok(p) => me = Some(p),
            Err(e) => return fail(&e, &format!("when parsing name {name}")),
        }
    } else if opts.anonymous {
        match default_realm() {
            Some(r) => {
                let anon =
                    PrincipalName::new(PrincipalName::NT_WELLKNOWN, ["WELLKNOWN", "ANONYMOUS"]);
                me = Some((krb5_protocol::realm(&r), anon));
            }
            None => {
                return fail(
                    &Krb5Error::of(Code::NoDefRealm),
                    "while getting default realm",
                );
            }
        }
    } else if opts.keytab && opts.client_keytab {
        match client_keytab_principal() {
            Ok(p) => me = Some(p),
            Err((e, doing)) => return fail(&e, doing),
        }
    } else if opts.keytab {
        me = Some(default_host_principal());
    } else if let Some(c) = &out {
        me = c.principal().ok();
    } else if defcache_princ.is_some() {
        if let Some((s, c)) = defcache.take() {
            out_spec = Some(store_spec(&s, &c));
            out = Some(c);
        }
        me = defcache_princ.take();
    }
    let me = if let Some(m) = me {
        m
    } else {
        let Some(user) = os_user_name() else {
            eprintln!("Unable to identify user");
            return None;
        };
        match parse_name(&user, opts.enterprise) {
            Ok(p) => p,
            Err(e) => return fail(&e, &format!("when parsing name {user}")),
        }
    };
    let mut switch_to_cache = false;
    if out.is_none()
        && let Some((spec, defc)) = &defcache
        && defc.supports_switch()
    {
        match cache_match(spec, &me) {
            Ok(c) => {
                if opts.verbose {
                    eprintln!("Using existing cache: {}", c.name());
                }
                out_spec = Some(c.spec());
                out = Some(c);
                switch_to_cache = true;
            }
            Err(e) if e.code == Code::CcNotfound => {
                if defcache_princ.is_some() {
                    match new_unique(spec) {
                        Ok(c) => {
                            if opts.verbose {
                                eprintln!("Using new cache: {}", c.name());
                            }
                            out_spec = Some(c.spec());
                            out = Some(c);
                            switch_to_cache = true;
                        }
                        Err(e) => return fail(&e, "while generating new ccache"),
                    }
                }
            }
            Err(e) => {
                let name = opts.principal.as_deref().unwrap_or("(null)");
                return fail(&e, &format!("while searching for ccache for {name}"));
            }
        }
    }
    let out = match (out, defcache) {
        (Some(c), _) => c,
        (None, Some((s, c))) => {
            if opts.verbose {
                eprintln!("Using default cache: {}", c.name());
            }
            out_spec = Some(store_spec(&s, &c));
            c
        }
        (None, None) => return None,
    };
    let out_spec = out_spec.unwrap_or_else(|| out.spec());
    let name = unparse(&me);
    if opts.verbose {
        eprintln!("Using principal: {name}");
    }
    Some(K5 {
        me,
        name,
        out,
        out_spec,
        switch_to_cache,
    })
}

/// `-c`, or in a `test-hooks` build the gates' positional cache.
fn out_cache_name(opts: &KinitArgs) -> Option<String> {
    #[cfg(feature = "test-hooks")]
    if opts.ccache.is_none() {
        return opts.gate.pos_ccache.clone();
    }
    opts.ccache.clone()
}

/// MIT `k5_kt_get_principal` of `krb5_kt_client_default`: the client keytab's first principal.
fn client_keytab_principal() -> Result<Princ, (Krb5Error, &'static str)> {
    let resolving = "When resolving the default client keytab";
    let determining = "When determining client principal name from keytab";
    let name = kt_client_default_name();
    let KeytabName::File(path) = kt_resolve(&name).map_err(|e| (e, resolving))? else {
        return Err((Krb5Error::of(Code::Other), determining));
    };
    let bytes = krb5_protocol::read_secret_file(&path).map_err(|e| {
        (
            krb5_client::keytab_read_error(&e, &path.display().to_string()),
            determining,
        )
    })?;
    let kt = Keytab::parse(&bytes)
        .map_err(|e| (Krb5Error::new(Code::Other, e.to_string()), determining))?;
    kt.entries
        .first()
        .map(|e| (e.realm.clone(), e.name.clone()))
        .ok_or_else(|| {
            (
                Krb5Error::new(Code::Other, "Key table entry not found"),
                determining,
            )
        })
}

/// MIT `krb5_sname_to_principal(NULL, NULL, KRB5_NT_SRV_HST)`: `host/<this host, lowercased>` in
/// the host's realm (`[domain_realm]`), else the default realm.
fn default_host_principal() -> Princ {
    let host = nix::unistd::gethostname()
        .map(|h| h.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let realm = krb5_config::load_krb5_conf()
        .and_then(|c| c.realm_for_host(&host).map(str::to_owned))
        .or_else(default_realm)
        .unwrap_or_default();
    (
        krb5_protocol::realm(&realm),
        PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", host.as_str()]),
    )
}

/// MIT `get_name_from_os` (`kinit.c:47-54`): the login name of the real user.
fn os_user_name() -> Option<String> {
    nix::unistd::User::from_uid(nix::unistd::Uid::current())
        .ok()
        .flatten()
        .map(|u| u.name)
}

/// MIT `k5_kinit` (`kinit.c:638-852`): initial credentials with a password or keytab, written to
/// the output cache; or the cache's TGT renewed or validated, the cache then holding it alone.
/// A wrong password is "Password incorrect while \<doing\>". The output cache becomes the primary
/// when `k5_begin` chose so.
fn k5_kinit(prog: &str, opts: &KinitArgs, k5: &K5) -> bool {
    let doing = match opts.action {
        KinitAction::InitPw | KinitAction::InitKt => "getting initial credentials",
        KinitAction::Validate => "validating credentials",
        KinitAction::Renew => "renewing credentials",
    };
    let result = match opts.action {
        KinitAction::Renew | KinitAction::Validate => valrenew(prog, opts, k5),
        KinitAction::InitPw | KinitAction::InitKt => init(opts, k5),
    };
    match result {
        Ok(()) => {}
        Err(Failure::PasswordIncorrect) => {
            eprintln!("{prog}: Password incorrect while {doing}");
            return false;
        }
        Err(Failure::Error(e)) => {
            eprintln!("{prog}: {e} while {doing}");
            return false;
        }
        Err(Failure::Reported) => return false,
    }
    if k5.switch_to_cache
        && let Err(e) = k5.out.switch_to()
    {
        eprintln!("{prog}: {e} while switching to new ccache");
        return false;
    }
    true
}

/// Why `k5_kinit` failed.
enum Failure {
    /// A wrong password.
    PasswordIncorrect,
    /// An error to report with what was being done.
    Error(Krb5Error),
    /// Already reported.
    Reported,
}

/// MIT `k5_kinit` (`kinit.c:797-823`): a renewed or validated credential replaces the cache's
/// contents under the client (the credential's own with `-C`).
fn valrenew(prog: &str, opts: &KinitArgs, k5: &K5) -> Result<(), Failure> {
    let cred = get_valrenewed_creds(
        &k5.out.spec(),
        &k5.me,
        opts.service.as_deref(),
        opts.action == KinitAction::Validate,
    )
    .map_err(Failure::Error)?;
    let cprinc = if opts.canonicalize {
        cred.client.clone()
    } else {
        k5.me.clone()
    };
    if opts.verbose {
        eprintln!("Initialized cache");
    }
    let cc = FileCcache::new(cprinc, vec![cred]);
    // MIT `k5_kinit` (`kinit.c:797-823`): the credential goes through a MEMORY cache moved into
    // the output cache, traced as `write_out_ccache` traces it.
    if krb5_protocol::trace::enabled() {
        krb5_protocol::trace::write_out_ccache(&k5.out.full_name(), &cc);
    }
    if let Err(e) = store_ccache_keep_default(&k5.out_spec, cc) {
        let name = opts.ccache.as_deref().unwrap_or("");
        let e = krb5_client::store_error(e.as_ref());
        eprintln!("{prog}: {e} while saving to cache {name}");
        return Err(Failure::Reported);
    }
    if opts.verbose {
        eprintln!("Stored credentials");
    }
    #[cfg(feature = "test-hooks")]
    println!("ok tgt=2 tgs=true");
    Ok(())
}

/// `-T` is a ccache name, resolved the way `-c` resolves one.
/// MIT `k5_kinit` (`clients/kinit/kinit.c:684-686`): passes `-T` to `krb5_get_init_creds_opt_set_fast_ccache_name`.
/// MIT `krb5_get_init_creds_opt_set_fast_ccache_name` (`lib/krb5/krb/gic_opt.c:279-292`): stores that name for resolution.
fn armor_ccache_spec(name: &str) -> Result<CcSpec, Krb5Error> {
    parse_ccspec(name).map_err(|e| Krb5Error::from_ccname(&e))
}

/// MIT `k5_kinit` (`kinit.c:654-795`): the initial-credentials options, the keytab, then
/// `krb5_get_init_creds_password` or `krb5_get_init_creds_keytab` with the output cache.
#[expect(clippy::too_many_lines, reason = "one MIT function, kept whole")]
fn init(opts: &KinitArgs, k5: &K5) -> Result<(), Failure> {
    let realm = String::from_utf8_lossy(k5.me.0.as_bytes()).into_owned();
    let addr = kdc(opts, &realm).map_err(Failure::Error)?;
    let conf = krb5_config::load_krb5_conf();
    let mut ticket = AsTicketOpts {
        lifetime: opts
            .lifetime
            .or_else(|| conf.as_ref().and_then(|c| c.ticket_lifetime)),
        rlife: opts
            .rlife
            .or_else(|| conf.as_ref().and_then(|c| c.renew_lifetime)),
        forwardable: opts
            .forwardable
            .unwrap_or_else(|| conf.as_ref().is_none_or(|c| c.forwardable)),
        proxiable: opts
            .proxiable
            .unwrap_or_else(|| conf.as_ref().is_none_or(|c| c.proxiable)),
        addresses: None,
        anonymous: opts.anonymous,
        starttime: opts.starttime,
    };
    if opts.addresses == Some(true) {
        ticket.addresses = local_host_addresses();
    }
    let keytab = if opts.keytab {
        let name = match (&opts.keytab_path, opts.client_keytab) {
            (Some(n), _) => n.clone(),
            (None, true) => kt_client_default_name(),
            (None, false) => kt_default_name(),
        };
        match kt_resolve(&name) {
            Ok(KeytabName::File(p)) => Some(p),
            Ok(KeytabName::Memory(_)) => {
                return Err(Failure::Error(Krb5Error::new(
                    Code::Other,
                    format!("Keytab contains no suitable keys for {}", k5.name),
                )));
            }
            Err(e) => {
                eprintln!("kinit: {e} resolving keytab {name}");
                return Err(Failure::Reported);
            }
        }
    } else {
        None
    };
    let pw_auth = !(opts.keytab || opts.anonymous || opts.pkinit_identity.is_some());
    let given = if pw_auth { env_password() } else { None };
    // MIT `kinit_prompter` (`kinit.c:629-633`): a password prompt is noted; the gates' password
    // stands for one.
    let prompted = std::cell::Cell::new(given.is_some());
    let mut read_password = || {
        prompted.set(true);
        read_password_line(&k5.name)
            .map_err(|_| Krb5Error::new(Code::Other, "Cannot read password"))
    };
    let new_password = env_new_password();
    // MIT `krb5_get_init_creds_password` (`gic_pwd.c:238-263`): the banner, then
    // `Enter new password` / `Enter it again`.
    // MIT `kinit_prompter` (`kinit.c:621-636`): those prompts go through this prompter,
    // which hands them to `krb5_prompter_posix`.
    let prompter = |banner: &str| -> Result<(Vec<u8>, Vec<u8>), String> {
        // MIT `krb5_prompter_posix` (`prompter.c:54-54`): prints the banner on stdout.
        println!("{banner}");
        let a = read_prompt_line("Enter new password")?;
        let b = read_prompt_line("Enter it again")?;
        Ok((a, b))
    };
    let key_exp_notice = |banner: &str| eprintln!("{banner}");
    let service = gate_service(opts);
    let armor_spec = match opts.armor_ccache.as_deref() {
        Some(name) => Some(armor_ccache_spec(name).map_err(Failure::Error)?),
        None => None,
    };
    let params = KinitParams {
        service: service.as_deref(),
        in_tkt_service: in_tkt_service(opts),
        want_spake: want_spake(opts),
        armor_ccache: armor_spec.as_ref(),
        pkinit_identity: opts.pkinit_identity.as_deref().map(Path::new),
        pkinit_anchors: opts.pkinit_anchors.as_deref().map(Path::new),
        enterprise: opts.enterprise,
        keytab: keytab.as_deref(),
        ticket,
        anonymous: opts.anonymous,
        canonicalize: opts.canonicalize
            || opts.enterprise
            || conf.as_ref().is_some_and(|c| c.canonicalize),
        new_password: new_password.as_deref(),
        prompter: (!opts.keytab).then_some(NewPasswordPrompter(&prompter)),
        key_exp_notice: Some(KeyExpNotice(&key_exp_notice)),
    };
    let spec = &k5.out_spec;
    let result = match given {
        Some(mut p) => kinit_with(&addr, &k5.name, &mut p, spec, params),
        None if pw_auth => kinit_prompted(&addr, &k5.name, &mut read_password, spec, params),
        None => kinit_with(&addr, &k5.name, &mut [], spec, params),
    };
    if let Some(mut n) = new_password {
        n.zeroize();
    }
    match result {
        Ok(r) => {
            #[cfg(feature = "test-hooks")]
            println!(
                "ok tgt={} tgs={}",
                r.as_out.enc_part.sname.name_string.len(),
                r.tgs_out.is_some()
            );
            #[cfg(not(feature = "test-hooks"))]
            let _ = r;
            Ok(())
        }
        Err(e) => {
            // MIT `k5_kinit` (`kinit.c:785-793`): BAD_INTEGRITY, or PREAUTH_FAILED after a
            // password prompt, is "Password incorrect".
            match mit_error_code(e.as_ref()) {
                Some(krb5_types::err::BAD_INTEGRITY) => Err(Failure::PasswordIncorrect),
                Some(krb5_types::err::PREAUTH_FAILED) if prompted.get() => {
                    Err(Failure::PasswordIncorrect)
                }
                _ => Err(Failure::Error(init_error(e.as_ref(), k5, &realm))),
            }
        }
    }
}

/// MIT's message for a failed initial-credentials request.
fn init_error(
    e: &(dyn std::error::Error + Send + Sync + 'static),
    k5: &K5,
    realm: &str,
) -> Krb5Error {
    if let Some(k) = e.downcast_ref::<Krb5Error>() {
        return k.clone();
    }
    if let Some(p) = e.downcast_ref::<krb5_protocol::Error>() {
        return Krb5Error::from_as(p, &k5.name, realm);
    }
    Krb5Error::new(Code::Other, e.to_string())
}

/// The KDC of the client's realm, or the gates' KDC host in a `test-hooks` build.
fn kdc(opts: &KinitArgs, realm: &str) -> Result<KdcAddr, Krb5Error> {
    #[cfg(feature = "test-hooks")]
    if let Some(host) = &opts.gate.kdc_host {
        return Ok(gate::parse_host(host));
    }
    let _ = opts;
    kdc_for_realm(realm)
}

/// `-S`: the initial ticket's service, MIT's `in_tkt_service`. A `test-hooks` build keeps the
/// gates' meaning instead, [`gate_service`].
fn in_tkt_service(opts: &KinitArgs) -> Option<&str> {
    if cfg!(feature = "test-hooks") {
        None
    } else {
        opts.service.as_deref()
    }
}

/// In a `test-hooks` build, the service the gates fetch with a TGS-REQ after the TGT: `-S`, else
/// the positional one.
fn gate_service(opts: &KinitArgs) -> Option<String> {
    #[cfg(feature = "test-hooks")]
    return opts
        .service
        .clone()
        .or_else(|| opts.gate.pos_service.clone());
    #[cfg(not(feature = "test-hooks"))]
    {
        let _ = opts;
        None
    }
}

/// The gates' `--spake`, in a `test-hooks` build.
const fn want_spake(opts: &KinitArgs) -> bool {
    #[cfg(feature = "test-hooks")]
    return opts.gate.want_spake;
    #[cfg(not(feature = "test-hooks"))]
    {
        let _ = opts;
        false
    }
}

/// The gates' pieces, in a `test-hooks` build only.
#[cfg(feature = "test-hooks")]
mod gate {
    use krb5_client::cli::KinitArgs;
    use krb5_protocol::KdcAddr;

    /// The gates read kinit's structured log lines on stdout.
    pub(super) fn init_logging() {
        let _ = tracing_subscriber::fmt()
            .json()
            .with_env_filter("krb5_crypto=info,krb5_asn1=info,krb5_protocol=info,krb5_client=info")
            .try_init();
    }

    /// `--spake` with `-T` or PKINIT is refused, exit 2.
    pub(super) fn refuse(opts: &KinitArgs) -> Option<i32> {
        if opts.gate.want_spake && (opts.armor_ccache.is_some() || opts.pkinit_identity.is_some()) {
            eprintln!("--spake cannot be combined with --armor-ccache or --pkinit");
            return Some(2);
        }
        None
    }

    /// `host[:port]`.
    pub(super) fn parse_host(host: &str) -> KdcAddr {
        if let Some((h, p)) = host.rsplit_once(':')
            && let Ok(port) = p.parse()
        {
            KdcAddr {
                host: h.to_owned(),
                port,
            }
        } else {
            KdcAddr::new(host)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "test-hooks")]
    #[test]
    fn parse_host_splits_port() {
        let a = gate::parse_host("127.0.0.1:8889");
        assert_eq!(a.host, "127.0.0.1");
        assert_eq!(a.port, 8889);
    }

    #[test]
    fn armor_file_residual_is_the_path() {
        let p = armor_ccache_spec("FILE:/var/tmp/p6g/armor.cc").expect("FILE residual");
        assert_eq!(
            p,
            CcSpec::File(std::path::PathBuf::from("/var/tmp/p6g/armor.cc"))
        );
        let bare = armor_ccache_spec("/var/tmp/p6g/armor.cc").expect("bare path");
        assert_eq!(
            bare,
            CcSpec::File(std::path::PathBuf::from("/var/tmp/p6g/armor.cc"))
        );
    }

    #[test]
    fn armor_dir_kcm_and_memory_resolve() {
        assert_eq!(
            armor_ccache_spec("DIR:/var/tmp/p6g/armordir").expect("DIR"),
            CcSpec::Dir("/var/tmp/p6g/armordir".to_owned())
        );
        assert_eq!(
            armor_ccache_spec("KCM:arm").expect("KCM"),
            CcSpec::Kcm("arm".to_owned())
        );
        assert_eq!(
            armor_ccache_spec("MEMORY:p6g").expect("MEMORY"),
            CcSpec::Memory("p6g".to_owned())
        );
    }

    #[test]
    fn armor_keyring_is_unknown() {
        let e = armor_ccache_spec("KEYRING:arm").expect_err("unbuilt");
        assert_eq!(e.to_string(), "Unknown credential cache type");
    }

    #[test]
    fn host_principal_is_srv_hst() {
        let (_, p) = default_host_principal();
        assert_eq!(p.name_type, PrincipalName::NT_SRV_HST);
        assert_eq!(p.name_string.len(), 2);
    }
}
