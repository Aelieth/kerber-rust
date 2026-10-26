#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![allow(
    clippy::disallowed_methods,
    reason = "a program reads its profile and environment when it starts"
)]

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
    ArmorCcache, FileCcache, KeyExpNotice, KeytabName, KinitParams, NewPasswordPrompter,
    PromptReply, kinit_prompted_princ, kinit_with_princ, kt_client_default_name, kt_default_name,
    kt_resolve, mit_error_code, store_ccache_keep_default,
};
use krb5_config::{
    CcSpec, ClientContext, env_new_password, env_password, parse_ccspec, resolve_ccspec,
};
use krb5_protocol::{AsTicketOpts, KdcAddr, Keytab};
use krb5_types::PrincipalName;
use zeroize::Zeroize;

fn main() {
    krb5_types::timestamp::setlocale();
    #[cfg(feature = "test-hooks")]
    gate::init_logging();
    let argv: Vec<String> = std::env::args().collect();
    let argv0 = argv.first().map_or("kinit", String::as_str);
    let prog = progname(argv0);
    let opts = match parse_kinit(argv.get(1..).unwrap_or_default()) {
        Ok(o) => o,
        Err(KinitParseError::Krb4(e)) => {
            for line in e.lines(argv0) {
                eprintln!("{line}");
            }
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

struct K5 {
    ctx: ClientContext,
    me: Princ,
    name: String,
    out: Cache,
    out_spec: CcSpec,
    switch_to_cache: bool,
    in_cc: Option<FileCcache>,
}

// MIT: `k5_begin` (kinit.c:413-605)
fn k5_begin(prog: &str, opts: &KinitArgs) -> Option<K5> {
    let fail = |e: &Krb5Error, doing: &str| {
        eprintln!("{prog}: {e} {doing}");
        None
    };
    let ctx = match krb5_client::init_context() {
        Ok(ctx) => ctx,
        Err(e) => return fail(&e, "while initializing Kerberos 5 library"),
    };
    let mut out: Option<Cache> = None;
    let mut out_spec: Option<CcSpec> = None;
    let mut defcache: Option<(CcSpec, Cache)> = None;
    let mut defcache_princ: Option<Princ> = None;
    if let Some(name) = out_cache_name(opts) {
        match parse_ccspec(&name)
            .map_err(|e| Krb5Error::from_ccname(&e))
            .and_then(|s| resolve(&ctx, &s).map(|c| (s, c)))
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
        let resolved = resolve_ccspec(&ctx, None)
            .map_err(|e| Krb5Error::from_ccname(&e))
            .and_then(|spec| resolve(&ctx, &spec).map(|c| (spec, c)));
        match resolved {
            Ok((spec, c)) => {
                defcache_princ = c.principal(&ctx).ok();
                defcache = Some((spec, c));
            }
            Err(e) => return fail(&e, "while getting default ccache"),
        }
    }
    let mut me: Option<Princ> = None;
    if let Some(name) = &opts.principal {
        match parse_name(&ctx, name, opts.enterprise) {
            Ok(p) => me = Some(p),
            Err(e) => return fail(&e, &format!("when parsing name {name}")),
        }
    } else if opts.anonymous {
        match default_realm(&ctx) {
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
        match client_keytab_principal(&ctx) {
            Ok(p) => me = Some(p),
            Err((e, doing)) => return fail(&e, doing),
        }
    } else if opts.keytab {
        me = Some(default_host_principal(&ctx));
    } else if let Some(c) = &out {
        me = c.principal(&ctx).ok();
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
        match parse_name(&ctx, &user, opts.enterprise) {
            Ok(p) => p,
            Err(e) => return fail(&e, &format!("when parsing name {user}")),
        }
    };
    let mut switch_to_cache = false;
    if out.is_none()
        && let Some((spec, defc)) = &defcache
        && defc.supports_switch()
    {
        match cache_match(&ctx, spec, &me) {
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
                    match new_unique(&ctx, spec) {
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
    // MIT: `read_allowed_preauth_type` (get_in_tkt.c:743-745)
    // A `pa_type` read that fails leaves the allowed type unset, and kinit continues.
    let in_cc = match &opts.in_ccache {
        None => None,
        Some(n) => match armor_ccache_spec(n) {
            Err(e) => return fail(&e, &format!("resolving ccache {n}")),
            Ok(spec) => {
                if opts.verbose {
                    eprintln!("Using specified input cache: {n}");
                }
                krb5_client::load_ccache(&ctx, &spec).ok()
            }
        },
    };
    let name = unparse(&me);
    if opts.verbose {
        eprintln!("Using principal: {name}");
    }
    Some(K5 {
        ctx,
        me,
        name,
        out,
        out_spec,
        switch_to_cache,
        in_cc,
    })
}

fn out_cache_name(opts: &KinitArgs) -> Option<String> {
    #[cfg(feature = "test-hooks")]
    if opts.ccache.is_none() {
        return opts.gate.pos_ccache.clone();
    }
    opts.ccache.clone()
}

fn client_keytab_principal(ctx: &ClientContext) -> Result<Princ, (Krb5Error, &'static str)> {
    let resolving = "When resolving the default client keytab";
    let determining = "When determining client principal name from keytab";
    let name = kt_client_default_name(ctx);
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

fn default_host_principal(ctx: &ClientContext) -> Princ {
    let host = nix::unistd::gethostname()
        .map(|h| h.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let realm = ctx
        .profile
        .realm_for_host(&host)
        .map(str::to_owned)
        .or_else(|| default_realm(ctx))
        .unwrap_or_default();
    (
        krb5_protocol::realm(&realm),
        PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", host.as_str()]),
    )
}

// MIT: `get_name_from_os` (kinit.c:47-54)
// the login name of the real user.
fn os_user_name() -> Option<String> {
    nix::unistd::User::from_uid(nix::unistd::Uid::current())
        .ok()
        .flatten()
        .map(|u| u.name)
}

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
        && let Err(e) = k5.out.switch_to(&k5.ctx)
    {
        eprintln!("{prog}: {e} while switching to new ccache");
        return false;
    }
    true
}

enum Failure {
    PasswordIncorrect,
    Error(Krb5Error),
    Reported,
}

fn valrenew(prog: &str, opts: &KinitArgs, k5: &K5) -> Result<(), Failure> {
    let cred = get_valrenewed_creds(
        &k5.ctx,
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
    let mut cc = FileCcache::new(cprinc, vec![cred]);
    // MIT: `marshal_header` (lib/krb5/ccache/cc_file.c:454-462)
    if let Some(off) = k5.ctx.kdc_offset() {
        cc.set_deltatime(off);
    }
    if krb5_protocol::trace::enabled() {
        krb5_protocol::trace::write_out_ccache(&k5.out.full_name(), &cc);
    }
    if let Err(e) = store_ccache_keep_default(&k5.ctx, &k5.out_spec, cc) {
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

// MIT: `krb5_get_init_creds_opt_set_fast_ccache_name` (lib/krb5/krb/gic_opt.c:279-292)
// stores that name for resolution.
fn armor_ccache_spec(name: &str) -> Result<CcSpec, Krb5Error> {
    parse_ccspec(name).map_err(|e| Krb5Error::from_ccname(&e))
}

#[expect(clippy::too_many_lines, reason = "one MIT function, kept whole")]
fn init(opts: &KinitArgs, k5: &K5) -> Result<(), Failure> {
    let realm = String::from_utf8_lossy(k5.me.0.as_bytes()).into_owned();
    let conf = &k5.ctx.profile;
    let mut ticket = AsTicketOpts {
        lifetime: opts.lifetime.or_else(|| conf.ticket_lifetime_for(&realm)),
        rlife: opts.rlife.or_else(|| conf.renew_lifetime_for(&realm)),
        forwardable: opts
            .forwardable
            .unwrap_or_else(|| conf.forwardable_for(&realm)),
        proxiable: opts.proxiable.unwrap_or_else(|| conf.proxiable_for(&realm)),
        addresses: None,
        anonymous: opts.anonymous,
        starttime: opts.starttime,
        pac_request: opts.request_pac,
        allowed_preauth_type: None,
        pa_config_in: None,
    };
    // MIT: `krb5_init_creds_init` (lib/krb5/krb/get_in_tkt.c:998-1005)
    // with neither, `noaddresses` absent or true sends none, and false sends that list.
    match opts.addresses {
        Some(true) => match krb5_protocol::os_localaddr() {
            Ok(list) => ticket.addresses = Some(list),
            Err(e) => {
                eprintln!(
                    "kinit: {} getting local addresses",
                    Krb5Error::from_local_addresses(&e)
                );
                return Err(Failure::Reported);
            }
        },
        Some(false) => {}
        None => {
            ticket.addresses = krb5_protocol::init_creds_addresses(conf.noaddresses_for(&realm))
                .map_err(|e| Failure::Error(Krb5Error::from_local_addresses(&e)))?;
        }
    }
    let keytab = if opts.keytab {
        let name = match (&opts.keytab_path, opts.client_keytab) {
            (Some(n), _) => n.clone(),
            (None, true) => kt_client_default_name(&k5.ctx),
            (None, false) => kt_default_name(&k5.ctx),
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
    // MIT: `handle_gic_opt` (plugins/preauth/pkinit/pkinit_clnt.c:1307-1335)
    // the pkinit module refuses a second `X509_user_identity`.
    let pkinit = krb5_protocol::clpreauth_loaded(&k5.ctx.profile, "pkinit");
    let mut identity = false;
    for (attr, value) in &opts.pa_opts {
        if pkinit && attr == "X509_user_identity" {
            if identity {
                eprintln!(
                    "kinit: Preauth module pkinit: X509_user_identity can not be given twice\n while setting '{attr}'='{value}'"
                );
                return Err(Failure::Reported);
            }
            identity = true;
        }
        if opts.verbose {
            eprintln!("PA Option {attr} = {value}");
        }
    }
    // MIT: `kinit_prompter` (clients/kinit/kinit.c:622-636)
    // The prompter serves any mechanism, so a PKINIT that cannot run goes on to the password.
    let pw_auth = !(opts.keytab || opts.anonymous);
    let given = if pw_auth { env_password() } else { None };
    let prompted = std::cell::Cell::new(given.is_some());
    let mut read_password = |client: &str| {
        prompted.set(true);
        read_password_line(client).map_err(|e| {
            let code = if e == krb5_cli::PromptError::Interrupted {
                Code::PwdInterrupted
            } else {
                Code::Other
            };
            Krb5Error::new(code, e.to_string())
        })
    };
    let new_password = env_new_password();
    // MIT: `krb5_get_init_creds_password` (gic_pwd.c:238-263)
    let prompter = |banner: &str| -> PromptReply {
        // MIT: `krb5_prompter_posix` (lib/krb5/os/prompter.c:32-125)
        println!("{banner}");
        let a = read_prompt_line("Enter new password")?;
        let b = read_prompt_line("Enter it again")?;
        Ok((a, b))
    };
    let key_exp_notice = |banner: &str| eprintln!("{banner}");
    let preauth_prompt = |p: &krb5_protocol::PreauthPrompt<'_>| {
        krb5_cli::Prompter::stdio().hidden_with(p.banner, p.prompt, 1024)
    };
    let service = gate_service(opts);
    let armor_spec = match opts.armor_ccache.as_deref() {
        Some(name) => Some(ArmorCcache {
            name: name.to_owned(),
            spec: armor_ccache_spec(name).map_err(Failure::Error)?,
        }),
        None => None,
    };
    let params = KinitParams {
        service: service.as_deref(),
        in_tkt_service: in_tkt_service(opts),
        want_spake: want_spake(opts),
        armor_ccache: armor_spec.as_ref(),
        pkinit_identity: opts.pkinit_identity.as_deref().map(Path::new),
        pkinit_anchors: &opts.pkinit_anchors,
        enterprise: opts.enterprise,
        keytab: keytab.as_deref(),
        ticket,
        anonymous: opts.anonymous,
        canonicalize: opts.canonicalize || conf.canonicalize_for(&realm),
        new_password: new_password.as_deref(),
        prompter: (!opts.keytab).then_some(NewPasswordPrompter(&prompter)),
        key_exp_notice: Some(KeyExpNotice(&key_exp_notice)),
        in_ccache: k5.in_cc.as_ref().map(krb5_client::InputCcache),
        preauth_prompter: (!opts.keytab).then_some(krb5_client::PreauthPrompter(&preauth_prompt)),
    };
    // MIT: `krb5_init_creds_init` (lib/krb5/krb/get_in_tkt.c:864)
    krb5_client::trace::init_creds(&k5.me.1, &realm, in_tkt_service(opts));
    krb5_client::trace::skip_next_init_creds();
    let addr = kdc(&k5.ctx, opts, &realm).map_err(Failure::Error)?;
    let spec = &k5.out_spec;
    let result = match given {
        Some(mut p) => kinit_with_princ(&k5.ctx, &addr, &k5.me, &mut p, spec, &params),
        None if pw_auth => {
            kinit_prompted_princ(&k5.ctx, &addr, &k5.me, &mut read_password, spec, &params)
        }
        None => kinit_with_princ(&k5.ctx, &addr, &k5.me, &mut [], spec, &params),
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
            // MIT: `k5_kinit` (kinit.c:785-793)
            // BAD_INTEGRITY, or PREAUTH_FAILED after a
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

fn kdc(ctx: &ClientContext, opts: &KinitArgs, realm: &str) -> Result<KdcAddr, Krb5Error> {
    #[cfg(feature = "test-hooks")]
    if let Some(host) = &opts.gate.kdc_host {
        return Ok(gate::parse_host(host));
    }
    let _ = opts;
    kdc_for_realm(&ctx.profile, realm)
}

fn in_tkt_service(opts: &KinitArgs) -> Option<&str> {
    if cfg!(feature = "test-hooks") {
        None
    } else {
        opts.service.as_deref()
    }
}

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

const fn want_spake(opts: &KinitArgs) -> bool {
    #[cfg(feature = "test-hooks")]
    return opts.gate.want_spake;
    #[cfg(not(feature = "test-hooks"))]
    {
        let _ = opts;
        false
    }
}

#[cfg(feature = "test-hooks")]
mod gate {
    use krb5_client::cli::KinitArgs;
    use krb5_protocol::KdcAddr;

    pub(super) fn init_logging() {
        let _ = tracing_subscriber::fmt()
            .json()
            .with_env_filter("krb5_crypto=info,krb5_asn1=info,krb5_protocol=info,krb5_client=info")
            .try_init();
    }

    pub(super) fn refuse(opts: &KinitArgs) -> Option<i32> {
        if opts.gate.want_spake && (opts.armor_ccache.is_some() || opts.pkinit_identity.is_some()) {
            eprintln!("--spake cannot be combined with --armor-ccache or --pkinit");
            return Some(2);
        }
        None
    }

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
