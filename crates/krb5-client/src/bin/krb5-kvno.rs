#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(
    clippy::disallowed_methods,
    reason = "a program reads its profile and environment when it starts"
)]

use krb5_asn1::decode;
use krb5_client::ccol::{resolve, store_spec};
use krb5_client::cli::{KvnoArgs, kvno_usage, parse_kvno, progname};
use krb5_client::creds::{
    GetCredsOptions, OpenCache, Princ, get_credentials, get_credentials_for_proxy,
    get_credentials_for_user, get_u2u_ticket, parse_name, princ_eq, server_decrypt_ticket_keytab,
    string_to_enctype, unparse,
};
use krb5_client::errmsg::{Code, Krb5Error};
use krb5_client::{CcacheCred, FileCcache, kt_resolve, store_ccache_keep_default};
use krb5_config::{ClientContext, resolve_ccspec};
use krb5_types::{PrincipalName, Ticket};

fn main() {
    krb5_types::timestamp::setlocale();
    let argv: Vec<String> = std::env::args().collect();
    let argv0 = argv.first().map_or("kvno", String::as_str);
    let prog = progname(argv0);
    let args = match parse_kvno(argv.get(1..).unwrap_or_default()) {
        Ok(a) => a,
        Err(e) => {
            for line in e.lines(argv0) {
                eprintln!("{line}");
            }
            eprintln!("{}", kvno_usage(prog));
            std::process::exit(1);
        }
    };
    std::process::exit(do_v5_kvno(prog, &args));
}

// MIT: `do_v5_kvno` (kvno.c:452-609)
// the options are checked and the caches and keytab named
fn do_v5_kvno(prog: &str, args: &KvnoArgs) -> i32 {
    let fail = |e: &Krb5Error, doing: &str| {
        eprintln!("{prog}: {e} {doing}");
        1
    };
    let kctx = match krb5_client::init_context() {
        Ok(kctx) => kctx,
        Err(e) => return fail(&e, "while initializing krb5 library"),
    };
    let mut opts = GetCredsOptions {
        cached_only: args.cached_only,
        no_store: args.no_store || args.out_cache.is_some(),
        ..GetCredsOptions::default()
    };
    opts.tgs.canonicalize = args.canonicalize;
    if let Some(name) = &args.etype {
        match string_to_enctype(name) {
            Ok(e) => opts.tgs.enctype = Some(e),
            Err(e) => return fail(&e, "while converting etype"),
        }
    }
    let spec = match resolve_ccspec(&kctx, args.ccache.as_deref())
        .map_err(|e| Krb5Error::from_ccname(&e))
        .and_then(|s| resolve(&kctx, &s))
    {
        Ok(c) => c.spec(),
        Err(e) => return fail(&e, "while opening ccache"),
    };
    let out_spec = match args.out_cache.as_deref().map(|n| {
        resolve_ccspec(&kctx, Some(n))
            .map_err(|e| Krb5Error::from_ccname(&e))
            .and_then(|s| resolve(&kctx, &s).map(|c| store_spec(&s, &c)))
    }) {
        None => None,
        Some(Ok(s)) => Some(s),
        Some(Err(e)) => return fail(&e, "while resolving output ccache"),
    };
    if let Some(kt) = &args.keytab
        && let Err(e) = kt_resolve(kt)
    {
        return fail(&e, &format!("resolving keytab {kt}"));
    }
    let for_user = match &args.for_user {
        None => None,
        Some(name) => match parse_name(&kctx, name, args.for_user_enterprise) {
            Ok(p) => Some(p),
            Err(e) => return fail(&e, &format!("while parsing principal name {name}")),
        },
    };
    if let Some(name) = &args.u2u {
        let ticket = resolve_ccspec(&kctx, Some(name))
            .map_err(|e| Krb5Error::from_ccname(&e))
            .and_then(|spec| get_u2u_ticket(&kctx, spec));
        match ticket {
            Ok(t) => opts.tgs.second_ticket = Some(t),
            Err(e) => {
                return fail(
                    &e,
                    &format!("while getting user-to-user ticket from {name}"),
                );
            }
        }
    }
    let mut cache = match OpenCache::open(&kctx, spec) {
        Ok(c) => c,
        Err(e) => return fail(&e, "while getting client principal name"),
    };
    let me = cache.principal();
    let for_user = for_user.map(|u| identify_user(u, &me));
    #[cfg(feature = "test-hooks")]
    gate::apply(args, &mut opts);
    let ctx = Ctx {
        prog,
        args,
        me: &me,
        for_user: for_user.as_ref(),
        opts: &opts,
    };
    let mut out: Option<FileCcache> = None;
    let mut errors = 0;
    for name in &args.services {
        match kvno(&ctx, &mut cache, name) {
            Ok(creds) => {
                if out_spec.is_some() {
                    out.get_or_insert_with(|| FileCcache::new(creds.client.clone(), Vec::new()))
                        .creds
                        .push(creds);
                }
            }
            Err(()) => errors += 1,
        }
    }
    if errors == 0
        && let (Some(spec), Some(cc)) = (out_spec, out)
        && let Err(e) = store_ccache_keep_default(&kctx, &spec, cc)
    {
        return fail(
            &Krb5Error::new(Code::Other, e.to_string()),
            "while writing output ccache",
        );
    }
    i32::from(errors > 0)
}

struct Ctx<'a> {
    prog: &'a str,
    args: &'a KvnoArgs,
    me: &'a Princ,
    for_user: Option<&'a Princ>,
    opts: &'a GetCredsOptions,
}

// MIT kvno; see docs/parity/b1-tools.md
fn kvno(ctx: &Ctx<'_>, cache: &mut OpenCache, name: &str) -> Result<CcacheCred, ()> {
    let prog = ctx.prog;
    let args = ctx.args;
    let mut server = match server_principal(cache.ctx, name, args.sname.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            if !args.quiet {
                eprintln!("{prog}: {e} while parsing principal name {name}");
            }
            return Err(());
        }
    };
    if args.unknown {
        server.1.name_type = PrincipalName::NT_UNKNOWN;
    }
    let princ = unparse(&server);
    let got = match ctx.for_user {
        Some(user) => {
            if !args.proxy && !princ_eq(ctx.me, &server) && !relaxed_for_user() {
                eprintln!(
                    "{prog}: {} client and server principal names must match",
                    Krb5Error::of(Code::Einval)
                );
                return Err(());
            }
            let self_sname = if args.proxy { ctx.me } else { &server };
            get_credentials_for_user(cache, user, self_sname, ctx.opts)
        }
        None => {
            #[cfg(feature = "test-hooks")]
            if let Some(got) = gate::body_realm_request(args, cache, ctx.me, &server, ctx.opts) {
                got
            } else {
                get_credentials(cache, ctx.me, &server, ctx.opts)
            }
            #[cfg(not(feature = "test-hooks"))]
            get_credentials(cache, ctx.me, &server, ctx.opts)
        }
    };
    let creds = match got {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{prog}: {e} while getting credentials for {princ}");
            return Err(());
        }
    };
    let ticket: Ticket = match decode(&creds.ticket) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{prog}: {e} while decoding ticket for {princ}");
            return Err(());
        }
    };
    let kvno = ticket.enc_part.kvno.unwrap_or(0);
    if let Some(kt) = &args.keytab {
        if let Err(e) = server_decrypt_ticket_keytab(kt, &ticket) {
            if !args.quiet {
                eprintln!("{princ}: kvno = {kvno}, keytab entry invalid");
            }
            eprintln!("{prog}: {e} while decrypting ticket for {princ}");
            return Err(());
        }
        if !args.quiet {
            println!("{princ}: kvno = {kvno}, keytab entry valid");
        }
    } else if !args.quiet {
        println!("{princ}: kvno = {kvno}");
    }
    if !args.proxy {
        return Ok(creds);
    }
    let client = creds.client.clone();
    get_credentials_for_proxy(cache, &client, &server, &creds, ctx.opts).map_err(|e| {
        eprintln!("{prog}: {e} {princ}: constrained delegation failed");
    })
}

// MIT: `s4u_identify_user` (lib/krb5/krb/s4u_creds.c:40-88)
// an enterprise name is looked up from the service realm by that probe, not by the text after `@`.
fn identify_user(user: Princ, _me: &Princ) -> Princ {
    user
}

fn server_principal(
    kctx: &ClientContext,
    name: &str,
    sname: Option<&str>,
) -> Result<Princ, Krb5Error> {
    let Some(sname) = sname else {
        return parse_name(kctx, name, false);
    };
    krb5_config::sname_to_principal(
        &kctx.profile,
        Some(name),
        Some(sname),
        PrincipalName::NT_SRV_HST,
    )
    .map_err(|e| Krb5Error::from_sname(&e))
}

const fn relaxed_for_user() -> bool {
    cfg!(feature = "test-hooks")
}

#[cfg(feature = "test-hooks")]
mod gate {
    use krb5_client::CcacheCred;
    use krb5_client::cli::KvnoArgs;
    use krb5_client::creds::{
        GetCredsOptions, OpenCache, Princ, cred_from_tgs, kdc_for_realm, outcome_from_cred,
    };
    use krb5_client::errmsg::Krb5Error;
    use krb5_protocol::{KdcAddr, tgs_exchange_once, tgs_u2u};

    pub(super) fn apply(args: &KvnoArgs, opts: &mut GetCredsOptions) {
        opts.tgs.no_transit_check = args.gate.disable_transited_check;
        opts.kdc = args.gate.kdc_host.as_deref().map(parse_addr);
    }

    fn parse_addr(host: &str) -> KdcAddr {
        match host.rsplit_once(':') {
            Some((h, p)) if p.parse::<u16>().is_ok() => KdcAddr {
                host: h.to_owned(),
                port: p.parse().unwrap_or(88),
            },
            _ => KdcAddr::new(host),
        }
    }

    pub(super) fn body_realm_request(
        args: &KvnoArgs,
        cache: &mut OpenCache,
        me: &Princ,
        server: &Princ,
        opts: &GetCredsOptions,
    ) -> Option<Result<CcacheCred, Krb5Error>> {
        let br = args.gate.body_realm.as_deref()?;
        Some(request(args, cache, me, server, opts, br))
    }

    fn request(
        args: &KvnoArgs,
        cache: &mut OpenCache,
        me: &Princ,
        server: &Princ,
        opts: &GetCredsOptions,
        br: &str,
    ) -> Result<CcacheCred, Krb5Error> {
        let srealm = String::from_utf8_lossy(server.0.as_bytes()).into_owned();
        let (cred, hop) = if args.gate.renew_ticket {
            let c = cache
                .cc
                .list()
                .into_iter()
                .find(|c| super::princ_eq(&c.server, server))
                .cloned()
                .ok_or_else(|| cache.not_found())?;
            (c, srealm.clone())
        } else {
            let creds = cache.cc.list();
            let crealm = String::from_utf8_lossy(me.0.as_bytes()).into_owned();
            let local = creds
                .iter()
                .copied()
                .find(|c| c.server.1.is_krbtgt())
                .ok_or_else(|| cache.not_found())?;
            let c = creds
                .iter()
                .copied()
                .find(|c| c.server.1.is_krbtgt_for(&srealm))
                .unwrap_or(local)
                .clone();
            let hop = krb5_protocol::referral_hop_realm(&c.server.1).unwrap_or(crealm);
            (c, hop)
        };
        let kdc = match &opts.kdc {
            Some(k) => k.clone(),
            None => kdc_for_realm(&cache.ctx.profile, &hop)?,
        };
        let mut tgt = outcome_from_cred(&cred)?;
        if let Some(off) = cache.ctx.kdc_offset() {
            tgt.time_offset = off;
        }
        let out = match &opts.tgs.second_ticket {
            Some(stkt) => tgs_u2u(
                &cache.ctx.profile,
                &kdc,
                &tgt,
                server.1.clone(),
                br,
                stkt.clone(),
            ),
            None => tgs_exchange_once(
                &cache.ctx.profile,
                &kdc,
                &tgt,
                server.1.clone(),
                br,
                args.gate.disable_transited_check,
                args.gate.renew || args.gate.renew_ticket,
            ),
        }
        .map_err(|e| Krb5Error::from_tgs(&e, &hop))?;
        let cred = cred_from_tgs(me, &out)?;
        let _ = cache.store(cred.clone());
        Ok(cred)
    }
}
