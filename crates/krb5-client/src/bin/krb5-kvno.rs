//! MIT `kvno`: get service tickets and print their key version numbers.
//!
//! Usage: `kvno [-c ccache] [-e etype] [-k keytab] [-q] [-u | -S sname] [[{-I | -U} for_user
//! [-P]] | --u2u ccache] [--cached-only] [--no-store] [--out-cache ccache] service1 service2 ...`
//! (MIT's `-F cert_file` is not supported). A `test-hooks` build also takes the gates'
//! options: a KDC host before the services, `--disable-transited-check`, and `--body-realm`
//! with `--renew` or `--renew-ticket` for one request with no referral chase.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use krb5_asn1::decode;
use krb5_client::cli::{KvnoArgs, kvno_usage, parse_kvno, progname};
use krb5_client::creds::{
    GetCredsOptions, OpenCache, Princ, default_realm, get_credentials, get_credentials_for_proxy,
    get_credentials_for_user, get_u2u_ticket, parse_name, princ_eq, server_decrypt_ticket_keytab,
    string_to_enctype, unparse,
};
use krb5_client::errmsg::{Code, Krb5Error};
use krb5_client::{CcacheCred, FileCcache, kt_resolve, store_ccache_keep_default};
use krb5_config::resolve_ccspec;
use krb5_types::{PrincipalName, Ticket};

fn main() {
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

/// MIT `do_v5_kvno` (`kvno.c:452-609`): the options are checked and the caches and keytab named
/// before any request; each service is then asked for in turn, a failed one counted, and the
/// output cache written only when none failed.
fn do_v5_kvno(prog: &str, args: &KvnoArgs) -> i32 {
    let fail = |e: &Krb5Error, doing: &str| {
        eprintln!("{prog}: {e} {doing}");
        1
    };
    if let Err(e) = krb5_client::init_context() {
        return fail(&e, "while initializing krb5 library");
    }
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
    let spec = match resolve_ccspec(args.ccache.as_deref()) {
        Ok(s) => s,
        Err(e) => return fail(&Krb5Error::from_ccname(&e), "while opening ccache"),
    };
    let out_spec = match args.out_cache.as_deref().map(|n| resolve_ccspec(Some(n))) {
        None => None,
        Some(Ok(s)) => Some(s),
        Some(Err(e)) => {
            return fail(&Krb5Error::from_ccname(&e), "while resolving output ccache");
        }
    };
    if let Some(kt) = &args.keytab
        && let Err(e) = kt_resolve(kt)
    {
        return fail(&e, &format!("resolving keytab {kt}"));
    }
    let default_realm = default_realm().unwrap_or_default();
    let for_user = match &args.for_user {
        None => None,
        Some(name) => match parse_name(name, args.for_user_enterprise) {
            Ok(p) => Some(p),
            Err(e) => return fail(&e, &format!("while parsing principal name {name}")),
        },
    };
    if let Some(name) = &args.u2u {
        let ticket = resolve_ccspec(Some(name))
            .map_err(|e| Krb5Error::from_ccname(&e))
            .and_then(get_u2u_ticket);
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
    let mut cache = match OpenCache::open(spec) {
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
        default_realm: &default_realm,
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
    if let Err(e) = cache.flush() {
        eprintln!("{prog}: {e} while storing credentials");
        errors += 1;
    }
    if errors == 0
        && let (Some(spec), Some(cc)) = (out_spec, out)
        && let Err(e) = store_ccache_keep_default(&spec, cc)
    {
        return fail(
            &Krb5Error::new(Code::Other, e.to_string()),
            "while writing output ccache",
        );
    }
    i32::from(errors > 0)
}

/// What every service of one run shares.
struct Ctx<'a> {
    prog: &'a str,
    args: &'a KvnoArgs,
    me: &'a Princ,
    for_user: Option<&'a Princ>,
    default_realm: &'a str,
    opts: &'a GetCredsOptions,
}

/// MIT `kvno` (`kvno.c:292-411`): one service's ticket, from the cache or the KDC, then
/// `<principal>: kvno = <n>` (with the keytab's verdict for `-k`), and for `-P` the S4U2Proxy
/// ticket on the S4U2Self evidence. Each failure is printed here.
fn kvno(ctx: &Ctx<'_>, cache: &mut OpenCache, name: &str) -> Result<CcacheCred, ()> {
    let prog = ctx.prog;
    let args = ctx.args;
    let mut server = match server_principal(name, args.sname.as_deref(), ctx.default_realm) {
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

/// The realm of an S4U2Self user.
/// MIT `s4u_identify_user` (`s4u_creds.c:39-88`): a user that is not an enterprise name keeps its
/// realm; an enterprise name is looked up starting in the realm of the service (the cache's
/// principal). That AS lookup is not sent here: the realm is the one after the name's last `@`,
/// else the service's.
fn identify_user(user: Princ, me: &Princ) -> Princ {
    if user.1.name_type != PrincipalName::NT_ENTERPRISE {
        return user;
    }
    let name = user.1.components_joined();
    let realm = match name.rsplit_once('@') {
        Some((_, r)) if !r.is_empty() => krb5_protocol::realm(r),
        _ => me.0.clone(),
    };
    (realm, user.1)
}

/// The server of one argument: MIT `krb5_parse_name`, or for `-S` MIT `krb5_sname_to_principal`
/// with the argument as the host: `sname/<host lowercased>`, NT-SRV-HST, in the host's realm
/// (`[domain_realm]`) else the default realm.
fn server_principal(name: &str, sname: Option<&str>, realm: &str) -> Result<Princ, Krb5Error> {
    let Some(sname) = sname else {
        return parse_name(name, false);
    };
    let host = name.to_ascii_lowercase();
    let host_realm = krb5_config::load_krb5_conf()
        .and_then(|c| c.realm_for_host(&host).map(str::to_owned))
        .unwrap_or_else(|| realm.to_owned());
    let p = PrincipalName::try_new(PrincipalName::NT_SRV_HST, [sname, host.as_str()])
        .map_err(|_| Krb5Error::of(Code::ParseMalformed))?;
    Ok((krb5_protocol::realm(&host_realm), p))
}

/// The gates send S4U2Self for a service other than the cache's principal, for the KDC to
/// refuse; a release build refuses it first, as MIT's `kvno` does.
const fn relaxed_for_user() -> bool {
    cfg!(feature = "test-hooks")
}

/// The gates' request shapes, in a `test-hooks` build only.
#[cfg(feature = "test-hooks")]
mod gate {
    use krb5_client::CcacheCred;
    use krb5_client::cli::KvnoArgs;
    use krb5_client::creds::{
        GetCredsOptions, OpenCache, Princ, cred_from_tgs, kdc_for_realm, outcome_from_cred,
    };
    use krb5_client::errmsg::Krb5Error;
    use krb5_protocol::{KdcAddr, tgs_exchange_once, tgs_u2u};

    /// The gates' KDC host before the services, and `--disable-transited-check`.
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

    /// `--body-realm`: one TGS-REQ with that `body.realm` and no referral chase, `--renew` /
    /// `--renew-ticket` setting RENEW, `--u2u` sending the second ticket.
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
            None => kdc_for_realm(&hop)?,
        };
        let tgt = outcome_from_cred(&cred)?;
        let out = match &opts.tgs.second_ticket {
            Some(stkt) => tgs_u2u(&kdc, &tgt, server.1.clone(), br, stkt.clone()),
            None => tgs_exchange_once(
                &kdc,
                &tgt,
                server.1.clone(),
                br,
                args.gate.disable_transited_check,
                args.gate.renew || args.gate.renew_ticket,
            ),
        }
        .map_err(|e| Krb5Error::from_tgs(&e, &super::unparse(server), &hop))?;
        let cred = cred_from_tgs(me, &out)?;
        cache.store(cred.clone());
        Ok(cred)
    }
}
