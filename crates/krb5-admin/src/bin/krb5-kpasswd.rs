//! MIT `kpasswd`: change a principal's password through its realm's kpasswd service.
//! else the login name. The current password is asked for when the KDC's reply needs the key, then the new one twice, one line each from a pipe. The server is the realm's `kpasswd_server`, else its `admin_server` on port 464; TCP first, then UDP.
//! A `test-hooks` build (the gates') takes the passwords from `KRB5_PASSWORD` and `KRB5_NEW_PASSWORD` when set, and with `KRB5_KPASSWD_TARGET=name@REALM` sets that principal's password instead (`krb5_set_password`, protocol `0xff80`). A release `kpasswd` reads none of them and changes the client's own password, as MIT's does.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![allow(
    clippy::disallowed_methods,
    reason = "a program reads its profile and environment when it starts"
)]

use std::io::{self, BufRead, Write};

use krb5_cli::Prompter;
use krb5_client::ArmorCcache;
use krb5_config::{CcSpec, ClientContext, Endpoint, Krb5Conf};
use krb5_protocol::{
    AsOutcome, AsRequest, AsTicketOpts, Error, FileCcache, KPASSWD_SUCCESS, KdcAddr, as_exchange,
    as_exchange_defer_fast, as_exchange_prompted, as_exchange_prompted_defer_fast,
    change_password_result, format_chpw_failure, parse_principal, set_password,
};
use krb5_types::PrincipalName;
use zeroize::Zeroizing;

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let prog = argv.first().map_or("kpasswd", String::as_str);
    if argv.len() > 2 {
        eprintln!("usage: {prog} [principal]");
        std::process::exit(1);
    }
    let mut prompter = Prompter::stdio();
    let code = run(prog, argv.get(1).map(String::as_str), &mut prompter);
    std::process::exit(code);
}

struct Client {
    name: PrincipalName,
    realm: String,
    display: String,
}

/// MIT `kpasswd`'s `main`: the exit code, 2 when the server refused the new password.
fn run<R: BufRead, W: Write>(
    prog: &str,
    pname: Option<&str>,
    prompter: &mut Prompter<R, W>,
) -> i32 {
    let ctx = match krb5_config::ClientContext::from_env() {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!("{prog}: {} initializing kerberos library", e.init_text());
            return 1;
        }
    };
    let conf = &ctx.profile;
    // MIT: `krb5_init_context_profile` (lib/krb5/krb/init_ctx.c:209-217)
    // `KRB5_TRACE` opens once the profile has loaded.
    krb5_protocol::trace::init();
    let (client, armor_cc) = match client(prog, pname, &ctx) {
        Ok(client) => client,
        Err(line) => {
            eprintln!("{line}");
            return 1;
        }
    };
    let target = match set_password_target() {
        Ok(target) => target,
        Err(e) => {
            eprintln!("{prog}: {e}");
            return 1;
        }
    };
    // MIT: `k5_locate_server` (locate_kdc.c:871-877)
    // a realm with no KDC is `KRB5_REALM_UNKNOWN`.
    let list = match conf.kdcs_for_traced(&client.realm, &mut krb5_protocol::trace::dns_srv) {
        Ok(list) if !list.is_empty() => list,
        Err(krb5_config::Error::InvalidArgument) => {
            eprintln!("{prog}: Invalid argument getting initial ticket");
            return 1;
        }
        _ => {
            eprintln!("{prog}: Cannot find KDC for requested realm getting initial ticket");
            return 1;
        }
    };
    let kdc = list[0].clone();
    krb5_config::hand_kdcs(&client.realm, list);
    let given = krb5_config::env_password().map(Zeroizing::new);
    // MIT: `k5_infer_principal_type` (lib/krb5/krb/bld_princ.c:34-42)
    // "kadmin/changepw" is not krbtgt or WELLKNOWN, so `krb5_parse_name` makes it NT-PRINCIPAL.
    let changepw = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["kadmin", "changepw"]);
    let kdc = KdcAddr {
        host: kdc.host,
        port: kdc.port,
    };
    // `krb5_get_init_creds_password` for `kadmin/changepw`, traced with its client and that service.
    krb5_protocol::trace::init_creds(krb5_protocol::trace::Princ::new(
        &client.name,
        client.realm.as_bytes(),
    ));
    krb5_protocol::trace::init_creds_service("kadmin/changepw");
    // MIT: `krb5_init_creds_init` (lib/krb5/krb/get_in_tkt.c:998-1005)
    // `kpasswd` sets no address list, so `noaddresses` decides: absent or true sends none, and false sends `krb5_os_localaddr`'s list.
    let addresses = match krb5_protocol::init_creds_addresses(conf.noaddresses_for(&client.realm)) {
        Ok(list) => list,
        Err(e) => {
            let text = match &e {
                Error::Io { message, .. } => message.clone(),
                other => other.to_string(),
            };
            eprintln!("{prog}: {text} getting initial ticket");
            return 1;
        }
    };
    let pkinit = match krb5_client::profile_pkinit(conf, &client.realm) {
        Ok(pkinit) => pkinit,
        Err(e) => {
            eprintln!("{prog}: {e} getting initial ticket");
            return 1;
        }
    };
    let req = AsRequest {
        cname: client.name,
        realm: &client.realm,
        password: given.as_deref().map_or(&[][..], Vec::as_slice),
        kdc: &kdc,
        profile: conf,
        want_spake: false,
        fast_armor: None,
        pkinit: Some(pkinit.arg()),
        canonicalize: false,
        sname: Some(&changepw),
        etypes: None,
        ticket: AsTicketOpts {
            lifetime: Some(300),
            forwardable: false,
            proxiable: false,
            addresses,
            ..AsTicketOpts::default()
        },
    };
    // `krb5_get_init_creds_password` is given no password, so the KDC is asked first and the prompter runs only when a reply needs the key.
    let mut unread: Option<krb5_cli::PromptError> = None;
    let asked = format!("Password for {}", client.display);
    let out = krb5_client::as_with_fast_ccache(
        &ctx,
        armor_cc.as_ref(),
        &client.realm,
        true,
        |fast_armor, defer| {
            let req = AsRequest {
                fast_armor,
                ..req.clone()
            };
            let mut prompt = || {
                prompter.hidden(&asked).map_err(|e| {
                    unread = Some(e);
                    let kind = if e == krb5_cli::PromptError::Interrupted {
                        io::ErrorKind::Interrupted
                    } else {
                        io::ErrorKind::Other
                    };
                    Error::File(io::Error::new(kind, e.to_string()))
                })
            };
            match (given.is_some(), defer) {
                (true, false) => as_exchange(&req),
                (true, true) => as_exchange_defer_fast(&req),
                (false, false) => as_exchange_prompted(&req, &mut prompt),
                (false, true) => as_exchange_prompted_defer_fast(&req, &mut prompt),
            }
        },
    );
    let out = match out {
        Ok(out) => out,
        Err(e) => {
            eprintln!("{prog}: {e} getting initial ticket");
            return 1;
        }
    };
    let as_out = match out {
        Ok(out) => {
            krb5_protocol::warn_deprecated_enctype(&out);
            out
        }
        // a wrong password is "Password incorrect", any other failure its own text.
        Err(
            Error::ReplyIntegrity
            | Error::KrbError {
                code: krb5_types::err::BAD_INTEGRITY,
                ..
            },
        ) => {
            eprintln!("{prog}: Password incorrect while getting initial ticket");
            return 1;
        }
        Err(e) => {
            let text = match (unread, &e) {
                // MIT: `process_pa_data` (lib/krb5/krb/preauth2.c:716-723)
                // a read that failed answering the KDC's preauthentication hint is `KRB5_PREAUTH_FAILED`.
                // MIT: `default_com_err_proc` (util/et/com_err.c:83-85)
                // kpasswd's `com_err` prints `error_message` of that code.
                (Some(_), Error::PreauthFailed(_)) | (_, Error::PreauthNoMech) => {
                    "Generic preauthentication failure".to_owned()
                }
                // A read that failed and was not the end of the exchange (a later mechanism read the password and the KDC refused it) leaves the KDC's own error to print.
                (Some(why), Error::File(_)) => why.to_string(),
                (_, e) => initial_ticket_text(e),
            };
            eprintln!("{prog}: {text} getting initial ticket");
            return 1;
        }
    };
    let new = match krb5_config::env_new_password() {
        Some(pw) => Zeroizing::new(pw),
        // `Enter new password`, then `Enter it again`, which must match.
        None => match prompter.password("Enter new password", Some("Enter it again")) {
            Ok(pw) => pw,
            Err(e) => {
                eprintln!("{prog}: {e} while reading password");
                return 1;
            }
        },
    };
    let servers =
        match conf.locate_kpasswd_traced(&client.realm, &mut krb5_protocol::trace::dns_srv) {
            Ok(list) => list,
            Err(e) => {
                eprintln!("{prog}: {e} changing password");
                return 1;
            }
        };
    if servers.is_empty() {
        eprintln!("{prog}: Cannot find KDC for requested realm changing password");
        return 1;
    }
    // MIT: `change_set_password` (changepw.c:256-265)
    // the next server only when one does not answer.
    match send(
        &servers,
        &as_out,
        &new,
        target.as_ref(),
        conf.request_timeout,
        conf,
    ) {
        Ok(None) => {
            // "Password changed." and exit 0.
            println!("Password changed.");
            0
        }
        Ok(Some(line)) => {
            // a refusal is printed on stdout, exit 2.
            println!("{line}");
            2
        }
        Err(Error::Io { .. }) => {
            eprintln!("{prog}: Cannot contact any KDC for requested realm changing password");
            1
        }
        Err(e) => {
            // a failed exchange is "<error> changing password".
            let text = krb5_client::errmsg::Krb5Error::from_protocol(&e, &client.realm);
            eprintln!("{prog}: {text} changing password");
            1
        }
    }
}

fn initial_ticket_text(e: &Error) -> String {
    let mit = match e {
        // MIT: `KRB5_KDC_UNREACH` (krb5_err.et:211-211)
        // no KDC answered.
        Error::Io { .. } => "Cannot contact any KDC for requested realm",
        Error::KrbError { code, .. } => match *code {
            // MIT: `KRB5KDC_ERR_NAME_EXP` (krb5_err.et:42-42)
            krb5_types::err::NAME_EXP => "Client's entry in database has expired",
            // MIT: `KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN` (krb5_err.et:47-47)
            krb5_types::err::C_PRINCIPAL_UNKNOWN => "Client not found in Kerberos database",
            // MIT: `KRB5KDC_ERR_CLIENT_REVOKED` (krb5_err.et:59-59)
            krb5_types::err::CLIENT_REVOKED => "Client's credentials have been revoked",
            // MIT: `KRB5KDC_ERR_PREAUTH_FAILED` (krb5_err.et:65-65)
            krb5_types::err::PREAUTH_FAILED => "Preauthentication failed",
            _ => return e.to_string(),
        },
        _ => return e.to_string(),
    };
    mit.to_owned()
}

/// The principal whose password changes, with the message MIT prints when there is none.
fn client(
    prog: &str,
    pname: Option<&str>,
    ctx: &ClientContext,
) -> Result<(Client, Option<ArmorCcache>), String> {
    let conf = &ctx.profile;
    let spec =
        open_default_ccache(ctx).map_err(|e| format!("{prog}: {e} opening default ccache"))?;
    let cached = ccache_principal(&spec, conf).map_err(|e| {
        format!(
            "{prog}: {} getting principal from ccache",
            cache_text(&spec, &e)
        )
    })?;
    let armor = cached.is_some().then(|| ArmorCcache {
        name: krb5_client::trace::ccname(ctx, &spec),
        spec,
    });
    if let Some(name) = pname {
        return parse_client(name, conf)
            .map(|c| (c, armor))
            .map_err(|e| format!("{prog}: {e} parsing client name"));
    }
    if let Some((realm, name)) = cached {
        let realm = String::from_utf8_lossy(realm.as_bytes()).into_owned();
        let display = name.unparse_with_realm(&realm);
        let client = Client {
            name,
            realm,
            display,
        };
        return Ok((client, armor));
    }
    // MIT: `get_name_from_passwd_file` (kpasswd.c:19-37)
    // the real uid's user name, as a principal.
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::current())
        .ok()
        .flatten()
        .ok_or_else(|| "Unable to identify user from password file".to_owned())?;
    parse_client(&user.name, conf)
        .map(|c| (c, armor))
        .map_err(|e| format!("{prog}: {e} when parsing name {}", user.name))
}

fn parse_client(name: &str, conf: &Krb5Conf) -> Result<Client, String> {
    let (name, realm) = parse_principal(&with_default_realm(name, conf)?)?;
    let display = name.unparse_with_realm(&realm);
    Ok(Client {
        name,
        realm,
        display,
    })
}

// MIT: `krb5_parse_name_flags` (krb/parse.c:198-211)
/// a name with no realm takes the default realm.
fn with_default_realm(name: &str, conf: &Krb5Conf) -> Result<String, String> {
    let parsed = krb5_types::parse_name_ex(name, "", false).map_err(|e| e.to_string())?;
    if parsed.has_realm {
        return Ok(name.to_owned());
    }
    let realm = conf
        .default_realm
        .as_deref()
        .ok_or_else(|| krb5_config::Error::NoDefaultRealm.to_string())?;
    Ok(format!("{name}@{realm}"))
}

// MIT: `kcm_resolve` (cc_kcm.c:750-759)
/// the connection first, then for `KCM:` the primary name; either failure fails the resolve.
fn open_default_ccache(ctx: &ClientContext) -> Result<CcSpec, String> {
    let spec = krb5_config::resolve_ccspec(ctx, None).map_err(|e| e.to_string())?;
    let kcm_text = |e: io::Error| strerror(&e);
    match spec {
        CcSpec::Kcm(n) if n.is_empty() => krb5_protocol::kcm_primary_name(&ctx.profile)
            .map(CcSpec::Kcm)
            .map_err(kcm_text),
        CcSpec::Kcm(n) => krb5_protocol::kcm_reachable(&ctx.profile)
            .map(|()| CcSpec::Kcm(n))
            .map_err(kcm_text),
        spec => Ok(spec),
    }
}

fn strerror(e: &io::Error) -> String {
    let text = e.to_string();
    text.rsplit_once(" (os error ")
        .map_or(text.as_str(), |(t, _)| t)
        .to_owned()
}

// MIT: `interpret_errno` (cc_file.c:1346-1389)
/// a refused path is `KRB5_FCC_PERM`, a bad argument or descriptor `KRB5_FCC_INTERNAL`, any other errno `KRB5_CC_IO`.
fn cache_text(spec: &CcSpec, e: &io::Error) -> String {
    use nix::errno::Errno;
    if matches!(spec, CcSpec::Kcm(_)) {
        return strerror(e);
    }
    let Some(n) = e.raw_os_error() else {
        return e.to_string();
    };
    match Errno::from_raw(n) {
        Errno::EPERM | Errno::EACCES | Errno::EISDIR | Errno::EROFS => {
            "Credentials cache permissions incorrect"
        }
        Errno::EINVAL | Errno::EEXIST | Errno::EFAULT | Errno::EBADF | Errno::EWOULDBLOCK => {
            "Internal credentials cache error"
        }
        _ => "Credentials cache I/O operation failed",
    }
    .to_owned()
}

// MIT: `read_header` (cc_file.c:396-401)
/// too short is `KRB5_CC_FORMAT`, a version other than 1–4 `KRB5_CCACHE_BADVNO`.
fn parse_cache_file(b: &[u8]) -> io::Result<FileCcache> {
    let bad = |text: &str| io::Error::new(io::ErrorKind::InvalidData, text);
    let Some(v) = b.get(..2) else {
        return Err(bad("Bad format in credentials cache"));
    };
    if !(1..=4).contains(&u16::from_be_bytes([v[0], v[1]]).wrapping_sub(0x0500)) {
        return Err(bad("Unsupported credentials cache format version number"));
    }
    FileCcache::parse(b).map_err(|_| bad("Bad format in credentials cache"))
}

fn ccache_principal(
    spec: &CcSpec,
    profile: &Krb5Conf,
) -> io::Result<Option<(krb5_types::Realm, PrincipalName)>> {
    let loaded = match spec {
        CcSpec::File(path) => std::fs::read(path).and_then(|b| parse_cache_file(&b)),
        CcSpec::Dir(residual) => krb5_protocol::dir_cache_path(residual)
            .and_then(std::fs::read)
            .and_then(|b| parse_cache_file(&b)),
        CcSpec::Kcm(residual) => krb5_protocol::kcm_load(profile, residual),
        CcSpec::Memory(_) => return Ok(None),
    };
    let nofile = |e: &io::Error| {
        e.kind() == io::ErrorKind::NotFound
            || matches!(
                e.raw_os_error().map(nix::errno::Errno::from_raw),
                Some(
                    nix::errno::Errno::ENOTDIR
                        | nix::errno::Errno::ELOOP
                        | nix::errno::Errno::ENAMETOOLONG
                )
            )
    };
    match loaded {
        Ok(cc) => Ok(Some(cc.primary)),
        Err(e) if nofile(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

/// The gates' set-password target, `KRB5_KPASSWD_TARGET=name@REALM`, in a `test-hooks` build.
/// `krb5_change_password` changes the client's own password, so a release build reads no target.
#[cfg_attr(
    not(feature = "test-hooks"),
    expect(
        clippy::unnecessary_wraps,
        reason = "a test-hooks build reads the target, which may not parse"
    )
)]
fn set_password_target() -> Result<Option<(PrincipalName, String)>, String> {
    #[cfg(feature = "test-hooks")]
    {
        std::env::var("KRB5_KPASSWD_TARGET")
            .ok()
            .map(|raw| {
                parse_principal(&raw).map_err(|e| format!("{e} parsing KRB5_KPASSWD_TARGET"))
            })
            .transpose()
    }
    #[cfg(not(feature = "test-hooks"))]
    {
        Ok(None)
    }
}

/// One kpasswd exchange: `Ok(None)` when the password was changed, `Ok(Some(line))` when the server refused it (`line` is what MIT's `kpasswd` prints).
fn send(
    servers: &[Endpoint],
    as_out: &AsOutcome,
    new: &[u8],
    target: Option<&(PrincipalName, String)>,
    timeout: Option<std::time::Duration>,
    profile: &krb5_config::Krb5Conf,
) -> Result<Option<String>, Error> {
    let Some((tname, trealm)) = target else {
        let (code, data) = change_password_result(servers, as_out, new, timeout, Some(profile))?;
        return Ok((code != KPASSWD_SUCCESS).then(|| format_chpw_failure(code, &data)));
    };
    match set_password(
        servers,
        as_out,
        new,
        (&krb5_protocol::realm(trealm), tname),
        timeout,
        Some(profile),
    ) {
        Ok(()) => Ok(None),
        Err(Error::ReplyMismatch(line)) if is_chpw_result_line(&line) => Ok(Some(line)),
        Err(e) => Err(e),
    }
}

fn is_chpw_result_line(line: &str) -> bool {
    line.starts_with("Success")
        || line.starts_with("Malformed request error")
        || line.starts_with("Server error")
        || line.starts_with("Authentication error")
        || line.starts_with("Password change rejected")
        || line.starts_with("Access denied")
        || line.starts_with("Wrong protocol version")
        || line.starts_with("Initial password required")
        || line.starts_with("Password change failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conf(text: &str) -> Krb5Conf {
        Krb5Conf::parse(text).unwrap()
    }

    fn hosts(list: &[Endpoint]) -> Vec<(&str, u16)> {
        list.iter().map(|e| (e.host.as_str(), e.port)).collect()
    }

    #[test]
    fn kpasswd_server_wins_and_admin_server_is_port_464() {
        let c = conf(
            "[libdefaults]\n dns_lookup_kdc = false\n[realms]\n R = {\n  kdc = k\n  admin_server = a:749\n  kpasswd_server = p1:1464\n  \
             kpasswd_server = p2\n }\n S = {\n  admin_server = a2:12345\n }\n T = {\n  kdc = k\n }\n",
        );
        assert_eq!(
            hosts(&c.locate_kpasswd("R").unwrap()),
            [("p1", 1464), ("p2", 464)]
        );
        assert_eq!(hosts(&c.locate_kpasswd("S").unwrap()), [("a2", 464)]);
        assert_eq!(
            hosts(&c.locate_kpasswd("T").unwrap()),
            [] as [(&str, u16); 0]
        );
        assert_eq!(
            hosts(&c.locate_kpasswd("U").unwrap()),
            [] as [(&str, u16); 0]
        );
    }

    #[test]
    fn a_name_without_a_realm_takes_the_default_realm() {
        let c = conf("[libdefaults]\n default_realm = R\n");
        assert_eq!(with_default_realm("user", &c).unwrap(), "user@R");
        assert_eq!(with_default_realm("user@S", &c).unwrap(), "user@S");
        assert_eq!(with_default_realm(r"a\@b", &c).unwrap(), r"a\@b@R");
        let client = parse_client("host/h.r", &c).unwrap();
        assert_eq!(client.realm, "R");
        assert_eq!(client.display, "host/h.r@R");
        let none = conf("[realms]\n R = {\n  kdc = k\n }\n");
        assert_eq!(
            with_default_realm("user", &none).unwrap_err(),
            "Configuration file does not specify default realm"
        );
    }

    #[test]
    fn initial_ticket_failures_read_as_mit_s_error_table() {
        // not answer, a wrong password under preauth, an unknown, revoked or expired client.
        let krb = |code| Error::KrbError { code, text: None };
        let unreachable = Error::Io {
            message: "no reply".into(),
            kind: io::ErrorKind::WouldBlock,
            retryable: true,
        };
        assert_eq!(
            initial_ticket_text(&unreachable),
            "Cannot contact any KDC for requested realm"
        );
        assert_eq!(
            initial_ticket_text(&krb(krb5_types::err::PREAUTH_FAILED)),
            "Preauthentication failed"
        );
        assert_eq!(
            initial_ticket_text(&krb(krb5_types::err::C_PRINCIPAL_UNKNOWN)),
            "Client not found in Kerberos database"
        );
        assert_eq!(
            initial_ticket_text(&krb(krb5_types::err::CLIENT_REVOKED)),
            "Client's credentials have been revoked"
        );
        assert_eq!(
            initial_ticket_text(&krb(krb5_types::err::NAME_EXP)),
            "Client's entry in database has expired"
        );
        let policy = krb(krb5_types::err::POLICY);
        assert_eq!(initial_ticket_text(&policy), policy.to_string());
    }

    #[test]
    fn a_missing_file_ccache_has_no_principal() {
        let dir = krb5_testkit::scratch_dir("kpasswd-cc");
        let missing = CcSpec::File(dir.join("no-such-cache"));
        assert_eq!(ccache_principal(&missing, &Krb5Conf::new()).unwrap(), None);
        let junk = dir.join("junk");
        std::fs::write(&junk, b"not a ccache").unwrap();
        assert!(ccache_principal(&CcSpec::File(junk), &Krb5Conf::new()).is_err());
        assert_eq!(
            ccache_principal(&CcSpec::Memory("m".into()), &Krb5Conf::new()).unwrap(),
            None
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
