//! MIT `kpasswd`: change a principal's password through its realm's kpasswd service.
//!
//! Usage: `krb5-kpasswd [principal]`. The principal is the argument, else the default ccache's,
//! else the login name. The current password is asked for, then the new one twice, one line each
//! from a pipe. The server is the realm's `kpasswd_server`, else its `admin_server` on port 464;
//! TCP first, then UDP.
//!
//! A `test-hooks` build (the gates') takes the passwords from `KRB5_PASSWORD` and
//! `KRB5_NEW_PASSWORD` when set, and with `KRB5_KPASSWD_TARGET=name@REALM` sets that principal's
//! password instead (`krb5_set_password`, protocol `0xff80`). A release `kpasswd` reads none of
//! them and changes the client's own password, as MIT's does.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::io::{self, BufRead, Write};

use krb5_cli::Prompter;
use krb5_config::{CcSpec, Endpoint, Krb5Conf};
use krb5_protocol::{
    AsOutcome, AsRequest, AsTicketOpts, Error, FileCcache, KPASSWD_PORT, KPASSWD_SUCCESS, KdcAddr,
    as_exchange, change_password_result, format_chpw_failure, parse_principal, set_password,
};
use krb5_types::PrincipalName;
use zeroize::Zeroizing;

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let prog = argv.first().map_or("kpasswd", String::as_str);
    // MIT `main` (`kpasswd.c:63-66`): more than one argument is the usage line and exit 1.
    if argv.len() > 2 {
        eprintln!("usage: {prog} [principal]");
        std::process::exit(1);
    }
    let mut prompter = Prompter::stdio();
    let code = run(prog, argv.get(1).map(String::as_str), &mut prompter);
    std::process::exit(code);
}

/// The client, its realm and its unparsed name.
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
    // MIT `main` (`kpasswd.c:70-74`): `com_err` of `krb5_init_context`'s code, then exit 1.
    let conf = match krb5_config::init_profile() {
        Ok(conf) => conf,
        Err(e) => {
            eprintln!("{prog}: {} initializing kerberos library", e.init_text());
            return 1;
        }
    };
    let client = match client(prog, pname, &conf) {
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
    // MIT `k5_locate_server` (`locate_kdc.c:871-877`): a realm with no KDC is `KRB5_REALM_UNKNOWN`.
    let Some(kdc) = conf
        .kdcs_for(&client.realm)
        .ok()
        .and_then(|list| list.into_iter().next())
    else {
        eprintln!("{prog}: Cannot find KDC for requested realm getting initial ticket");
        return 1;
    };
    let old = match krb5_config::env_password() {
        Some(pw) => Zeroizing::new(pw),
        None => match prompter.hidden(&format!("Password for {}", client.display)) {
            Ok(pw) => pw,
            Err(e) => {
                eprintln!("{prog}: {e} getting initial ticket");
                return 1;
            }
        },
    };
    let changepw = PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "changepw"]);
    let kdc = KdcAddr {
        host: kdc.host,
        port: kdc.port,
    };
    let as_out = match as_exchange(&AsRequest {
        cname: client.name,
        realm: &client.realm,
        password: &old,
        kdc: &kdc,
        want_spake: false,
        fast_armor: None,
        pkinit: None,
        canonicalize: false,
        sname: Some(&changepw),
        etypes: None,
        // MIT `main` (`kpasswd.c:124-131`): a 5-minute kadmin/changepw ticket, not renewable, forwardable or proxiable.
        ticket: AsTicketOpts {
            lifetime: Some(300),
            forwardable: false,
            proxiable: false,
            ..AsTicketOpts::default()
        },
    }) {
        Ok(out) => out,
        // MIT `main` (`kpasswd.c:132-142`): a wrong password is "Password incorrect", any other failure its own text.
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
            eprintln!("{prog}: {} getting initial ticket", initial_ticket_text(&e));
            return 1;
        }
    };
    let new = match krb5_config::env_new_password() {
        Some(pw) => Zeroizing::new(pw),
        // MIT `main` (`kpasswd.c:144-150`): `Enter new password`, then `Enter it again`, which must match.
        None => match prompter.password("Enter new password", Some("Enter it again")) {
            Ok(pw) => pw,
            Err(e) => {
                eprintln!("{prog}: {e} while reading password");
                return 1;
            }
        },
    };
    let servers = kpasswd_servers(&conf, &client.realm);
    if servers.is_empty() {
        eprintln!("{prog}: Cannot find KDC for requested realm changing password");
        return 1;
    }
    // MIT `change_set_password` (`changepw.c:256-265`): the next server only when one does not answer.
    for server in servers {
        let server = KdcAddr {
            host: server.host,
            port: server.port,
        };
        match send(&server, &as_out, &new, target.as_ref()) {
            Ok(None) => {
                // MIT `main` (`kpasswd.c:175-176`): "Password changed." and exit 0.
                println!("Password changed.");
                return 0;
            }
            Ok(Some(line)) => {
                // MIT `main` (`kpasswd.c:160-169`): a refusal is printed on stdout, exit 2.
                println!("{line}");
                return 2;
            }
            Err(Error::Io { .. }) => {}
            Err(e) => {
                // MIT `main` (`kpasswd.c:152-158`): a failed exchange is "<error> changing password".
                eprintln!("{prog}: {e} changing password");
                return 1;
            }
        }
    }
    eprintln!("{prog}: Cannot contact any KDC for requested realm changing password");
    1
}

/// What MIT's kpasswd prints for a failed initial ticket: `error_message()` of the code, the
/// `krb5_err.et` text, for the failures settled against MIT; the error itself for the rest.
fn initial_ticket_text(e: &Error) -> String {
    let mit = match e {
        // MIT `KRB5_KDC_UNREACH` (`krb5_err.et:211-211`): no KDC answered.
        Error::Io { .. } => "Cannot contact any KDC for requested realm",
        Error::KrbError { code, .. } => match *code {
            // MIT `KRB5KDC_ERR_NAME_EXP` (`krb5_err.et:42-42`): the text.
            krb5_types::err::NAME_EXP => "Client's entry in database has expired",
            // MIT `KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN` (`krb5_err.et:47-47`): the text.
            krb5_types::err::C_PRINCIPAL_UNKNOWN => "Client not found in Kerberos database",
            // MIT `KRB5KDC_ERR_CLIENT_REVOKED` (`krb5_err.et:59-59`): the text.
            krb5_types::err::CLIENT_REVOKED => "Client's credentials have been revoked",
            // MIT `KRB5KDC_ERR_PREAUTH_FAILED` (`krb5_err.et:65-65`): the text.
            krb5_types::err::PREAUTH_FAILED => "Preauthentication failed",
            _ => return e.to_string(),
        },
        _ => return e.to_string(),
    };
    mit.to_owned()
}

/// The principal whose password changes, with the message MIT prints when there is none.
/// MIT `main` (`kpasswd.c:91-122`): the default ccache is opened and its principal read whether
/// or not a name is given, either failure (other than no cache or no principal) ending kpasswd;
/// then the argument, else that principal, else the login name.
fn client(prog: &str, pname: Option<&str>, conf: &Krb5Conf) -> Result<Client, String> {
    let spec = open_default_ccache().map_err(|e| format!("{prog}: {e} opening default ccache"))?;
    let cached = ccache_principal(&spec).map_err(|e| {
        format!(
            "{prog}: {} getting principal from ccache",
            cache_text(&spec, &e)
        )
    })?;
    if let Some(name) = pname {
        return parse_client(name, conf).map_err(|e| format!("{prog}: {e} parsing client name"));
    }
    if let Some((realm, name)) = cached {
        let realm = String::from_utf8_lossy(realm.as_bytes()).into_owned();
        let display = name.unparse_with_realm(&realm);
        return Ok(Client {
            name,
            realm,
            display,
        });
    }
    // MIT `get_name_from_passwd_file` (`kpasswd.c:19-37`): the real uid's user name, as a principal.
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::current())
        .ok()
        .flatten()
        .ok_or_else(|| "Unable to identify user from password file".to_owned())?;
    parse_client(&user.name, conf)
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

/// `name`, with krb5.conf's `default_realm` when it names no realm.
/// MIT `krb5_parse_name_flags` (`krb/parse.c:198-211`): a name with no realm takes the default realm.
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

/// The default ccache, resolved as MIT's `krb5_cc_default` resolves it: a KCM name asks its
/// daemon, and `KCM:` asks for the name of the default cache.
/// MIT `kcm_resolve` (`cc_kcm.c:750-759`): the connection first, then for `KCM:` the primary
/// name; either failure fails the resolve.
fn open_default_ccache() -> Result<CcSpec, String> {
    let spec = krb5_config::resolve_ccspec(None).map_err(|e| e.to_string())?;
    let kcm_text = |e: io::Error| strerror(&e);
    match spec {
        CcSpec::Kcm(n) if n.is_empty() => krb5_protocol::kcm_primary_name()
            .map(CcSpec::Kcm)
            .map_err(kcm_text),
        CcSpec::Kcm(n) => krb5_protocol::kcm_reachable()
            .map(|()| CcSpec::Kcm(n))
            .map_err(kcm_text),
        spec => Ok(spec),
    }
}

/// `e`'s text as `com_err` prints an errno, without Rust's `(os error N)`.
fn strerror(e: &io::Error) -> String {
    let text = e.to_string();
    text.rsplit_once(" (os error ")
        .map_or(text.as_str(), |(t, _)| t)
        .to_owned()
}

/// The text of a failure to read the default ccache's principal, as MIT's default `com_err`
/// prints its code: for a FILE or DIR cache, the cache code its errno maps to, or a header that
/// does not read; for KCM, the daemon's error.
/// MIT `interpret_errno` (`cc_file.c:1346-1389`): a refused path is `KRB5_FCC_PERM`, a bad
/// argument or descriptor `KRB5_FCC_INTERNAL`, any other errno `KRB5_CC_IO`.
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

/// A cache file's bytes parsed, or MIT's text for a header that does not read.
/// MIT `read_header` (`cc_file.c:396-401`): too short is `KRB5_CC_FORMAT`, a version other than
/// 1–4 `KRB5_CCACHE_BADVNO`.
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

/// The default ccache's principal; `None` when that cache does not exist.
/// MIT `main` (`kpasswd.c:96-97`): a missing cache (`KRB5_FCC_NOFILE`, also `ENOTDIR`, `ELOOP` and
/// `ENAMETOOLONG`) or principal (`KRB5_CC_NOTFOUND`) is no error.
fn ccache_principal(spec: &CcSpec) -> io::Result<Option<(krb5_types::Realm, PrincipalName)>> {
    let loaded = match spec {
        CcSpec::File(path) => std::fs::read(path).and_then(|b| parse_cache_file(&b)),
        CcSpec::Dir(residual) => krb5_protocol::dir_cache_path(residual)
            .and_then(std::fs::read)
            .and_then(|b| parse_cache_file(&b)),
        CcSpec::Kcm(residual) => krb5_protocol::kcm_load(residual),
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

/// The kpasswd servers for `realm`: its `kpasswd_server` entries, else its `admin_server` hosts on
/// port 464.
/// MIT `locate_kpasswd` (`changepw.c:61-90`): `admin_server` only when no `kpasswd_server` is listed, its port replaced by `DEFAULT_KPASSWD_PORT`.
fn kpasswd_servers(conf: &Krb5Conf, realm: &str) -> Vec<Endpoint> {
    if let Some(list) = conf.kpasswd_servers.get(realm).filter(|l| !l.is_empty()) {
        return list.clone();
    }
    conf.admin_servers
        .get(realm)
        .into_iter()
        .flatten()
        .map(|e| Endpoint {
            host: e.host.clone(),
            port: KPASSWD_PORT,
        })
        .collect()
}

/// The gates' set-password target, `KRB5_KPASSWD_TARGET=name@REALM`, in a `test-hooks` build.
/// MIT `main` (`kpasswd.c:152-153`): `krb5_change_password` changes the client's own password,
/// so a release build reads no target.
///
/// # Errors
///
/// The parse error of a target that is not a principal name, with what was parsed.
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

/// One kpasswd exchange: `Ok(None)` when the password was changed, `Ok(Some(line))` when the
/// server refused it (`line` is what MIT's `kpasswd` prints).
fn send(
    server: &KdcAddr,
    as_out: &AsOutcome,
    new: &[u8],
    target: Option<&(PrincipalName, String)>,
) -> Result<Option<String>, Error> {
    let Some((tname, trealm)) = target else {
        let (code, data) = change_password_result(server, as_out, new)?;
        return Ok((code != KPASSWD_SUCCESS).then(|| format_chpw_failure(code, &data)));
    };
    match set_password(server, as_out, new, (&krb5_protocol::realm(trealm), tname)) {
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
        // Live MIT 1.22.2 kpasswd: kpasswd_server entries in order, with no fall back to
        // admin_server; admin_server alone goes to 464 whatever port it names.
        let c = conf(
            "[realms]\n R = {\n  kdc = k\n  admin_server = a:749\n  kpasswd_server = p1:1464\n  \
             kpasswd_server = p2\n }\n S = {\n  admin_server = a2:12345\n }\n T = {\n  kdc = k\n }\n",
        );
        assert_eq!(
            hosts(&kpasswd_servers(&c, "R")),
            [("p1", 1464), ("p2", 464)]
        );
        assert_eq!(hosts(&kpasswd_servers(&c, "S")), [("a2", 464)]);
        assert_eq!(hosts(&kpasswd_servers(&c, "T")), [] as [(&str, u16); 0]);
        assert_eq!(hosts(&kpasswd_servers(&c, "U")), [] as [(&str, u16); 0]);
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
        // Live MIT 1.22.2: "kpasswd: Configuration file does not specify default realm parsing
        // client name", exit 1.
        let none = conf("[realms]\n R = {\n  kdc = k\n }\n");
        assert_eq!(
            with_default_realm("user", &none).unwrap_err(),
            "Configuration file does not specify default realm"
        );
    }

    #[test]
    fn initial_ticket_failures_read_as_mit_s_error_table() {
        // Live MIT 1.22.2 kpasswd: "kpasswd: <text> getting initial ticket" for a KDC that does
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
        assert_eq!(ccache_principal(&missing).unwrap(), None);
        let junk = dir.join("junk");
        std::fs::write(&junk, b"not a ccache").unwrap();
        assert!(ccache_principal(&CcSpec::File(junk)).is_err());
        assert_eq!(ccache_principal(&CcSpec::Memory("m".into())).unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
