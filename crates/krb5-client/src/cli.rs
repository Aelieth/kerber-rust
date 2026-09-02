//! getopt-compatible CLI parsing for kinit/klist/kvno/kdestroy.

use krb5_protocol::{CcacheCred, FileCcache};

/// One option from [`getopt`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opt {
    /// Short letter, or 0 when `long` is set.
    pub flag: char,
    /// Long name without `--` when this came from a long option.
    pub long: Option<&'static str>,
    /// Argument when the optstring requires one.
    pub arg: Option<String>,
}

/// Long option (`name`, takes argument, optional short alias).
#[derive(Clone, Copy, Debug)]
pub struct LongOpt {
    /// Without the leading `--`.
    pub name: &'static str,
    /// Whether a value is required.
    pub takes_arg: bool,
    /// MIT short equivalent.
    pub short: Option<char>,
}

/// Split `args` (no argv0) into options and operands. Clustering is POSIX.
///
/// # Errors
///
/// Unknown option or missing argument.
pub fn getopt(
    args: &[String],
    optstring: &str,
    longs: &[LongOpt],
) -> Result<(Vec<Opt>, Vec<String>), String> {
    let mut opts = Vec::new();
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            rest.extend(args[i + 1..].iter().cloned());
            break;
        }
        if let Some(name) = a.strip_prefix("--") {
            let (name, inline) = match name.split_once('=') {
                Some((n, v)) => (n, Some(v.to_owned())),
                None => (name, None),
            };
            let spec = longs
                .iter()
                .find(|l| l.name == name)
                .ok_or_else(|| format!("unrecognized option '--{name}'"))?;
            let arg = if spec.takes_arg {
                if let Some(v) = inline {
                    Some(v)
                } else {
                    i += 1;
                    Some(
                        args.get(i)
                            .cloned()
                            .ok_or_else(|| format!("option '{name}' requires an argument"))?,
                    )
                }
            } else {
                if inline.is_some() {
                    return Err(format!("option '--{name}' doesn't allow an argument"));
                }
                None
            };
            opts.push(Opt {
                flag: spec.short.unwrap_or('\0'),
                long: Some(spec.name),
                arg,
            });
            i += 1;
            continue;
        }
        if a.starts_with('-') && a.len() > 1 {
            let chars: Vec<char> = a[1..].chars().collect();
            let mut ci = 0;
            while ci < chars.len() {
                let c = chars[ci];
                let wants = opt_wants_arg(optstring, c)?;
                let arg = if wants {
                    let inline: String = chars[ci + 1..].iter().collect();
                    if inline.is_empty() {
                        i += 1;
                        Some(
                            args.get(i)
                                .cloned()
                                .ok_or_else(|| format!("option requires an argument -- '{c}'"))?,
                        )
                    } else {
                        ci = chars.len();
                        Some(inline)
                    }
                } else {
                    None
                };
                opts.push(Opt {
                    flag: c,
                    long: None,
                    arg,
                });
                if wants {
                    break;
                }
                ci += 1;
            }
            i += 1;
            continue;
        }
        rest.push(a.clone());
        i += 1;
    }
    Ok((opts, rest))
}

fn opt_wants_arg(optstring: &str, c: char) -> Result<bool, String> {
    let mut it = optstring.chars().peekable();
    while let Some(ch) = it.next() {
        if ch == ':' {
            continue;
        }
        if ch == c {
            return Ok(it.next() == Some(':'));
        }
    }
    Err(format!("invalid option -- '{c}'"))
}

/// Parsed `kinit` argv (MIT shopts plus `--spake`/`--pkinit` aliases).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KinitArgs {
    /// `-k`.
    pub keytab: bool,
    /// `-t`.
    pub keytab_path: Option<String>,
    /// `-c`.
    pub ccache: Option<String>,
    /// `-r`.
    pub rlife: Option<String>,
    /// `-l`.
    pub lifetime: Option<String>,
    /// `-R`.
    pub renew: bool,
    /// `-f` / `-F`.
    pub forwardable: Option<bool>,
    /// `-p` / `-P`.
    pub proxiable: Option<bool>,
    /// `-a` / `-A`.
    pub addresses: Option<bool>,
    /// `-S`.
    pub service: Option<String>,
    /// `-E`.
    pub enterprise: bool,
    /// `-n`.
    pub anonymous: bool,
    /// `-X` values.
    pub pa_attrs: Vec<String>,
    /// `--spake`.
    pub want_spake: bool,
    /// `-T` / `--armor-ccache`.
    pub armor_ccache: Option<String>,
    /// `--pkinit` or `-X X509_user_identity=`.
    pub pkinit_identity: Option<String>,
    /// `--pkinit-anchors` or `-X X509_anchors=`.
    pub pkinit_anchors: Option<String>,
    /// Compat: first positional host when it has no `@`.
    pub kdc_host: Option<String>,
    /// Client principal.
    pub principal: Option<String>,
    /// Compat positional ccache.
    pub pos_ccache: Option<String>,
    /// Compat positional service.
    pub pos_service: Option<String>,
}

const KINIT_OPTSTRING: &str = "r:l:c:t:T:S:X:kfpFPnaAER";

fn kinit_longs() -> &'static [LongOpt] {
    &[
        LongOpt {
            name: "spake",
            takes_arg: false,
            short: None,
        },
        LongOpt {
            name: "fast",
            takes_arg: false,
            short: None,
        },
        LongOpt {
            name: "armor-ccache",
            takes_arg: true,
            short: Some('T'),
        },
        LongOpt {
            name: "pkinit",
            takes_arg: true,
            short: None,
        },
        LongOpt {
            name: "pkinit-anchors",
            takes_arg: true,
            short: None,
        },
        LongOpt {
            name: "enterprise",
            takes_arg: false,
            short: Some('E'),
        },
    ]
}

/// Parse `kinit` arguments after argv0.
///
/// # Errors
///
/// Unknown option or missing argument.
pub fn parse_kinit(args: &[String]) -> Result<KinitArgs, String> {
    let (opts, rest) = getopt(args, KINIT_OPTSTRING, kinit_longs())?;
    let mut out = KinitArgs::default();
    for o in opts {
        if let Some(name) = o.long {
            match name {
                "spake" => out.want_spake = true,
                "fast" => {}
                "armor-ccache" => out.armor_ccache = o.arg,
                "pkinit" => out.pkinit_identity = o.arg.as_deref().map(strip_file_spec),
                "pkinit-anchors" => out.pkinit_anchors = o.arg.as_deref().map(strip_file_spec),
                "enterprise" => out.enterprise = true,
                _ => return Err(format!("unrecognized option '--{name}'")),
            }
            continue;
        }
        match o.flag {
            'k' => out.keytab = true,
            't' => out.keytab_path = o.arg,
            'c' => out.ccache = o.arg,
            'r' => out.rlife = o.arg,
            'l' => out.lifetime = o.arg,
            'R' => out.renew = true,
            'f' => out.forwardable = Some(true),
            'F' => out.forwardable = Some(false),
            'p' => out.proxiable = Some(true),
            'P' => out.proxiable = Some(false),
            'a' => out.addresses = Some(true),
            'A' => out.addresses = Some(false),
            'S' => out.service = o.arg,
            'E' => out.enterprise = true,
            'n' => out.anonymous = true,
            'X' => {
                if let Some(v) = o.arg {
                    apply_x_attr(&mut out, &v);
                    out.pa_attrs.push(v);
                }
            }
            'T' => out.armor_ccache = o.arg,
            _ => return Err(format!("invalid option -- '{}'", o.flag)),
        }
    }
    split_kinit_positionals(&mut out, &rest);
    Ok(out)
}

fn apply_x_attr(out: &mut KinitArgs, v: &str) {
    if let Some(p) = v
        .strip_prefix("X509_user_identity=")
        .or_else(|| v.strip_prefix("X509_user_identity"))
    {
        let p = p.strip_prefix('=').unwrap_or(p);
        if !p.is_empty() {
            out.pkinit_identity = Some(strip_file_spec(p));
        }
    }
    if let Some(p) = v.strip_prefix("X509_anchors=") {
        out.pkinit_anchors = Some(strip_file_spec(p));
    }
}

fn strip_file_spec(s: &str) -> String {
    s.strip_prefix("FILE:").unwrap_or(s).to_owned()
}

fn split_kinit_positionals(out: &mut KinitArgs, rest: &[String]) {
    if rest.len() >= 2 && !rest[0].contains('@') && rest[1].contains('@') {
        out.kdc_host = Some(rest[0].clone());
        out.principal = Some(rest[1].clone());
        out.pos_ccache = rest.get(2).cloned();
        out.pos_service = rest.get(3).cloned();
        return;
    }
    if let Some(p) = rest.first() {
        out.principal = Some(p.clone());
    }
    if rest.len() >= 2 {
        out.pos_ccache = Some(rest[1].clone());
    }
    if rest.len() >= 3 {
        out.pos_service = Some(rest[2].clone());
    }
}

/// Parsed `klist` argv.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KlistArgs {
    /// `-c`.
    pub ccache: Option<String>,
    /// `-f`.
    pub flags: bool,
    /// `-e`.
    pub etype: bool,
    /// `-s`.
    pub silent: bool,
}

/// Parse `klist` arguments after argv0.
///
/// # Errors
///
/// Unknown option or missing argument.
pub fn parse_klist(args: &[String]) -> Result<KlistArgs, String> {
    let (opts, _rest) = getopt(args, "c:fes", &[])?;
    let mut out = KlistArgs::default();
    for o in opts {
        match o.flag {
            'c' => out.ccache = o.arg,
            'f' => out.flags = true,
            'e' => out.etype = true,
            's' => out.silent = true,
            _ => return Err(format!("invalid option -- '{}'", o.flag)),
        }
    }
    Ok(out)
}

/// Parsed `kvno` argv.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KvnoArgs {
    /// `-c`.
    pub ccache: Option<String>,
    /// Compat KDC host.
    pub kdc_host: Option<String>,
    /// Service principals.
    pub services: Vec<String>,
    /// `--disable-transited-check` (gate-only; MIT `kvno` cannot set bit 26).
    pub disable_transited_check: bool,
    /// `--body-realm` (gate-only): TGS-REQ realm with no chase. MIT clients
    /// never send a foreign `body.realm`.
    pub body_realm: Option<String>,
    /// `--renew` (gate-only): set KDC option RENEW (dest-RENEW cells).
    pub renew: bool,
    /// `-U` impersonated user (S4U2Self). Unlike MIT `kvno`, the ccache
    /// principal need not equal the service; the KDC enforces that.
    pub for_user: Option<String>,
}

fn kvno_longs() -> &'static [LongOpt] {
    &[
        LongOpt {
            name: "disable-transited-check",
            takes_arg: false,
            short: None,
        },
        LongOpt {
            name: "body-realm",
            takes_arg: true,
            short: None,
        },
        LongOpt {
            name: "renew",
            takes_arg: false,
            short: None,
        },
    ]
}

/// Parse `kvno` arguments after argv0.
///
/// # Errors
///
/// Unknown option or missing argument.
pub fn parse_kvno(args: &[String]) -> Result<KvnoArgs, String> {
    let (opts, rest) = getopt(args, "c:U:", kvno_longs())?;
    let mut out = KvnoArgs::default();
    for o in opts {
        if o.long == Some("disable-transited-check") {
            out.disable_transited_check = true;
            continue;
        }
        if o.long == Some("body-realm") {
            out.body_realm = o.arg;
            continue;
        }
        if o.long == Some("renew") {
            out.renew = true;
            continue;
        }
        match o.flag {
            'c' => out.ccache = o.arg,
            'U' => out.for_user = o.arg,
            _ => return Err(format!("invalid option -- '{}'", o.flag)),
        }
    }
    let mut pos = rest;
    if pos.len() >= 2 && !pos[0].contains('/') && !pos[0].contains('@') {
        out.kdc_host = Some(pos.remove(0));
    }
    out.services = pos;
    if out.renew && out.body_realm.is_none() {
        return Err(
            "requires --body-realm (gate-only; MIT kvno has no renew — `kinit -R` is `renew-gate.sh`)"
                .into(),
        );
    }
    Ok(out)
}

/// Parsed `kdestroy` argv.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KdestroyArgs {
    /// `-c`.
    pub ccache: Option<String>,
}

/// Parse `kdestroy` arguments after argv0.
///
/// # Errors
///
/// Unknown option or missing argument.
pub fn parse_kdestroy(args: &[String]) -> Result<KdestroyArgs, String> {
    let (opts, _rest) = getopt(args, "c:", &[])?;
    let mut out = KdestroyArgs::default();
    for o in opts {
        if o.flag == 'c' {
            out.ccache = o.arg;
        } else {
            return Err(format!("invalid option -- '{}'", o.flag));
        }
    }
    Ok(out)
}

/// MIT `klist.c` `check_ccache`: 0 if usable, 1 otherwise.
#[must_use]
pub fn check_ccache(cc: &FileCcache, now: u32) -> i32 {
    let realm = cc.primary.0.as_bytes();
    let mut found_tgt = false;
    let mut found_current_tgt = false;
    let mut found_current_cred = false;
    for cred in cc.list() {
        if is_local_tgt(cred, realm) {
            found_tgt = true;
            if cred.endtime > now {
                found_current_tgt = true;
            }
        } else if cred.endtime > now {
            found_current_cred = true;
        }
    }
    if found_tgt {
        i32::from(!found_current_tgt)
    } else {
        i32::from(!found_current_cred)
    }
}

fn is_local_tgt(cred: &CcacheCred, realm: &[u8]) -> bool {
    let s = &cred.server.1;
    cred.server.0.as_bytes() == realm
        && s.name_string.len() == 2
        && s.name_string[0].as_bytes() == b"krbtgt"
        && s.name_string[1].as_bytes() == realm
}

/// Prompt on stderr and strip a trailing newline (MIT `krb5_prompter_posix`).
///
/// # Errors
///
/// Stdin read failure.
pub fn read_password_line(principal: &str) -> Result<Vec<u8>, String> {
    eprint!("Password for {principal}: ");
    let mut s = String::new();
    std::io::stdin()
        .read_line(&mut s)
        .map_err(|_| "failed to read password from stdin".to_owned())?;
    Ok(s.trim_end_matches(['\n', '\r']).as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_crypto::{EncryptionType, ProtocolKey};
    use krb5_protocol::{CcacheKeyblock, realm};
    use krb5_types::PrincipalName;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn kinit_kt_cluster_is_keytab_plus_path() {
        let a = parse_kinit(&s(&["-kt", "/tmp/user.keytab", "user@KERBER.TEST"])).unwrap();
        assert!(a.keytab);
        assert_eq!(a.keytab_path.as_deref(), Some("/tmp/user.keytab"));
        assert_eq!(a.principal.as_deref(), Some("user@KERBER.TEST"));
        assert!(a.kdc_host.is_none());
    }

    #[test]
    fn kinit_clustered_fe_is_not_kinit() {
        let e = parse_kinit(&s(&["-fe"])).unwrap_err();
        assert!(e.contains("invalid option"), "{e}");
    }

    #[test]
    fn klist_fe_cluster() {
        let a = parse_klist(&s(&["-fe", "-c", "/tmp/cc"])).unwrap();
        assert!(a.flags && a.etype);
        assert_eq!(a.ccache.as_deref(), Some("/tmp/cc"));
        assert!(!a.silent);
    }

    #[test]
    fn klist_s_cluster_with_c() {
        let a = parse_klist(&s(&["-sc", "/tmp/cc"])).unwrap();
        assert!(a.silent);
        assert_eq!(a.ccache.as_deref(), Some("/tmp/cc"));
    }

    #[test]
    fn kvno_disable_transited_check_long_opt() {
        let a = parse_kvno(&s(&[
            "--disable-transited-check",
            "-c",
            "/tmp/cc",
            "host/x@R",
        ]))
        .unwrap();
        assert!(a.disable_transited_check);
        assert_eq!(a.ccache.as_deref(), Some("/tmp/cc"));
        assert_eq!(a.services, vec!["host/x@R".to_string()]);
        let b = parse_kvno(&s(&["-c", "/tmp/cc", "host/x@R"])).unwrap();
        assert!(!b.disable_transited_check);
        let u = parse_kvno(&s(&["-U", "admin", "host/x@R"])).unwrap();
        assert_eq!(u.for_user.as_deref(), Some("admin"));
        let r = parse_kvno(&s(&["--body-realm", "GARBAGE.EXAMPLE", "host/x@R"])).unwrap();
        assert_eq!(r.body_realm.as_deref(), Some("GARBAGE.EXAMPLE"));
        let n = parse_kvno(&s(&[
            "--renew",
            "--body-realm",
            "B.TEST",
            "krbtgt/C.TEST@C.TEST",
        ]))
        .unwrap();
        assert!(n.renew);
        assert_eq!(n.body_realm.as_deref(), Some("B.TEST"));
    }

    #[test]
    fn kvno_renew_requires_body_realm() {
        let e = parse_kvno(&s(&["--renew", "host/x@R"])).unwrap_err();
        assert!(e.contains("requires --body-realm"), "{e}");
    }

    #[test]
    fn kvno_for_user_with_realm_parses() {
        let u = parse_kvno(&s(&["-U", "victim@A.TEST", "user@C.TEST"])).unwrap();
        assert_eq!(u.for_user.as_deref(), Some("victim@A.TEST"));
        assert_eq!(u.services, vec!["user@C.TEST".to_string()]);
    }

    #[test]
    fn kinit_host_first_compat() {
        let a = parse_kinit(&s(&[
            "127.0.0.1",
            "user@KERBER.TEST",
            "/tmp/cc",
            "host/svc",
        ]))
        .unwrap();
        assert_eq!(a.kdc_host.as_deref(), Some("127.0.0.1"));
        assert_eq!(a.principal.as_deref(), Some("user@KERBER.TEST"));
        assert_eq!(a.pos_ccache.as_deref(), Some("/tmp/cc"));
        assert_eq!(a.pos_service.as_deref(), Some("host/svc"));
    }

    #[test]
    fn kinit_mit_flags() {
        let a = parse_kinit(&s(&[
            "-r", "7d", "-l", "5m", "-f", "-p", "-a", "-S", "host/x", "-E", "user@R",
        ]))
        .unwrap();
        assert_eq!(a.rlife.as_deref(), Some("7d"));
        assert_eq!(a.lifetime.as_deref(), Some("5m"));
        assert_eq!(a.forwardable, Some(true));
        assert_eq!(a.proxiable, Some(true));
        assert_eq!(a.addresses, Some(true));
        assert_eq!(a.service.as_deref(), Some("host/x"));
        assert!(a.enterprise);
        assert_eq!(a.principal.as_deref(), Some("user@R"));
    }

    fn sample(end: u32, server: PrincipalName) -> CcacheCred {
        let realm = realm("KERBER.TEST");
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
        let key = ProtocolKey::from_bytes(EncryptionType::Aes128CtsHmacSha196, &[0u8; 16]).unwrap();
        CcacheCred {
            client: (realm.clone(), user),
            server: (realm, server),
            key: CcacheKeyblock::from_protocol(&key),
            authtime: 1_700_000_000,
            starttime: 1_700_000_000,
            endtime: end,
            renew_till: 0,
            is_skey: 0,
            ticket_flags: 0,
            addresses: Vec::new(),
            authdata: Vec::new(),
            ticket: Vec::new(),
            second_ticket: Vec::new(),
        }
    }

    #[test]
    fn check_ccache_uses_local_tgt_not_service() {
        let now = 1_700_100_000;
        let live_tgt = sample(now + 100, PrincipalName::krbtgt("KERBER.TEST"));
        let cc = FileCcache::new(live_tgt.client.clone(), vec![live_tgt]);
        assert_eq!(check_ccache(&cc, now), 0);

        let dead_tgt = sample(now - 1, PrincipalName::krbtgt("KERBER.TEST"));
        let live_svc = sample(
            now + 100,
            PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc"]),
        );
        let mixed = FileCcache::new(dead_tgt.client.clone(), vec![dead_tgt, live_svc]);
        assert_eq!(check_ccache(&mixed, now), 1);

        let only_svc = sample(
            now + 100,
            PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc"]),
        );
        let svc_cc = FileCcache::new(only_svc.client.clone(), vec![only_svc]);
        assert_eq!(check_ccache(&svc_cc, now), 0);
    }
}
