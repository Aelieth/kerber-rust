//! Obtain a TGT from a KDC and write an MIT FILE ccache.
//!
//! Usage matches MIT `kinit`: `kinit [-kt keytab] [-c cache] [-r life] [-l life]
//! [-s start] [-R] [-v] [-f|-F] [-p|-P] [-a|-A] [-S service] [-C] [-E] [-n]
//! [-X attr=val] [principal]`

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::path::Path;

use krb5_client::cli::{parse_kinit, read_password_line, read_prompt_line};
use krb5_client::{
    KinitParams, NewPasswordPrompter, kinit_with, local_host_addresses, mit_error_code,
};
use krb5_config::{env_ktname, env_new_password, env_password, parse_deltat, resolve_ccspec};
use krb5_protocol::{AsTicketOpts, KdcAddr, parse_principal_ex};
use zeroize::Zeroize;

fn main() {
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter("krb5_crypto=info,krb5_asn1=info,krb5_protocol=info,krb5_client=info")
        .try_init();

    let raw: Vec<String> = std::env::args().skip(1).collect();
    let args = parse_kinit(&raw).unwrap_or_else(|e| {
        eprintln!("kinit: {e}");
        std::process::exit(2);
    });
    let principal = if args.anonymous {
        if let Some(p) = args.principal.clone() {
            p
        } else {
            let realm = krb5_config::load_krb5_conf()
                .and_then(|c| c.default_realm)
                .unwrap_or_else(|| {
                    eprintln!("kinit: cannot determine default realm");
                    std::process::exit(1);
                });
            format!("WELLKNOWN/ANONYMOUS@{realm}")
        }
    } else {
        args.principal.clone().unwrap_or_else(|| {
            eprintln!("kinit: missing principal");
            std::process::exit(2);
        })
    };
    let principal = if !args.enterprise && !principal.contains('@') {
        match krb5_config::load_krb5_conf_paths(krb5_config::krb5_conf_paths()) {
            Ok(c) => match c.default_realm {
                Some(r) => format!("{principal}@{r}"),
                None => principal,
            },
            Err(e) => {
                eprintln!("kinit: {e}");
                std::process::exit(1);
            }
        }
    } else {
        principal
    };
    let service = args.service.clone().or(args.pos_service.clone());
    let ccflag = args.ccache.clone().or(args.pos_ccache.clone());
    let spec = resolve_ccspec(ccflag.as_deref()).unwrap_or_else(|e| {
        eprintln!("kinit: {e}");
        std::process::exit(2);
    });
    let (_, mut realm) = parse_principal_ex(&principal, args.enterprise).unwrap_or_else(|e| {
        eprintln!("kinit: {e}");
        std::process::exit(2);
    });
    if realm.is_empty() {
        realm = krb5_config::load_krb5_conf()
            .and_then(|c| c.default_realm)
            .unwrap_or_default();
    }
    let addr = kdc_addr(args.kdc_host.as_deref(), &realm).unwrap_or_else(|e| {
        eprintln!("kinit: {e}");
        std::process::exit(2);
    });
    if args.want_spake && (args.armor_ccache.is_some() || args.pkinit_identity.is_some()) {
        eprintln!("--spake cannot be combined with --armor-ccache or --pkinit");
        std::process::exit(2);
    }
    let conf = krb5_config::load_krb5_conf();
    let mut ticket = AsTicketOpts {
        lifetime: args
            .lifetime
            .as_deref()
            .and_then(parse_deltat)
            .or_else(|| conf.as_ref().and_then(|c| c.ticket_lifetime)),
        rlife: args
            .rlife
            .as_deref()
            .and_then(parse_deltat)
            .or_else(|| conf.as_ref().and_then(|c| c.renew_lifetime)),
        forwardable: args
            .forwardable
            .unwrap_or_else(|| conf.as_ref().is_none_or(|c| c.forwardable)),
        proxiable: args
            .proxiable
            .unwrap_or_else(|| conf.as_ref().is_none_or(|c| c.proxiable)),
        addresses: None,
        anonymous: args.anonymous,
        starttime: args.starttime.as_deref().map(|s| {
            parse_deltat(s).unwrap_or_else(|| {
                eprintln!("kinit: Bad start time value {s}");
                std::process::exit(2);
            })
        }),
    };
    if args.addresses == Some(true) {
        ticket.addresses = local_host_addresses();
    }
    let mut password = if args.keytab
        || args.renew
        || args.validate
        || args.pkinit_identity.is_some()
        || args.anonymous
    {
        Vec::new()
    } else {
        env_password().unwrap_or_else(|| {
            read_password_line(&principal).unwrap_or_else(|e| {
                eprintln!("kinit: {e}");
                std::process::exit(2);
            })
        })
    };
    let kt_path = args.keytab_path.clone().or_else(|| {
        args.keytab.then(|| {
            env_ktname().map_or_else(
                || "/etc/krb5.keytab".to_owned(),
                |p| p.to_string_lossy().into_owned(),
            )
        })
    });
    let armor = args.armor_ccache.clone();
    let pk_id = args.pkinit_identity.clone();
    let pk_an = args.pkinit_anchors.clone();
    let new_password = env_new_password();
    // kinit.c:625-633 `pwprompt`: the password came from the user, so a
    // PREAUTH_FAILED is reported as "Password incorrect" (`:785-790`).
    let pw_auth = !(args.keytab
        || args.renew
        || args.validate
        || args.pkinit_identity.is_some()
        || args.anonymous);
    // gic_pwd.c:238-263 through `kinit_prompter` (kinit.c:620-640): the
    // banner, then `Enter new password` / `Enter it again`.
    let prompter = |banner: &str| -> Result<(Vec<u8>, Vec<u8>), String> {
        // `krb5_prompter_posix` prints the banner on stdout (`prompter.c:54`).
        println!("{banner}");
        let a = read_prompt_line("Enter new password: ")?;
        let b = read_prompt_line("Enter it again: ")?;
        Ok((a, b))
    };
    {
        let params = KinitParams {
            service: service.as_deref(),
            want_spake: args.want_spake,
            armor_ccache: armor.as_deref().map(Path::new),
            pkinit_identity: pk_id.as_deref().map(Path::new),
            pkinit_anchors: pk_an.as_deref().map(Path::new),
            enterprise: args.enterprise,
            keytab: if args.keytab {
                kt_path.as_deref().map(Path::new)
            } else {
                None
            },
            ticket: ticket.clone(),
            renew: args.renew,
            validate: args.validate,
            anonymous: args.anonymous,
            canonicalize: args.canonicalize
                || args.enterprise
                || conf.as_ref().is_some_and(|c| c.canonicalize),
            new_password: new_password.as_deref(),
            prompter: (!args.keytab).then_some(NewPasswordPrompter(&prompter)),
        };
        match kinit_with(&addr, &principal, &mut password, &spec, params) {
            Ok(r) => {
                println!(
                    "ok tgt={} tgs={}",
                    r.as_out.enc_part.sname.name_string.len(),
                    r.tgs_out.is_some()
                );
            }
            Err(e) => {
                // kinit.c:785-793: BAD_INTEGRITY, or PREAUTH_FAILED after a
                // password prompt, is "Password incorrect while getting
                // initial credentials".
                match mit_error_code(e.as_ref()) {
                    Some(krb5_types::err::BAD_INTEGRITY) => {
                        eprintln!("kinit: Password incorrect while getting initial credentials");
                    }
                    Some(krb5_types::err::PREAUTH_FAILED) if pw_auth => {
                        eprintln!("kinit: Password incorrect while getting initial credentials");
                    }
                    _ => eprintln!("kinit failed: {e}"),
                }
                std::process::exit(1);
            }
        }
    }
    if let Some(mut n) = new_password {
        n.zeroize();
    }
}

fn kdc_addr(host: Option<&str>, realm: &str) -> Result<KdcAddr, String> {
    if let Some(host) = host {
        return Ok(parse_host(host));
    }
    krb5_config::discover_kdc(realm)
        .map(|ep| KdcAddr {
            host: ep.host,
            port: ep.port,
        })
        .ok_or_else(|| format!("Cannot find KDC for requested realm {realm}"))
}

fn parse_host(host: &str) -> KdcAddr {
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

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_client::cli::parse_kinit;

    #[test]
    fn ccache_path_flag_beats_positional() {
        let a = parse_kinit(&[
            "-c".into(),
            "FILE:/tmp/a".into(),
            "127.0.0.1".into(),
            "user@R".into(),
            "/tmp/b".into(),
        ])
        .unwrap();
        let spec = resolve_ccspec(a.ccache.as_deref().or(a.pos_ccache.as_deref())).unwrap();
        assert_eq!(
            spec,
            krb5_config::CcSpec::File(std::path::PathBuf::from("/tmp/a"))
        );
    }

    #[test]
    fn ccache_path_rejects_keyring() {
        let e = resolve_ccspec(Some("KEYRING:user:foo")).unwrap_err();
        assert_eq!(e, krb5_config::KRB5_CC_UNKNOWN_TYPE);
        assert!(!e.contains("G8"), "{e}");
        assert_eq!(
            resolve_ccspec(Some("KCM:")).unwrap(),
            krb5_config::CcSpec::Kcm(String::new())
        );
        let e = resolve_ccspec(Some("NOTATYPE:x")).unwrap_err();
        assert_eq!(e, krb5_config::KRB5_CC_UNKNOWN_TYPE);
    }

    #[test]
    fn ccache_path_default_is_uid_file() {
        assert_eq!(
            resolve_ccspec(None).unwrap(),
            krb5_config::CcSpec::File(krb5_config::default_ccache_name())
        );
    }

    #[test]
    fn parse_host_splits_port() {
        let a = parse_host("127.0.0.1:8889");
        assert_eq!(a.host, "127.0.0.1");
        assert_eq!(a.port, 8889);
    }
}
