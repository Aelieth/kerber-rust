//! glibc `getopt` / `getopt_long`, as the MIT tools built on it parse their argv.

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

/// Split `args` (no argv0) into options and operands. Clustering is POSIX. Operands may come
/// between options, as glibc permutes them, unless `optstring` starts with `+`: then the first
/// operand ends the options and it and every argument after it are operands (`kadmin.local`'s
/// `+x:r:p:…`, so a query's own `-pw` stays the query's). `--` ends the options either way.
///
/// # Errors
///
/// The first of [`getopt_each`]'s complaints: an option not in `optstring` or `longs`, an option
/// that takes an argument with none, or a long option that takes none given one
/// (`--name=value`).
pub fn getopt(
    args: &[String],
    optstring: &str,
    longs: &[LongOpt],
) -> Result<(Vec<Opt>, Vec<String>), String> {
    let (each, rest) = getopt_each(args, optstring, longs);
    let opts = each.into_iter().collect::<Result<Vec<_>, _>>()?;
    Ok((opts, rest))
}

/// [`getopt`] that goes on past a bad option, as glibc's does: each option or glibc's complaint
/// about it (`Err`), in argv order, and the operands.
#[must_use]
pub fn getopt_each(
    args: &[String],
    optstring: &str,
    longs: &[LongOpt],
) -> (Vec<Result<Opt, String>>, Vec<String>) {
    let (stop_at_operand, optstring) = match optstring.strip_prefix('+') {
        Some(rest) => (true, rest),
        None => (false, optstring),
    };
    let mut each = Vec::new();
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            rest.extend(args[i + 1..].iter().cloned());
            break;
        }
        if let Some(whole) = a.strip_prefix("--") {
            let (name, inline) = match whole.split_once('=') {
                Some((n, v)) => (n, Some(v.to_owned())),
                None => (whole, None),
            };
            i += 1;
            let spec = match long_named(longs, name) {
                Ok(spec) => spec,
                Err(None) => {
                    each.push(Err(format!("unrecognized option '--{whole}'")));
                    continue;
                }
                Err(Some(names)) => {
                    each.push(Err(format!(
                        "option '--{whole}' is ambiguous; possibilities:{names}"
                    )));
                    continue;
                }
            };
            // glibc `process_long_option`: a missing or unwanted argument is named by the option matched, not the prefix typed. An unknown or ambiguous option stays named by the text typed.
            let arg = match (spec.takes_arg, inline) {
                (true, Some(v)) => Some(v),
                (true, None) => {
                    let Some(v) = args.get(i) else {
                        each.push(Err(format!(
                            "option '--{}' requires an argument",
                            spec.name
                        )));
                        break;
                    };
                    i += 1;
                    Some(v.clone())
                }
                (false, Some(_)) => {
                    each.push(Err(format!(
                        "option '--{}' doesn't allow an argument",
                        spec.name
                    )));
                    continue;
                }
                (false, None) => None,
            };
            each.push(Ok(Opt {
                flag: spec.short.unwrap_or('\0'),
                long: Some(spec.name),
                arg,
            }));
            continue;
        }
        if a.starts_with('-') && a.len() > 1 {
            let chars: Vec<char> = a[1..].chars().collect();
            i += 1;
            let mut ci = 0;
            while ci < chars.len() {
                let c = chars[ci];
                ci += 1;
                let wants = match opt_wants_arg(optstring, c) {
                    Ok(w) => w,
                    Err(e) => {
                        each.push(Err(e));
                        continue;
                    }
                };
                let arg = if !wants {
                    None
                } else if ci < chars.len() {
                    let inline: String = chars[ci..].iter().collect();
                    ci = chars.len();
                    Some(inline)
                } else if let Some(v) = args.get(i) {
                    i += 1;
                    Some(v.clone())
                } else {
                    each.push(Err(format!("option requires an argument -- '{c}'")));
                    break;
                };
                each.push(Ok(Opt {
                    flag: c,
                    long: None,
                    arg,
                }));
            }
            continue;
        }
        if stop_at_operand {
            rest.extend(args[i..].iter().cloned());
            break;
        }
        rest.push(a.clone());
        i += 1;
    }
    (each, rest)
}

/// The long option `name` names: its exact match, else the one option it is a prefix of. `Err`
/// carries, for a prefix of several, the possibilities as glibc lists them (` '--a' '--b'`).
/// As glibc's `getopt_long`: an exact name wins, a prefix of one option is that option, and a
/// prefix of options that differ is ambiguous (live MIT 1.22.2 `kvno --cached`, `--no-st`).
fn long_named<'a>(longs: &'a [LongOpt], name: &str) -> Result<&'a LongOpt, Option<String>> {
    if let Some(exact) = longs.iter().find(|l| l.name == name) {
        return Ok(exact);
    }
    let found: Vec<&LongOpt> = longs
        .iter()
        .filter(|l| !name.is_empty() && l.name.starts_with(name))
        .collect();
    match found.as_slice() {
        [] => Err(None),
        [first, rest @ ..]
            if rest.iter().all(|l| {
                l.takes_arg == first.takes_arg && l.short.is_some() && l.short == first.short
            }) =>
        {
            Ok(first)
        }
        all => Err(Some(all.iter().fold(String::new(), |mut names, l| {
            names.push_str(" '--");
            names.push_str(l.name);
            names.push('\'');
            names
        }))),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    fn letters(opts: &[Opt]) -> Vec<(char, Option<&str>)> {
        opts.iter().map(|o| (o.flag, o.arg.as_deref())).collect()
    }

    /// MIT `initialize_realms` (`kdc/main.c:669-669`): krb5kdc's optstring.
    const KRB5KDC: &str = "x:r:d:mM:k:R:P:p:nw:4:T:X3";
    /// MIT `kadmin_startup` (`kadmin/cli/kadmin.c:315-316`): kadmin.local's optstring.
    const KADMIN: &str = "+x:r:p:knq:w:d:s:mc:t:e:ON";

    #[test]
    fn values_separate_attached_and_clustered() {
        let (opts, rest) = getopt(
            &s(&["-n", "-rA.TEST", "-p", "88", "-nr", "B.TEST"]),
            KRB5KDC,
            &[],
        )
        .unwrap();
        assert_eq!(
            letters(&opts),
            [
                ('n', None),
                ('r', Some("A.TEST")),
                ('p', Some("88")),
                ('n', None),
                ('r', Some("B.TEST")),
            ]
        );
        assert_eq!(rest, [] as [String; 0]);
    }

    #[test]
    fn operands_between_options_are_permuted_without_plus() {
        let (opts, rest) = getopt(&s(&["extra", "-n", "more"]), KRB5KDC, &[]).unwrap();
        assert_eq!(letters(&opts), [('n', None)]);
        assert_eq!(rest, ["extra", "more"]);
    }

    #[test]
    fn plus_stops_at_the_first_operand() {
        let argv = s(&["-r", "A.TEST", "addprinc", "-pw", "secret", "-q", "user"]);
        let (opts, rest) = getopt(&argv, KADMIN, &[]).unwrap();
        assert_eq!(letters(&opts), [('r', Some("A.TEST"))]);
        assert_eq!(rest, ["addprinc", "-pw", "secret", "-q", "user"]);
    }

    #[test]
    fn double_dash_ends_the_options() {
        let (opts, rest) = getopt(&s(&["-n", "--", "-r", "x"]), KRB5KDC, &[]).unwrap();
        assert_eq!(letters(&opts), [('n', None)]);
        assert_eq!(rest, ["-r", "x"]);
    }

    #[test]
    fn errors_are_glibc_worded() {
        assert_eq!(
            getopt(&s(&["-Z"]), KRB5KDC, &[]).unwrap_err(),
            "invalid option -- 'Z'"
        );
        assert_eq!(
            getopt(&s(&["-r"]), KRB5KDC, &[]).unwrap_err(),
            "option requires an argument -- 'r'"
        );
        assert_eq!(
            getopt(&s(&["-+"]), KADMIN, &[]).unwrap_err(),
            "invalid option -- '+'"
        );
    }

    #[test]
    fn long_options_take_inline_or_next_values() {
        let longs = [
            LongOpt {
                name: "armor-ccache",
                takes_arg: true,
                short: Some('T'),
            },
            LongOpt {
                name: "spake",
                takes_arg: false,
                short: None,
            },
        ];
        let (opts, _) = getopt(
            &s(&["--armor-ccache=/a", "--spake", "--armor-ccache", "/b"]),
            "T:",
            &longs,
        )
        .unwrap();
        assert_eq!(opts[0].arg.as_deref(), Some("/a"));
        assert_eq!(opts[1].long, Some("spake"));
        assert_eq!((opts[2].flag, opts[2].arg.as_deref()), ('T', Some("/b")));
        assert_eq!(
            getopt(&s(&["--spake=1"]), "", &longs).unwrap_err(),
            "option '--spake' doesn't allow an argument"
        );
        assert_eq!(
            getopt(&s(&["--armor-ccache"]), "T:", &longs).unwrap_err(),
            "option '--armor-ccache' requires an argument"
        );
        assert_eq!(
            getopt(&s(&["--nope=1"]), "", &longs).unwrap_err(),
            "unrecognized option '--nope=1'"
        );
        // Live MIT 1.22.2 `kvno --out` / `kvno --cached=1`: a prefix's complaint names the option in full.
        assert_eq!(
            getopt(&s(&["--armor"]), "T:", &longs).unwrap_err(),
            "option '--armor-ccache' requires an argument"
        );
        assert_eq!(
            getopt(&s(&["--spa=1"]), "", &longs).unwrap_err(),
            "option '--spake' doesn't allow an argument"
        );
    }

    #[test]
    fn long_names_take_a_unique_prefix() {
        let longs = [
            LongOpt {
                name: "cached-only",
                takes_arg: false,
                short: None,
            },
            LongOpt {
                name: "renew",
                takes_arg: false,
                short: None,
            },
            LongOpt {
                name: "renew-ticket",
                takes_arg: false,
                short: None,
            },
        ];
        let (opts, _) = getopt(&s(&["--cached", "--renew"]), "", &longs).unwrap();
        assert_eq!(opts[0].long, Some("cached-only"));
        assert_eq!(opts[1].long, Some("renew"));
        assert_eq!(
            getopt(&s(&["--ren"]), "", &longs).unwrap_err(),
            "option '--ren' is ambiguous; possibilities: '--renew' '--renew-ticket'"
        );
    }

    /// glibc's `getopt` reports a bad option and goes on with the rest of argv (live MIT 1.22.2
    /// `kinit --pkinit /x alice`: the complaint, then `Extra arguments (starting with "alice").`).
    #[test]
    fn each_goes_on_past_a_bad_option() {
        let (each, rest) = getopt_each(&s(&["-Zn", "--x", "a", "-r", "R", "b"]), KRB5KDC, &[]);
        assert_eq!(
            each,
            [
                Err("invalid option -- 'Z'".to_owned()),
                Ok(Opt {
                    flag: 'n',
                    long: None,
                    arg: None
                }),
                Err("unrecognized option '--x'".to_owned()),
                Ok(Opt {
                    flag: 'r',
                    long: None,
                    arg: Some("R".to_owned())
                }),
            ]
        );
        assert_eq!(rest, ["a", "b"]);
    }
}
