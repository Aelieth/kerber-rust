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
/// An error message when an option is not in `optstring` or `longs`, an option that takes an
/// argument has none, or a long option that takes none is given one (`--name=value`).
pub fn getopt(
    args: &[String],
    optstring: &str,
    longs: &[LongOpt],
) -> Result<(Vec<Opt>, Vec<String>), String> {
    let (stop_at_operand, optstring) = match optstring.strip_prefix('+') {
        Some(rest) => (true, rest),
        None => (false, optstring),
    };
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
        if stop_at_operand {
            rest.extend(args[i..].iter().cloned());
            break;
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
    }
}
