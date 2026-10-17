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
