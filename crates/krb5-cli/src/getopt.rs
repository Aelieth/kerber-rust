#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opt {
    pub flag: char,
    pub long: Option<&'static str>,
    pub arg: Option<String>,
}

#[derive(Clone, Copy, Debug)]
pub struct LongOpt {
    pub name: &'static str,
    pub takes_arg: bool,
    pub short: Option<char>,
}

/// A leading plus in the optstring stops at the first operand.
pub fn getopt(
    args: &[String],
    optstring: &str,
    longs: &[LongOpt],
) -> Result<(Vec<Opt>, Vec<String>), String> {
    let (each, rest) = getopt_each(args, optstring, longs);
    let opts = each.into_iter().collect::<Result<Vec<_>, _>>()?;
    Ok((opts, rest))
}

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
