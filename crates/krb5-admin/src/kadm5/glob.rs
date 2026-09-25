//! Principal and policy name globbing for `GET_PRINCS` / `GET_POLS`
//! (`svr_iters.c` `glob_to_regexp`): the pre-flight MIT answers `EINVAL`
//! for, and the match itself with POSIX bracket classes.

/// MIT `kadm5_get_either` (`svr_iters.c:175-175`): MIT compiles the glob to a POSIX BRE with `regcomp`; a
/// pattern that fails to compile (trailing `\\`, an unterminated `[...]`) is
/// `EINVAL` from `kadm5_get_either`. This mirrors that pre-flight.
#[must_use]
pub fn glob_pattern_ok(glob: &str) -> bool {
    // MIT's `ss_parse` unescapes a `\\` pair before `glob_to_regexp`; the Rust
    // tokenizer does not, so a pattern ending in a backslash is `EINVAL` either
    // way (a lone trailing `\` fails `regcomp`; MIT unescapes a `\\` pair to a
    // lone trailing `\` and then fails).
    if glob.ends_with('\\') {
        return false;
    }
    let b = glob.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' => {
                if i + 1 >= b.len() {
                    return false;
                }
                i += 2;
            }
            b'[' => {
                let mut j = i + 1;
                if b.get(j) == Some(&b'^') {
                    j += 1;
                }
                if b.get(j) == Some(&b']') {
                    j += 1;
                }
                while j < b.len() && b[j] != b']' {
                    if b[j] == b'[' && b.get(j + 1) == Some(&b':') {
                        j += 2;
                        while j + 1 < b.len() && !(b[j] == b':' && b[j + 1] == b']') {
                            j += 1;
                        }
                        if j + 1 >= b.len() {
                            return false;
                        }
                        j += 2;
                    } else {
                        j += 1;
                    }
                }
                if j >= b.len() {
                    return false;
                }
                i = j + 1;
            }
            _ => i += 1,
        }
    }
    true
}

/// POSIX character classes MIT's BRE accepts inside `[...]`.
fn posix_class_match(name: &[u8], c: u8) -> bool {
    match name {
        b"digit" => c.is_ascii_digit(),
        b"alpha" => c.is_ascii_alphabetic(),
        b"alnum" => c.is_ascii_alphanumeric(),
        b"upper" => c.is_ascii_uppercase(),
        b"lower" => c.is_ascii_lowercase(),
        b"space" => c.is_ascii_whitespace(),
        b"blank" => c == b' ' || c == b'\t',
        b"punct" => c.is_ascii_punctuation(),
        b"xdigit" => c.is_ascii_hexdigit(),
        _ => false,
    }
}

/// Append `@*` when a principal glob has no realm (`svr_iters.c` implicit `@*`).
pub(crate) fn glob_expand(glob: &str, append_realm: bool) -> String {
    if append_realm && !glob.contains('@') {
        format!("{glob}@*")
    } else {
        glob.to_owned()
    }
}

/// MIT `glob_to_regexp` (`svr_iters.c:55-109`): `glob_to_regexp` + `regexec` as a direct anchored
/// matcher: `?`=one, `*`=run, `[...]`=class, `\\x`=literal.
pub(crate) fn glob_is_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star_p, mut star_t): (Option<usize>, usize) = (None, 0);
    while t < text.len() {
        let mut matched = false;
        if p < pattern.len() {
            match pattern[p] {
                b'?' => {
                    p += 1;
                    t += 1;
                    matched = true;
                }
                b'*' => {
                    star_p = Some(p);
                    star_t = t;
                    p += 1;
                    matched = true;
                }
                b'[' => {
                    if let Some((ok, np)) = glob_class(&pattern[p..], text[t]) {
                        if ok {
                            p += np;
                            t += 1;
                            matched = true;
                        }
                    } else if pattern[p] == text[t] {
                        p += 1;
                        t += 1;
                        matched = true;
                    }
                }
                b'\\' if p + 1 < pattern.len() => {
                    if pattern[p + 1] == text[t] {
                        p += 2;
                        t += 1;
                        matched = true;
                    }
                }
                c => {
                    if c == text[t] {
                        p += 1;
                        t += 1;
                        matched = true;
                    }
                }
            }
        }
        if matched {
            continue;
        }
        if let Some(sp) = star_p {
            p = sp + 1;
            star_t += 1;
            t = star_t;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

/// Match one `[...]` class at the start of `pat`; `Some((matched, consumed))`
/// or `None` when the class is malformed (treat `[` as a literal).
fn glob_class(pat: &[u8], c: u8) -> Option<(bool, usize)> {
    let mut i = 1;
    let negate = pat.get(i) == Some(&b'^');
    if negate {
        i += 1;
    }
    let mut matched = false;
    let start = i;
    while i < pat.len() && (pat[i] != b']' || i == start) {
        if pat[i] == b'[' && pat.get(i + 1) == Some(&b':') {
            let mut k = i + 2;
            while k + 1 < pat.len() && !(pat[k] == b':' && pat[k + 1] == b']') {
                k += 1;
            }
            if posix_class_match(&pat[i + 2..k], c) {
                matched = true;
            }
            i = k + 2;
        } else if i + 2 < pat.len() && pat[i + 1] == b'-' && pat[i + 2] != b']' {
            if pat[i] <= c && c <= pat[i + 2] {
                matched = true;
            }
            i += 3;
        } else {
            if pat[i] == c {
                matched = true;
            }
            i += 1;
        }
    }
    if i >= pat.len() || pat[i] != b']' {
        return None;
    }
    Some((matched != negate, i + 1))
}
