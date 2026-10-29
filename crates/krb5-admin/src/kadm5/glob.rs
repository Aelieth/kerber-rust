//! Pre-flight: MIT `regcomp` EINVAL.

use krb5_kdc::PrincipalStore;

// MIT: `kadm5_get_either` (svr_iters.c:175-175)
#[must_use]
pub fn glob_pattern_ok(glob: &str) -> bool {
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

/// Append `@*` when no realm; MIT's regexp form is `@.*`.
pub(crate) fn glob_expand(glob: &str, append_realm: bool) -> String {
    if append_realm && !glob.contains('@') {
        format!("{glob}@*")
    } else {
        glob.to_owned()
    }
}

// MIT: `get_either_iter` (svr_iters.c:111-115)
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

pub(crate) fn principals_matching(store: &PrincipalStore, expr: Option<&str>) -> Vec<String> {
    let ids = store.ids();
    match expr {
        Some(g) if g != "*" => {
            let pat = glob_expand(g, true);
            ids.into_iter()
                .filter(|id| glob_is_match(pat.as_bytes(), id.as_bytes()))
                .collect()
        }
        _ => ids,
    }
}

pub(crate) fn policies_matching(store: &PrincipalStore, expr: Option<&str>) -> Vec<String> {
    let pat = expr.filter(|g| *g != "*").map(|g| glob_expand(g, false));
    let mut names: Vec<String> = store
        .policies()
        .keys()
        .filter(|n| {
            pat.as_deref()
                .is_none_or(|p| glob_is_match(p.as_bytes(), n.as_bytes()))
        })
        .cloned()
        .collect();
    names.sort();
    names
}
