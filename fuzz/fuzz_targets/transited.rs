#![no_main]
use libfuzzer_sys::fuzz_target;
use krb5_types::{MAX_TRANSIT_HOPS, MAX_TRANSIT_RAW, MAX_TRANSIT_REALMS, OctetString, TransitedEncoding};

fn strip_nul(data: &[u8]) -> &[u8] {
    match data.split_last() {
        Some((0, rest)) => rest,
        _ => data,
    }
}

fn take_cstr(data: &[u8]) -> (&[u8], &[u8]) {
    match data.iter().position(|&b| b == 0) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &[]),
    }
}

fn unescaped_fields(data: &[u8]) -> Vec<String> {
    let s = String::from_utf8_lossy(data);
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut escaped = false;
    for c in s.chars() {
        if escaped {
            cur.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            ',' => {
                fields.push(std::mem::take(&mut cur));
            }
            ' ' if cur.is_empty() => {}
            _ => cur.push(c),
        }
    }
    fields.push(cur);
    fields
}

fuzz_target!(|data: &[u8]| {
    let (crealm_b, rest) = take_cstr(data);
    let (srealm_b, contents) = take_cstr(rest);
    let crealm = String::from_utf8_lossy(crealm_b);
    let srealm = String::from_utf8_lossy(srealm_b);
    let t = TransitedEncoding {
        tr_type: 1,
        contents: OctetString::from(contents.to_vec()),
    };
    let got = t.realms_for(&crealm, &srealm);
    let stripped = strip_nul(contents);
    if stripped.is_empty() {
        assert!(got.as_ref().is_ok_and(Vec::is_empty));
        return;
    }
    let commas = stripped.iter().filter(|&&b| b == b',').count();
    let fields = unescaped_fields(stripped);
    let raw_over = fields.iter().any(|f| f.len() >= MAX_TRANSIT_RAW);
    if commas > MAX_TRANSIT_REALMS || raw_over {
        assert!(got.is_err());
        return;
    }
    let empty_field = fields.iter().any(String::is_empty);
    let joins = fields
        .iter()
        .any(|f| f.starts_with('/') || f.ends_with('.'));
    let literal = !contents.contains(&b'\\') && !empty_field && !joins;
    if literal {
        assert!(got.is_ok(), "well-formed transited must expand");
    }
    let Ok(hops) = got else {
        return;
    };
    assert!(hops.len() <= MAX_TRANSIT_HOPS);
    if literal {
        assert_eq!(hops.len(), fields.len());
    }
});
