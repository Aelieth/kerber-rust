#![no_main]
use libfuzzer_sys::fuzz_target;
use krb5_types::{OctetString, TransitedEncoding};

const MAX_TRANSIT_REALMS: usize = 256;
const MAX_TRANSIT_RAW: usize = 512;

fn strip_nul(data: &[u8]) -> &[u8] {
    match data.split_last() {
        Some((0, rest)) => rest,
        _ => data,
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
    let t = TransitedEncoding {
        tr_type: 1,
        contents: OctetString::from(data.to_vec()),
    };
    let got = t.realms_for("", "");
    let stripped = strip_nul(data);
    let commas = stripped.iter().filter(|&&b| b == b',').count();
    let fields = unescaped_fields(stripped);
    let raw_over = fields.iter().any(|f| f.len() >= MAX_TRANSIT_RAW);
    if commas > MAX_TRANSIT_REALMS || raw_over {
        assert!(got.is_err());
        return;
    }
    let Ok(hops) = got else {
        return;
    };
    if data.contains(&b'\\') {
        return;
    }
    if stripped.starts_with(b",")
        || stripped.ends_with(b",")
        || stripped.windows(2).any(|w| w == b",,")
    {
        return;
    }
    let n = stripped
        .split(|&b| b == b',')
        .filter(|f| f.iter().any(|&b| b != b' '))
        .count();
    assert_eq!(hops.len(), n);
});
