#![no_main]
use libfuzzer_sys::fuzz_target;
use krb5_types::{OctetString, TransitedEncoding};

const MAX_TRANSIT_REALMS: usize = 256;

fuzz_target!(|data: &[u8]| {
    let t = TransitedEncoding {
        tr_type: 1,
        contents: OctetString::from(data.to_vec()),
    };
    let hops = t.realms();
    let commas = data.iter().filter(|&&b| b == b',').count();
    if commas > MAX_TRANSIT_REALMS {
        assert_eq!(hops.as_slice(), ["\0"]);
        return;
    }
    if hops.as_slice() == ["\0"] {
        return;
    }
    assert!(hops.len() <= MAX_TRANSIT_REALMS + 1);
    if data.contains(&b'\\') {
        return;
    }
    let fields = data
        .split(|&b| b == b',')
        .filter(|f| f.iter().any(|&b| b != b' '))
        .count();
    assert_eq!(hops.len(), fields);
});
