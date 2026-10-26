// MIT: `k5_der_len_len` (include/k5-der.h:68-68)
#[must_use]
pub const fn len_len(len: usize) -> usize {
    if len < 128 {
        return 1;
    }
    let mut n = len;
    let mut llen = 1;
    while n > 0 {
        n >>= 8;
        llen += 1;
    }
    llen
}

// MIT: `k5_der_add_taglen` (include/k5-der.h:102-102)
pub fn push_len(out: &mut Vec<u8>, len: usize) {
    let llen = len_len(len);
    if llen == 1 {
        out.push(u8::try_from(len).unwrap_or_default());
        return;
    }
    out.push(0x80 | u8::try_from(llen - 1).unwrap_or_default());
    let bytes = len.to_be_bytes();
    out.extend_from_slice(&bytes[bytes.len() - (llen - 1)..]);
}

// MIT: `k5_der_add_value` (include/k5-der.h:99-101)
pub fn push_tlv(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    out.push(tag);
    push_len(out, value.len());
    out.extend_from_slice(value);
}

// MIT: `get_tag` (lib/krb5/asn.1/asn1_encode.c:351-425)
#[must_use]
pub fn read_len(input: &[u8]) -> Option<(usize, usize)> {
    let first = *input.first()?;
    let (len, hlen) = if first < 0x80 {
        (usize::from(first), 1)
    } else {
        let llen = usize::from(first & 0x7F);
        if llen == 0 || llen > std::mem::size_of::<usize>() {
            return None;
        }
        let octets = input.get(1..=llen)?;
        let len = octets
            .iter()
            .fold(0usize, |len, &b| (len << 8) | usize::from(b));
        (len, 1 + llen)
    };
    (len <= input.len() - hlen).then_some((len, hlen))
}
