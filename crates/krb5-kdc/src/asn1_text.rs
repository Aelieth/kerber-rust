//! KDC ASN.1 texts.

// MIT: `ASN1_MISSING_FIELD` (lib/krb5/error_tables/asn1_err.et:3-3)
pub(crate) const ASN1_MISSING_FIELD: &str = "ASN.1 structure is missing a required field";
// MIT: `ASN1_OVERFLOW` (lib/krb5/error_tables/asn1_err.et:6-6)
pub(crate) const ASN1_OVERFLOW: &str = "ASN.1 value too large";
// MIT: `ASN1_OVERRUN` (lib/krb5/error_tables/asn1_err.et:7-7)
pub(crate) const ASN1_OVERRUN: &str = "ASN.1 encoding ended unexpectedly";
// MIT: `ASN1_BAD_ID` (lib/krb5/error_tables/asn1_err.et:8-8)
pub(crate) const ASN1_BAD_ID: &str = "ASN.1 identifier doesn't match expected value";
// MIT: `ASN1_BAD_LENGTH` (lib/krb5/error_tables/asn1_err.et:9-9)
pub(crate) const ASN1_BAD_LENGTH: &str = "ASN.1 length doesn't match expected value";
// MIT: `ASN1_BAD_FORMAT` (lib/krb5/error_tables/asn1_err.et:10-10)
pub(crate) const ASN1_BAD_FORMAT: &str = "ASN.1 badly-formatted encoding";
// MIT: `ASN1_PARSE_ERROR` (lib/krb5/error_tables/asn1_err.et:11-11)
pub(crate) const ASN1_PARSE_ERROR: &str = "ASN.1 parse error";
// MIT: `ASN1_INDEF` (lib/krb5/error_tables/asn1_err.et:13-13)
pub(crate) const ASN1_INDEF: &str = "ASN.1 indefinite encoding";

const ASN1_BASE: i32 = 1_859_794_432;

/// Unknown text maps to offset 9.
pub(crate) fn asn1_code(text: &str) -> i32 {
    let offset: i32 = match text {
        ASN1_MISSING_FIELD => 1,
        ASN1_OVERFLOW => 4,
        ASN1_OVERRUN => 5,
        ASN1_BAD_ID => 6,
        ASN1_BAD_LENGTH => 7,
        ASN1_BAD_FORMAT => 8,
        ASN1_INDEF => 11,
        _ => 9,
    };
    ASN1_BASE + offset
}

pub(crate) fn preauth_decode_failure(
    der: &[u8],
    first_field_explicit: bool,
) -> crate::error::Error {
    let message = decode_failure_text(der, first_field_explicit);
    crate::error::Error::PreauthModule {
        code: asn1_code(message),
        message: message.to_owned(),
    }
}

pub(crate) const UNIVERSAL: u8 = 0x00;
pub(crate) const APPLICATION: u8 = 0x40;
pub(crate) const CONTEXT: u8 = 0x80;
// MIT: `ASN1_SEQUENCE` (lib/krb5/asn.1/krbasn1.h:36-36)
pub(crate) const SEQUENCE: u32 = 16;
// MIT: `ASN1_TAGNUM_MAX` (lib/krb5/asn.1/krbasn1.h:22-22)
const TAGNUM_MAX: u32 = 0x7fff_fffe;

pub(crate) struct Tlv<'a> {
    pub(crate) class: u8,
    pub(crate) constructed: bool,
    pub(crate) tagnum: u32,
    pub(crate) contents: &'a [u8],
    pub(crate) rest: &'a [u8],
}

// MIT: `get_tag` (lib/krb5/asn.1/asn1_encode.c:366-421)
/// A zero long-length is indefinite encoding.
pub(crate) fn get_tag(asn1: &[u8]) -> Result<Tlv<'_>, &'static str> {
    let (&o, mut p) = asn1.split_first().ok_or(ASN1_OVERRUN)?;
    let mut tagnum = u32::from(o & 0x1F);
    if o & 0x1F == 0x1F {
        tagnum = 0;
        loop {
            let (&b, q) = p.split_first().ok_or(ASN1_OVERRUN)?;
            p = q;
            if tagnum > TAGNUM_MAX >> 7 {
                return Err(ASN1_OVERFLOW);
            }
            tagnum = (tagnum << 7) | u32::from(b & 0x7F);
            if b & 0x80 == 0 {
                break;
            }
        }
        if tagnum > TAGNUM_MAX {
            return Err(ASN1_OVERFLOW);
        }
    }
    let (&l, p) = p.split_first().ok_or(ASN1_OVERRUN)?;
    let (clen, p) = if l & 0x80 == 0 {
        (usize::from(l), p)
    } else {
        let llen = usize::from(l & 0x7F);
        if llen > p.len() {
            return Err(ASN1_OVERRUN);
        }
        if llen > std::mem::size_of::<usize>() {
            return Err(ASN1_OVERFLOW);
        }
        if llen == 0 {
            return Err(ASN1_INDEF);
        }
        let clen = p[..llen]
            .iter()
            .fold(0usize, |c, &b| (c << 8) | usize::from(b));
        (clen, &p[llen..])
    };
    if clen > p.len() {
        return Err(ASN1_OVERRUN);
    }
    Ok(Tlv {
        class: o & 0xC0,
        constructed: o & 0x20 != 0,
        tagnum,
        contents: &p[..clen],
        rest: &p[clen..],
    })
}

// MIT: `k5_asn1_full_decode` (lib/krb5/asn.1/asn1_encode.c:1582-1583)
// MIT: `check_atype_tag` (lib/krb5/asn.1/asn1_encode.c:1049-1052)
// MIT: `decode_sequence` (lib/krb5/asn.1/asn1_encode.c:1411-1412)
// MIT: `omit_atype` (lib/krb5/asn.1/asn1_encode.c:1375-1375)
pub(crate) fn decode_failure_text(der: &[u8], first_field_explicit: bool) -> &'static str {
    let outer = match get_tag(der) {
        Ok(t) => t,
        Err(text) => return text,
    };
    if outer.class != UNIVERSAL || !outer.constructed || outer.tagnum != SEQUENCE {
        return ASN1_BAD_ID;
    }
    if outer.contents.is_empty() {
        return ASN1_MISSING_FIELD;
    }
    let first = match get_tag(outer.contents) {
        Ok(t) => t,
        Err(text) => return text,
    };
    let is_zero = first.class == CONTEXT && first.tagnum == 0;
    if is_zero && (!first_field_explicit || first.constructed) {
        ASN1_OVERRUN
    } else {
        ASN1_MISSING_FIELD
    }
}

// MIT: `decode_cntype` (lib/krb5/asn.1/asn1_encode.c:1277-1293)
// MIT: `get_tag` (lib/krb5/asn.1/asn1_encode.c:368-369)
// MIT: `decode_sequence` (lib/krb5/asn.1/asn1_encode.c:1411-1412)
pub(crate) fn pa_spake_failure_text(der: &[u8]) -> &'static str {
    let top = match get_tag(der) {
        Ok(t) => t,
        Err(text) => return text,
    };
    let inner = match get_tag(top.contents) {
        Ok(t) => t,
        Err(text) => return text,
    };
    if inner.class != UNIVERSAL || !inner.constructed || inner.tagnum != SEQUENCE {
        return ASN1_BAD_ID;
    }
    ASN1_MISSING_FIELD
}

// MIT: `k5_asn1_decode_generaltime` (lib/krb5/asn.1/asn1_encode.c:242-260)
pub(crate) fn body_failure_text(e: &str) -> &'static str {
    if let Some(n) = e
        .split("KerberosTime is not YYYYMMDDhhmmssZ (")
        .nth(1)
        .and_then(|rest| rest.split(" octets)").next())
        .and_then(|n| n.parse::<usize>().ok())
    {
        return if n == 15 {
            ASN1_BAD_FORMAT
        } else {
            ASN1_BAD_LENGTH
        };
    }
    if let Some(time) = e
        .split("Invalid date string: ")
        .nth(1)
        .and_then(|t| t.split(" (Codec").next())
    {
        return if time.len() == 15 {
            ASN1_BAD_FORMAT
        } else {
            ASN1_BAD_LENGTH
        };
    }
    if e.contains("Expected Tag { class: Context")
        || e.contains("Missing field")
        || e.contains("Need more data")
        || e.contains("Unexpected EOF")
    {
        return ASN1_MISSING_FIELD;
    }
    if e.contains("Expected Tag {") {
        return ASN1_BAD_ID;
    }
    if e.contains(" bytes, actual length was ") {
        return ASN1_BAD_LENGTH;
    }
    if e.contains("larger than expected") {
        return ASN1_OVERFLOW;
    }
    if e.contains("Indefinite length") {
        return ASN1_INDEF;
    }
    ASN1_PARSE_ERROR
}
