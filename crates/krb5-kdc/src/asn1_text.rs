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
const SEQUENCE: u32 = 16;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The four inputs of the settle's cell X1 (a PA-OTP-ENC-REQUEST's plaintext, mutated), and the empty plaintext, each with the text MIT's log gave for it.
    #[test]
    fn decode_failure_text_matches_the_x1_cells() {
        // X1 `garbage`: deadbeef01020304 is an overrun.
        let garbage = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];
        assert_eq!(decode_failure_text(&garbage, false), ASN1_OVERRUN);
        assert_eq!(decode_failure_text(&garbage, true), ASN1_OVERRUN);
        // X1 `empty`: no octets at all.
        assert_eq!(decode_failure_text(&[], true), ASN1_OVERRUN);
        // X1 `badtag`: 04 02 AA BB is an OCTET STRING, not a SEQUENCE.
        assert_eq!(
            decode_failure_text(&[0x04, 0x02, 0xaa, 0xbb], false),
            ASN1_BAD_ID
        );
        // X1 `badfield`: 30 03 81 01 00 has a context [1] where the [0] field must be.
        let badfield = [0x30, 0x03, 0x81, 0x01, 0x00];
        assert_eq!(decode_failure_text(&badfield, false), ASN1_MISSING_FIELD);
        assert_eq!(decode_failure_text(&badfield, true), ASN1_MISSING_FIELD);
    }

    /// The PA-SPAKE cells, each with the text MIT's krb5kdc logged for it.
    #[test]
    fn pa_spake_failure_text_matches_mits_cells() {
        // `ffff`: a tag that runs out. `a000`: an alternative with nothing in it.
        assert_eq!(pa_spake_failure_text(&[0xff, 0xff]), ASN1_OVERRUN);
        assert_eq!(pa_spake_failure_text(&[0xa0, 0x00]), ASN1_OVERRUN);
        // `a0 02 30 00`, `a2 02 30 00` and `a1 02 30 00`: an empty SEQUENCE has no field.
        for lead in [0xa0, 0xa1, 0xa2] {
            assert_eq!(
                pa_spake_failure_text(&[lead, 0x02, 0x30, 0x00]),
                ASN1_MISSING_FIELD,
                "{lead:#x}"
            );
        }
        // `a0 02 04 00`: an alternative holding an element that is no SEQUENCE.
        assert_eq!(
            pa_spake_failure_text(&[0xa0, 0x02, 0x04, 0x00]),
            ASN1_BAD_ID
        );
    }

    /// The stale-nonce cell: an implicit `[0]` (primitive) is the field of a PA-OTP-ENC-REQUEST, and the same bytes read as a PA-ENC-TS-ENC are missing their explicit (constructed) `[0]`.
    #[test]
    fn implicit_and_explicit_zero_fields_differ() {
        let mut stale = vec![0x30, 0x26, 0x80, 0x24];
        stale.extend([0x5a; 36]);
        // The implicit field is there, so the failure is inside it.
        assert_eq!(decode_failure_text(&stale, false), ASN1_OVERRUN);
        // The explicit field must be constructed, so it is missing (X1 `stale-nonce`).
        assert_eq!(decode_failure_text(&stale, true), ASN1_MISSING_FIELD);
        // An empty SEQUENCE has no first field.
        assert_eq!(
            decode_failure_text(&[0x30, 0x00], false),
            ASN1_MISSING_FIELD
        );
        // A constructed explicit `[0]` is the field, so the failure is inside it.
        let fresh = [0x30, 0x03, 0xa0, 0x01, 0x00];
        assert_eq!(decode_failure_text(&fresh, true), ASN1_OVERRUN);
    }
}
