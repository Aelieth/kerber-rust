//! MIT's `pkinit_matching.c` rules: the `pkinit_cert_match` a client's certificate must satisfy.

use super::cms::{OID_MS_SC_LOGON, bitstring_has, cert_sans, each_ext, walk_tbs};
use super::{OID_EKU, OID_KP_CLIENT_AUTH, OID_KU, take_tlv};
use crate::ere::Ere;

const ENOENT: i32 = 2;
const ENOMEM: i32 = 12;
const EINVAL: i32 = 22;

const OID_CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
const OID_EMAIL_PROTECTION: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04];

const KU_DIGITAL_SIGNATURE: u32 = 1;
const KU_KEY_ENCIPHERMENT: u32 = 2;
const EKU_PKINIT: u32 = 1;
const EKU_MS_SC_LOGIN: u32 = 2;
const EKU_CLIENT_AUTH: u32 = 4;
const EKU_EMAIL_PROTECTION: u32 = 8;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Keyword {
    Ku,
    Eku,
    San,
    Issuer,
    Subject,
}

impl Keyword {
    // MIT keyword2string; see docs/parity/a3-preauth.md
    fn name(self) -> &'static str {
        match self {
            Self::Ku => "KU",
            Self::Eku => "EKU",
            Self::San => "SAN",
            Self::Issuer => "ISSUER",
            Self::Subject => "SUBJECT",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum MatchTrace<'a> {
    Rule(&'a str),
    RuleInvalid(&'a str),
    Regexp {
        matched: bool,
        keyword: &'static str,
        rule: &'a [u8],
        value: &'a [u8],
        cert: usize,
    },
    Checked {
        certs: usize,
        matches: usize,
    },
    NoMatch,
    NoDefault(usize),
}

/// The five keywords of MIT's `matching_keywords` table (`pkinit_matching.c`), matched as written.
const KEYWORDS: [(&[u8], Keyword); 5] = [
    (b"<KU>", Keyword::Ku),
    (b"<EKU>", Keyword::Eku),
    (b"<SAN>", Keyword::San),
    (b"<ISSUER>", Keyword::Issuer),
    (b"<SUBJECT>", Keyword::Subject),
];

/// MIT `ku_keywords` (`pkinit_matching.c:117-121`): the key usage words.
const KU_WORDS: [(&[u8], u32); 2] = [
    (b"digitalSignature", KU_DIGITAL_SIGNATURE),
    (b"keyEncipherment", KU_KEY_ENCIPHERMENT),
];
/// MIT `eku_keywords` (`pkinit_matching.c:123-129`): the extended key usage words.
const EKU_WORDS: [(&[u8], u32); 4] = [
    (b"pkinit", EKU_PKINIT),
    (b"msScLogin", EKU_MS_SC_LOGIN),
    (b"clientAuth", EKU_CLIENT_AUTH),
    (b"emailProtection", EKU_EMAIL_PROTECTION),
];

enum Component {
    Regexp(Keyword, Ere, Vec<u8>),
    Bits(Keyword, u32),
}

#[derive(PartialEq, Eq)]
enum Relation {
    None,
    And,
    Or,
}

/// Why a rule could not be checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertMatchError {
    /// MIT's `errno` or `regcomp` code, which the KDC reports as an errno.
    Code(i32),
    /// A regular expression with a back-reference (`\1` to `\9`).
    BackReference,
}

impl std::fmt::Display for CertMatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Code(code) => {
                let text = std::io::Error::from_raw_os_error(*code).to_string();
                let text = text.rfind(" (os error ").map_or(&*text, |at| &text[..at]);
                f.write_str(text)
            }
            Self::BackReference => {
                f.write_str("pkinit_cert_match: back-references are not supported")
            }
        }
    }
}

/// MIT `pkinit_client_cert_match` (`pkinit_matching.c:716-750`): the rule is parsed, the certificate's matching data read, and the components checked in order, an `&&` rule stopping at the first miss and an `||` rule at the first hit; the last component checked decides.
///
/// # Errors
/// MIT's code for a rule or certificate it cannot read, or a back-reference.
pub fn cert_match(
    rule: &str,
    cert: &[u8],
    trace: &mut dyn FnMut(MatchTrace<'_>),
) -> Result<bool, CertMatchError> {
    let rule = rule.split('\0').next().unwrap_or_default();
    let (relation, components) = parse_rule_set(rule.as_bytes()).map_err(CertMatchError::Code)?;
    let md = matching_data(cert).map_err(CertMatchError::Code)?;
    let mut matched = false;
    for c in &components {
        matched = component_match(c, &md, 0, trace)?;
        if (matched && relation == Relation::Or) || (!matched && relation == Relation::And) {
            break;
        }
    }
    Ok(matched)
}

/// Which of a client's certificates it uses: the one the first rule that picks exactly one picks,
/// a rule that does not parse (`EINVAL`) skipped; with no rule, the only one.
/// MIT `pkinit_cert_matching` (`pkinit_matching.c:617-713`): each `pkinit_cert_match` rule in turn until one matches exactly one certificate, else `ENOENT`.
/// MIT `crypto_cert_select_default` (`pkinit_crypto_openssl.c:4974-4991`): with no rule, exactly one certificate, else `EINVAL`.
///
/// # Errors
///
/// `EINVAL` for no rule and not one certificate, `ENOENT` when no rule picks one, a rule's other
/// parse error, or a back-reference.
pub fn select_cert(
    rules: &[String],
    certs: &[&[u8]],
    trace: &mut dyn FnMut(MatchTrace<'_>),
) -> Result<usize, CertMatchError> {
    if rules.is_empty() {
        if certs.len() == 1 {
            return Ok(0);
        }
        trace(MatchTrace::NoDefault(certs.len()));
        return Err(CertMatchError::Code(EINVAL));
    }
    let mut data: Option<Vec<MatchData>> = None;
    for rule in rules {
        let rule = rule.split('\0').next().unwrap_or_default();
        trace(MatchTrace::Rule(rule));
        let (relation, components) = match parse_rule_set(rule.as_bytes()) {
            Ok(rs) => rs,
            Err(EINVAL) => {
                trace(MatchTrace::RuleInvalid(rule));
                continue;
            }
            Err(code) => return Err(CertMatchError::Code(code)),
        };
        if data.is_none() {
            let md: Result<Vec<MatchData>, i32> = certs.iter().map(|c| matching_data(c)).collect();
            data = Some(md.map_err(|_| CertMatchError::Code(ENOENT))?);
        }
        let mds = data.as_deref().unwrap_or_default();
        if let Some(i) = check_all_certs(&relation, &components, mds, trace)? {
            return Ok(i);
        }
    }
    trace(MatchTrace::NoMatch);
    Err(CertMatchError::Code(ENOENT))
}

/// The certificate a rule picks when it matches exactly one.
/// MIT `check_all_certs` (`pkinit_matching.c:541-614`): an `||` rule counts a certificate at its first hit and an `&&` rule drops it at its first miss; otherwise the last component checked decides.
fn check_all_certs(
    relation: &Relation,
    components: &[Component],
    mds: &[MatchData],
    trace: &mut dyn FnMut(MatchTrace<'_>),
) -> Result<Option<usize>, CertMatchError> {
    let mut matched = false;
    let (mut total, mut save) = (0, 0);
    for (i, md) in mds.iter().enumerate() {
        let mut decided = false;
        for c in components {
            matched = component_match(c, md, i, trace)?;
            if matched && *relation == Relation::Or {
                (total, save) = (total + 1, i);
                decided = true;
                break;
            }
            if !matched && *relation == Relation::And {
                decided = true;
                break;
            }
        }
        if !decided && matched {
            (total, save) = (total + 1, i);
        }
    }
    trace(MatchTrace::Checked {
        certs: mds.len(),
        matches: total,
    });
    Ok((total == 1).then_some(save))
}

fn keyword_at(rule: &[u8]) -> Option<(Keyword, usize)> {
    KEYWORDS
        .iter()
        .find(|(k, _)| rule.starts_with(k))
        .map(|(k, kw)| (*kw, k.len()))
}

/// MIT `parse_rule_set` (`pkinit_matching.c:375-447`): components without `&&` or `||` are `&&`.
fn parse_rule_set(rule: &[u8]) -> Result<(Relation, Vec<Component>), i32> {
    let mut rest = rule;
    let mut relation = Relation::None;
    if rest.len() > 1 {
        if rest.starts_with(b"&&") {
            relation = Relation::And;
            rest = &rest[2..];
        } else if rest.starts_with(b"||") {
            relation = Relation::Or;
            rest = &rest[2..];
        }
    }
    let mut components = Vec::new();
    while !rest.is_empty() {
        if relation == Relation::None && !components.is_empty() {
            relation = Relation::And;
        }
        components.push(parse_rule_component(&mut rest)?);
    }
    Ok((relation, components))
}

/// MIT `parse_rule_component` (`pkinit_matching.c:253-372`): a keyword and its value up to the next.
fn parse_rule_component(rule: &mut &[u8]) -> Result<Component, i32> {
    let (kw, n) = keyword_at(rule).ok_or(ENOENT)?;
    let after = &rule[n..];
    let len = (0..after.len())
        .find(|&i| after[i] == b'<' && keyword_at(&after[i..]).is_some())
        .unwrap_or(after.len());
    if len == 0 {
        return Err(EINVAL);
    }
    let value = &after[..len];
    *rule = &after[len..];
    match kw {
        Keyword::Ku | Keyword::Eku => parse_list_value(kw, value).map(|b| Component::Bits(kw, b)),
        _ => Ere::new(value).map(|re| Component::Regexp(kw, re, value.to_vec())),
    }
}

/// MIT `parse_list_value` (`pkinit_matching.c:182-250`): a word matches a keyword it starts, and
/// the value moves on by the keyword's length; where MIT would read past the end, the value ends.
fn parse_list_value(kw: Keyword, value: &[u8]) -> Result<u32, i32> {
    let words: &[(&[u8], u32)] = if kw == Keyword::Eku {
        &EKU_WORDS
    } else {
        &KU_WORDS
    };
    let mut bits = 0;
    let mut i = 0;
    while i < value.len() {
        let rest = &value[i..];
        let len = rest.iter().position(|&b| b == b',').unwrap_or(rest.len());
        let (word, bit) = words
            .iter()
            .find(|(w, _)| {
                len <= w.len()
                    && w[..len]
                        .iter()
                        .zip(rest)
                        .all(|(a, b)| a.eq_ignore_ascii_case(b))
            })
            .ok_or(EINVAL)?;
        bits |= bit;
        i += word.len();
        if value.get(i) == Some(&b',') {
            i += 1;
        }
    }
    Ok(bits)
}

struct MatchData {
    subject: Vec<u8>,
    issuer: Vec<u8>,
    sans: Vec<String>,
    upns: Vec<String>,
    ku: u32,
    eku: u32,
}

/// MIT `get_matching_data` (`pkinit_crypto_openssl.c:4850-4888`): names, SANs, UPNs and usage bits.
fn matching_data(cert: &[u8]) -> Result<MatchData, i32> {
    let w = walk_tbs(cert).ok_or(EINVAL)?;
    let subject = print_name(w.subject).ok_or(ENOMEM)?;
    let issuer = print_name(w.issuer).ok_or(ENOMEM)?;
    let sans = cert_sans(cert, true).ok_or(EINVAL)?;
    let (ku, eku) = w.extensions.map(usage_bits).unwrap_or_default();
    Ok(MatchData {
        subject,
        issuer,
        sans: sans
            .principals
            .iter()
            .map(|(realm, _, comps)| crate::name::unparse_name(comps, realm))
            .collect(),
        upns: sans.upns,
        ku,
        eku,
    })
}

/// MIT `component_match` (`pkinit_matching.c:468-535`): a list's words must all be set.
/// MIT `component_match` (`pkinit_matching.c:484-497`): the UPN loop runs after the SAN loop, so with any UPN its outcome is the SAN keyword's.
fn component_match(
    c: &Component,
    md: &MatchData,
    cert: usize,
    trace: &mut dyn FnMut(MatchTrace<'_>),
) -> Result<bool, CertMatchError> {
    // MIT regexp_match; see docs/parity/a3-preauth.md
    let mut is = |kw: &Keyword, re: &Ere, rule: &[u8], value: &[u8]| {
        let matched = re.is_match(value).ok_or(CertMatchError::BackReference)?;
        trace(MatchTrace::Regexp {
            matched,
            keyword: kw.name(),
            rule,
            value,
            cert,
        });
        Ok::<bool, CertMatchError>(matched)
    };
    Ok(match c {
        Component::Regexp(kw @ Keyword::Subject, re, rule) => is(kw, re, rule, &md.subject)?,
        Component::Regexp(kw @ Keyword::Issuer, re, rule) => is(kw, re, rule, &md.issuer)?,
        Component::Regexp(kw, re, rule) => {
            let mut matched = false;
            for s in &md.sans {
                matched = is(kw, re, rule, s.as_bytes())?;
                if matched {
                    break;
                }
            }
            for u in &md.upns {
                matched = is(kw, re, rule, u.as_bytes())?;
                if matched {
                    break;
                }
            }
            matched
        }
        Component::Bits(Keyword::Eku, bits) => md.eku & bits == *bits,
        Component::Bits(_, bits) => md.ku & bits == *bits,
    })
}

/// MIT `crypto_retrieve_X509_key_usage` (`pkinit_crypto_openssl.c:4694-4766`): an extension that appears twice gives none.
fn usage_bits(extensions: &[u8]) -> (u32, u32) {
    let mut ku = Vec::new();
    let mut eku = Vec::new();
    each_ext(extensions, |oid, val| {
        if oid == OID_KU {
            ku.push(val.to_vec());
        } else if oid == OID_EKU {
            eku.push(val.to_vec());
        }
        false
    });
    let mut ku_bits = 0;
    if let [val] = ku.as_slice()
        && let Some((0x03, _, _)) = take_tlv(val)
    {
        if bitstring_has(val, 0) {
            ku_bits |= KU_DIGITAL_SIGNATURE;
        }
        if bitstring_has(val, 2) {
            ku_bits |= KU_KEY_ENCIPHERMENT;
        }
    }
    let mut eku_bits = 0;
    if let [val] = eku.as_slice()
        && let Some((0x30, mut oids, _)) = take_tlv(val)
    {
        let mut bits = 0;
        while let Some((0x06, oid, rest)) = take_tlv(oids) {
            bits |= match oid {
                OID_KP_CLIENT_AUTH => EKU_PKINIT,
                OID_MS_SC_LOGON => EKU_MS_SC_LOGIN,
                OID_CLIENT_AUTH => EKU_CLIENT_AUTH,
                OID_EMAIL_PROTECTION => EKU_EMAIL_PROTECTION,
                _ => 0,
            };
            oids = rest;
        }
        if oids.is_empty() {
            eku_bits = bits;
        }
    }
    (ku_bits, eku_bits)
}

/// MIT `rfc2253_name` (`pkinit_crypto_openssl.c:4769-4790`): `X509_NAME_print_ex` with `XN_FLAG_SEP_COMMA_PLUS`, read as a C string.
fn print_name(name: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut rdns = name;
    while !rdns.is_empty() {
        let (_, mut atvs, rest) = take_tlv(rdns)?;
        rdns = rest;
        let mut sep = b',';
        while !atvs.is_empty() {
            let (_, atv, rest) = take_tlv(atvs)?;
            if !out.is_empty() || sep == b'+' {
                out.push(sep);
            }
            sep = b'+';
            let (_, oid, value) = take_tlv(atv)?;
            out.extend(field_name(oid)?.as_bytes());
            out.push(b'=');
            let (tag, body, after) = take_tlv(value)?;
            let data = if tag == 0x30 || tag == 0x31 {
                &value[..value.len() - after.len()]
            } else {
                body
            };
            print_string(tag, data, &mut out)?;
            atvs = rest;
        }
    }
    let end = out.iter().position(|&b| b == 0).unwrap_or(out.len());
    out.truncate(end);
    Some(out)
}

/// OpenSSL `do_print_ex`, `do_buf` and `do_esc_char` without `ASN1_STRFLGS`.
fn print_string(tag: u8, data: &[u8], out: &mut Vec<u8>) -> Option<()> {
    let mut put = |c: u32| {
        if c > 0xffff {
            out.extend(format!("\\W{c:08X}").as_bytes());
        } else if c > 0xff {
            out.extend(format!("\\U{c:04X}").as_bytes());
        } else {
            out.push(u8::try_from(c).unwrap_or_default());
        }
    };
    match tag {
        0x0c => {
            let mut p = data;
            while !p.is_empty() {
                let (c, n) = utf8_getc(p)?;
                put(c);
                p = &p[n..];
            }
        }
        0x1e | 0x1c => {
            let width = if tag == 0x1e { 2 } else { 4 };
            if !data.len().is_multiple_of(width) {
                return None;
            }
            for ch in data.chunks(width) {
                put(ch.iter().fold(0, |c, &b| (c << 8) | u32::from(b)));
            }
        }
        _ => data.iter().for_each(|&b| put(u32::from(b))),
    }
    Some(())
}

/// OpenSSL `UTF8_getc`.
fn utf8_getc(p: &[u8]) -> Option<(u32, usize)> {
    let b0 = u32::from(p[0]);
    let (n, init, min) = match p[0] {
        0x00..=0x7f => return Some((b0, 1)),
        0xc0..=0xdf => (2, b0 & 0x1f, 0x80),
        0xe0..=0xef => (3, b0 & 0x0f, 0x800),
        0xf0..=0xf7 => (4, b0 & 0x07, 0x1_0000),
        _ => return None,
    };
    let tail = p.get(1..n)?;
    if tail.iter().any(|&b| b & 0xc0 != 0x80) {
        return None;
    }
    let c = tail
        .iter()
        .fold(init, |c, &b| (c << 6) | (u32::from(b) & 0x3f));
    (c >= min && !(0xd800..0xe000).contains(&c)).then_some((c, n))
}

/// OpenSSL 3.5's short name in four attribute arcs, else `OBJ_obj2txt`'s dotted OID.
fn field_name(oid: &[u8]) -> Option<String> {
    let mut arcs: Vec<u128> = Vec::new();
    let mut v: u128 = 0;
    for (i, &b) in oid.iter().enumerate() {
        v = v.checked_mul(128)? | u128::from(b & 0x7f);
        if b & 0x80 == 0 {
            if arcs.is_empty() {
                let first = v.min(80) / 40;
                arcs.extend([first, v - first * 40]);
            } else {
                arcs.push(v);
            }
            v = 0;
        } else if i + 1 == oid.len() {
            return None;
        }
    }
    let dotted = arcs
        .iter()
        .map(u128::to_string)
        .collect::<Vec<_>>()
        .join(".");
    let named = |prefix: &str, table: &str| {
        let last = dotted.strip_prefix(prefix)?;
        let mut words = table.split(' ');
        while let (Some(n), Some(sn)) = (words.next(), words.next()) {
            if n == last {
                return Some(sn.to_owned());
            }
        }
        None
    };
    Some(
        named("2.5.4.", X520_NAMES)
            .or_else(|| named("1.2.840.113549.1.9.", PKCS9_NAMES))
            .or_else(|| named("0.9.2342.19200300.100.1.", PILOT_NAMES))
            .or_else(|| named("1.3.6.1.4.1.311.60.2.1.", JURISDICTION_NAMES))
            .unwrap_or_else(|| dotted.chars().take(79).collect()),
    )
}

const X520_NAMES: &str = concat!(
    "3 CN 4 SN 5 serialNumber 6 C 7 L 8 ST 9 street 10 O 11 OU 12 title 13 description ",
    "14 searchGuide 15 businessCategory 16 postalAddress 17 postalCode 18 postOfficeBox ",
    "19 physicalDeliveryOfficeName 20 telephoneNumber 21 telexNumber ",
    "22 teletexTerminalIdentifier 23 facsimileTelephoneNumber 24 x121Address ",
    "25 internationaliSDNNumber 26 registeredAddress 27 destinationIndicator ",
    "28 preferredDeliveryMethod 29 presentationAddress 30 supportedApplicationContext ",
    "31 member 32 owner 33 roleOccupant 34 seeAlso 35 userPassword 36 userCertificate ",
    "37 cACertificate 38 authorityRevocationList 39 certificateRevocationList ",
    "40 crossCertificatePair 41 name 42 GN 43 initials 44 generationQualifier ",
    "45 x500UniqueIdentifier 46 dnQualifier 47 enhancedSearchGuide 48 protocolInformation ",
    "49 distinguishedName 50 uniqueMember 51 houseIdentifier 52 supportedAlgorithms ",
    "53 deltaRevocationList 54 dmdName 65 pseudonym 72 role 97 organizationIdentifier 98 c3 ",
    "99 n3 100 dnsName",
);
const PKCS9_NAMES: &str = concat!(
    "1 emailAddress 2 unstructuredName 3 contentType 4 messageDigest 5 signingTime ",
    "6 countersignature 7 challengePassword 8 unstructuredAddress ",
    "9 extendedCertificateAttributes 14 extReq 15 SMIME-CAPS 16 SMIME 20 friendlyName ",
    "21 localKeyID 52 id-aa-CMSAlgorithmProtection",
);
const PILOT_NAMES: &str = concat!(
    "1 UID 2 textEncodedORAddress 3 mail 4 info 5 favouriteDrink 6 roomNumber 7 photo ",
    "8 userClass 9 host 10 manager 11 documentIdentifier 12 documentTitle 13 documentVersion ",
    "14 documentAuthor 15 documentLocation 20 homeTelephoneNumber 21 secretary ",
    "22 otherMailbox 23 lastModifiedTime 24 lastModifiedBy 25 DC 26 aRecord ",
    "27 pilotAttributeType27 28 mXRecord 29 nSRecord 30 sOARecord 31 cNAMERecord ",
    "37 associatedDomain 38 associatedName 39 homePostalAddress 40 personalTitle ",
    "41 mobileTelephoneNumber 42 pagerTelephoneNumber 43 friendlyCountryName 44 uid ",
    "45 organizationalStatus 46 janetMailbox 47 mailPreferenceOption 48 buildingName ",
    "49 dSAQuality 50 singleLevelQuality 51 subtreeMinimumQuality 52 subtreeMaximumQuality ",
    "53 personalSignature 54 dITRedirect 55 audio 56 documentPublisher",
);
const JURISDICTION_NAMES: &str = "1 jurisdictionL 2 jurisdictionST 3 jurisdictionC";
