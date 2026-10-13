//! The OTP clpreauth module (`lib/krb5/krb/preauth_otp.c`), RFC 6560 on the client.
//!
//! It runs only inside FAST. The KDC's PA-OTP-CHALLENGE is filtered to the tokens this client
//! supports, a responder or the user picks one and gives its value (and a PIN where the token asks
//! for one), and the nonce, encrypted in the FAST armor key with key usage 45, goes back in a
//! PA-OTP-REQUEST. The armor key is then the AS key (FAST strengthens it) and the exchange allows no
//! fallback after the request.

use std::fmt::Write as _;
use std::io::ErrorKind;

use krb5_asn1::{decode, encode};
use krb5_crypto::{KeyUsage, ProtocolKey, encrypt};
use krb5_types::k5json::{self, Value};
use krb5_types::otp::{
    OTP_FLAG_COLLECT_PIN, OTP_FLAG_NEXTOTP, OTP_FLAG_NO_COLLECT_PIN, OTP_FLAG_SEPARATE_PIN,
    OTP_FORMAT_ALPHANUMERIC, OTP_FORMAT_BASE64, OTP_FORMAT_BINARY, OTP_FORMAT_DECIMAL,
    OTP_FORMAT_HEXADECIMAL, OtpTokenInfo, PaOtpChallenge, PaOtpEncRequest, PaOtpRequest,
};
use krb5_types::{EncryptedData, KerberosFlags, OctetString, PaData, ku, pa};
use zeroize::{Zeroize, Zeroizing};

use super::responder::{QUESTION_OTP, ResponderItems};
use super::{AsPrompt, PreauthPrompt, PromptType};
use crate::error::Error;
use crate::trace::ERROR_TABLE_BASE_KRB5;

/// MIT's name of the OTP module (`preauth_otp.c`).
pub(super) const OTP_MODULE: &str = "otp";

/// MIT `KRB5_RESPONDER_OTP_FLAGS_COLLECT_TOKEN` (`include/krb5/krb5.hin:6551-6551`): the value the responder JSON's `flags` starts from.
const R_COLLECT_TOKEN: i64 = 0x1;
/// MIT `KRB5_RESPONDER_OTP_FLAGS_COLLECT_PIN` (`include/krb5/krb5.hin:6556-6556`): the token collects a PIN.
const R_COLLECT_PIN: i64 = 0x2;
/// MIT `KRB5_RESPONDER_OTP_FLAGS_NEXTOTP` (`include/krb5/krb5.hin:6563-6563`): the token is in re-synchronization mode.
const R_NEXTOTP: i64 = 0x4;

/// The reply buffers of `doprompt` callers are 1024 bytes, so a reply is at most 1023.
const REPLY_MAX: usize = 1023;

/// How `process` failed. An interrupted prompt stops every mechanism, any other failure moves on
/// to the next one.
/// MIT `process_pa_data` (`lib/krb5/krb/preauth2.c:696-698`): a keyboard interrupt ends the walk.
#[derive(Debug)]
pub(super) struct OtpFail {
    /// The error for the caller.
    pub(super) error: Error,
    /// MIT's `krb5_error_code`, for the trace line `Preauth module otp (141) (real) returned: <code>/<text>`.
    pub(super) code: i64,
    /// The message MIT has set for that code, for the same line.
    pub(super) text: String,
    /// `KRB5_LIBOS_PWDINTR`.
    pub(super) interrupted: bool,
}

/// MIT `KRB5_LIBOS_CANTREADPWD` (`krb5_err.et`): "Cannot read password".
const CANTREADPWD: i64 = ERROR_TABLE_BASE_KRB5 + 130;
/// MIT `KRB5_LIBOS_PWDINTR` (`krb5_err.et`): "Password read interrupted".
const PWDINTR: i64 = ERROR_TABLE_BASE_KRB5 + 132;
/// MIT `KRB5_PREAUTH_FAILED` (`krb5_err.et`): "Generic preauthentication failure".
const PREAUTH_FAILED: i64 = ERROR_TABLE_BASE_KRB5 + 210;
/// `EINVAL`, `ERANGE`, `ENOTSUP` and `ENOMEM`.
const EINVAL: i64 = 22;
const ERANGE: i64 = 34;
const ENOTSUP: i64 = 95;
const ENOMEM: i64 = 12;

fn fail(code: i64, text: &str) -> OtpFail {
    OtpFail {
        error: Error::Message(text.into()),
        code,
        text: text.into(),
        interrupted: false,
    }
}

/// What `prep_questions` leaves for `process`: the challenge with its tokens filtered.
/// MIT `otp_client_request_init` (`lib/krb5/krb/preauth_otp.c:979-979`): the per-request slot that holds the decoded challenge.
#[derive(Default)]
pub(super) struct OtpState {
    chl: Option<PaOtpChallenge>,
}

/// The first 32 bits of a flags field, bit 0 first, as MIT's `krb5_flags` word.
fn flags_u32(f: &KerberosFlags) -> u32 {
    f.iter()
        .take(32)
        .enumerate()
        .fold(0, |w, (i, b)| if *b { w | (1 << (31 - i)) } else { w })
}

/// The octets of an OCTET STRING or a UTF8String, `None` when it is absent or empty.
/// MIT `k5_asn1_decode_bytestring` (`lib/krb5/asn.1/asn1_encode.c:222-239`): length 0 gives `NULL`.
/// MIT `utf8string` (`lib/krb5/asn.1/asn1_k_encode.c:89-91`): a byte string, so these fields are octets.
fn odata(o: Option<&OctetString>) -> Option<&[u8]> {
    o.map(AsRef::as_ref).filter(|b: &&[u8]| !b.is_empty())
}

/// `Some` of a copy of `b` when it is not empty.
fn nonempty(b: &[u8]) -> Option<OctetString> {
    (!b.is_empty()).then(|| OctetString::from(b.to_vec()))
}

fn length(ti: &OtpTokenInfo) -> i32 {
    ti.length.unwrap_or(-1)
}

fn format(ti: &OtpTokenInfo) -> i32 {
    ti.format.unwrap_or(-1)
}

/// MIT `is_printable_string` (`lib/krb5/krb/preauth_otp.c:851-865`): every byte `isprint`, ASCII.
fn printable(b: Option<&[u8]>) -> bool {
    b.is_none_or(|b| b.iter().all(|c| (0x20..=0x7e).contains(c)))
}

/// MIT `is_tokeninfo_supported` (`lib/krb5/krb/preauth_otp.c:872-896`): only the PIN flags, no hash algorithm or iteration count, a printable vendor and challenge, and a format other than base64.
fn is_supported(ti: &OtpTokenInfo) -> bool {
    let ok_flags = OTP_FLAG_COLLECT_PIN | OTP_FLAG_NO_COLLECT_PIN | OTP_FLAG_SEPARATE_PIN;
    flags_u32(&ti.flags) & !ok_flags == 0
        && ti.supported_hash_alg.is_none()
        && ti.iteration_count.unwrap_or(-1) < 0
        && printable(odata(ti.vendor.as_ref()))
        && printable(odata(ti.challenge.as_ref()))
        && format(ti) != OTP_FORMAT_BASE64
}

/// MIT `filter_supported_tokeninfos` (`lib/krb5/krb/preauth_otp.c:899-921`): drop what this
/// client cannot answer; none left is `KRB5_PREAUTH_FAILED` "No supported tokens".
fn filter_supported(tis: Vec<OtpTokenInfo>) -> Result<Vec<OtpTokenInfo>, Error> {
    let kept: Vec<OtpTokenInfo> = tis.into_iter().filter(is_supported).collect();
    if kept.is_empty() {
        return Err(Error::Message("No supported tokens".into()));
    }
    Ok(kept)
}

/// The string `key` of the ccache's preauth config.
/// MIT `get_cc_config` (`lib/krb5/krb/preauth2.c:513-530`): only a string value counts.
fn cc_get<'a>(cc: Option<&'a Value>, key: &str) -> Option<&'a [u8]> {
    cc?.member(key)?.as_cstr()
}

/// MIT `filter_config_tokeninfos` (`lib/krb5/krb/preauth_otp.c:928-973`): when exactly one token
/// agrees with the vendor, algID and tokenID the ccache recorded, it is the only one kept.
fn filter_config(tis: &mut Vec<OtpTokenInfo>, cc: Option<&Value>) {
    let (vendor, alg_id, token_id) = (
        cc_get(cc, "vendor"),
        cc_get(cc, "algID"),
        cc_get(cc, "tokenID"),
    );
    let differs = |have: Option<&[u8]>, want: Option<&[u8]>| match (want, have) {
        (Some(w), Some(h)) => w != h,
        _ => false,
    };
    let mut matching = tis.iter().enumerate().filter(|(_, ti)| {
        !differs(odata(ti.vendor.as_ref()), vendor)
            && !differs(odata(ti.alg_id.as_ref()), alg_id)
            && !differs(odata(ti.token_id.as_ref()), token_id)
    });
    let (Some((at, _)), None) = (matching.next(), matching.next()) else {
        return;
    };
    let keep = tis.swap_remove(at);
    tis.clear();
    tis.push(keep);
}

/// A JSON string of the octets `b`.
fn string_value(b: &[u8]) -> Value {
    Value::String(b.to_vec())
}

/// MIT `codec_encode_tokeninfo` (`lib/krb5/krb/preauth_otp.c:149-206`): one token as the responder
/// reads it. A token that collects a PIN is flags 3; one that also has a separate PIN is 7, since MIT
/// sets NEXTOTP there and not SEPARATE_PIN (`:161-165`). Format 3 (binary) and 4 (base64) are left
/// out, and -1 means absent.
fn tokeninfo_json(ti: &OtpTokenInfo) -> Value {
    let f = flags_u32(&ti.flags);
    let mut flags = R_COLLECT_TOKEN;
    if f & OTP_FLAG_COLLECT_PIN != 0 {
        flags |= R_COLLECT_PIN;
        if f & OTP_FLAG_SEPARATE_PIN != 0 {
            flags |= R_NEXTOTP;
        }
    }
    if f & OTP_FLAG_NEXTOTP != 0 {
        flags |= R_NEXTOTP;
    }
    let mut o = Value::Object(Vec::new());
    o.set("flags", Value::Number(flags));
    if let Some(v) = odata(ti.vendor.as_ref()) {
        o.set("vendor", string_value(v));
    }
    if let Some(c) = odata(ti.challenge.as_ref()) {
        o.set("challenge", string_value(c));
    }
    if length(ti) != -1 {
        o.set("length", Value::Number(i64::from(length(ti))));
    }
    if format(ti) != OTP_FORMAT_BASE64 && format(ti) != OTP_FORMAT_BINARY && format(ti) != -1 {
        o.set("format", Value::Number(i64::from(format(ti))));
    }
    if let Some(t) = odata(ti.token_id.as_ref()) {
        o.set("tokenID", string_value(t));
    }
    if let Some(a) = odata(ti.alg_id.as_ref()) {
        o.set("algID", string_value(a));
    }
    o
}

/// MIT `codec_encode_challenge` (`lib/krb5/krb/preauth_otp.c:209-261`): the challenge the responder
/// reads, `{"service": .., "tokenInfo": [..]}` in MIT's key order and compact. The service is left out
/// when it is empty.
fn challenge_json(chl: &PaOtpChallenge) -> Vec<u8> {
    let mut o = Value::Object(Vec::new());
    if let Some(s) = odata(chl.service.as_ref()) {
        o.set("service", string_value(s));
    }
    o.set(
        "tokenInfo",
        Value::Array(chl.token_info.iter().map(tokeninfo_json).collect()),
    );
    k5json::encode(&o)
}

/// MIT `otp_client_prep_questions` (`lib/krb5/krb/preauth_otp.c:983-1030`): decode the challenge,
/// keep the supported tokens, prune by the ccache's config, and ask the `otp` question with the
/// challenge JSON. Any error ends the round, the other mechanisms' too. A later challenge in the
/// list replaces an earlier one, as MIT's does.
///
/// # Errors
///
/// [`Error::Asn1`] when the challenge does not decode; [`Error::Message`] "No supported tokens"
/// when none is left.
pub(super) fn prep_questions(
    state: &mut OtpState,
    pa_data: &PaData,
    cc_in: Option<&Value>,
    items: &mut ResponderItems,
) -> Result<(), Error> {
    let mut chl: PaOtpChallenge = decode(pa_data.padata_value.as_ref())?;
    chl.token_info = filter_supported(chl.token_info)?;
    filter_config(&mut chl.token_info, cc_in);
    items.ask_question(QUESTION_OTP, Some(&challenge_json(&chl)));
    state.chl = Some(chl);
    Ok(())
}

/// C `strtoul(s, NULL, 0)`: the value, and whether it overflowed (`ERANGE`).
fn strtoul_base0(s: &[u8]) -> (u64, bool) {
    let mut i = 0;
    while s
        .get(i)
        .is_some_and(|c| matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r'))
    {
        i += 1;
    }
    let neg = s.get(i) == Some(&b'-');
    if matches!(s.get(i), Some(b'-' | b'+')) {
        i += 1;
    }
    let mut base = 10u64;
    if s.get(i) == Some(&b'0') {
        if matches!(s.get(i + 1), Some(b'x' | b'X'))
            && s.get(i + 2).is_some_and(u8::is_ascii_hexdigit)
        {
            base = 16;
            i += 2;
        } else {
            base = 8;
        }
    }
    let mut n: u64 = 0;
    let mut range = false;
    while let Some(d) = s.get(i).and_then(|&c| char::from(c).to_digit(16)) {
        if u64::from(d) >= base {
            break;
        }
        if let Some(v) = n
            .checked_mul(base)
            .and_then(|n| n.checked_add(u64::from(d)))
        {
            n = v;
        } else {
            range = true;
            n = u64::MAX;
        }
        i += 1;
    }
    if range {
        return (u64::MAX, true);
    }
    (if neg { n.wrapping_neg() } else { n }, false)
}

/// MIT `otpvalue_matches_tokeninfo` (`lib/krb5/krb/preauth_otp.c:456-469`): the value has the
/// token's length, and its format when that is 0 to 2; a format of 3 or more is not checked.
fn value_matches(value: &[u8], ti: &OtpTokenInfo) -> bool {
    if length(ti) >= 0 && value.len() != usize::try_from(length(ti)).unwrap_or(usize::MAX) {
        return false;
    }
    match format(ti) {
        OTP_FORMAT_DECIMAL => value.iter().all(u8::is_ascii_digit),
        OTP_FORMAT_HEXADECIMAL => value.iter().all(u8::is_ascii_hexdigit),
        OTP_FORMAT_ALPHANUMERIC => value.iter().all(u8::is_ascii_alphanumeric),
        _ => true,
    }
}

fn prompt_fail(e: Error) -> OtpFail {
    match e {
        Error::File(io) if io.kind() == ErrorKind::Interrupted => OtpFail {
            text: io.to_string(),
            error: Error::File(io),
            code: PWDINTR,
            interrupted: true,
        },
        Error::File(io) => fail(CANTREADPWD, &io.to_string()),
        other => OtpFail {
            text: other.to_string(),
            error: other,
            code: CANTREADPWD,
            interrupted: false,
        },
    }
}

/// MIT `doprompt` (`lib/krb5/krb/preauth_otp.c:482-499`): one hidden prompt of type PREAUTH into
/// a 1024-byte buffer, read as a C string: the reply is cut at its first NUL.
fn doprompt(
    ui: &mut dyn AsPrompt,
    banner: Option<&str>,
    prompt: &str,
) -> Result<Zeroizing<Vec<u8>>, OtpFail> {
    let mut reply = ui
        .preauth(&PreauthPrompt {
            banner,
            prompt,
            hidden: true,
            prompt_type: PromptType::Preauth,
        })
        .map_err(prompt_fail)?;
    let mut end = reply.len().min(REPLY_MAX);
    if let Some(nul) = reply[..end].iter().position(|&b| b == 0) {
        end = nul;
    }
    reply[end..].zeroize();
    reply.truncate(end);
    Ok(reply)
}

/// MIT `prompt_for_tokeninfo` (`lib/krb5/krb/preauth_otp.c:514-543`): the menu, asked again until
/// the answer is a number from 1 to the count (`strtoul` base 0; a number out of range is an error).
fn prompt_for_tokeninfo(
    ui: &mut dyn AsPrompt,
    tis: &[usize],
    all: &[OtpTokenInfo],
) -> Result<usize, OtpFail> {
    let mut menu = String::from("Please choose from the following:\n");
    for (n, &at) in tis.iter().enumerate() {
        let vendor = odata(all[at].vendor.as_ref()).unwrap_or_default();
        let _ = writeln!(
            menu,
            "\t{}. Vendor: {}",
            n + 1,
            String::from_utf8_lossy(vendor)
        );
    }
    loop {
        let reply = doprompt(ui, Some(&menu), "Enter #")?;
        let (j, range) = strtoul_base0(&reply);
        if range {
            return Err(fail(ERANGE, "Numerical result out of range"));
        }
        if j >= 1 && j <= tis.len() as u64 {
            return Ok(tis[usize::try_from(j - 1).unwrap_or(0)]);
        }
    }
}

/// MIT `collect_pin` (`lib/krb5/krb/preauth_otp.c:583-602`): asked when the token collects a PIN
/// or a separate one; `None` is MIT's `empty_data`.
fn collect_pin(
    ui: &mut dyn AsPrompt,
    ti: &OtpTokenInfo,
) -> Result<Option<Zeroizing<Vec<u8>>>, OtpFail> {
    if flags_u32(&ti.flags) & (OTP_FLAG_COLLECT_PIN | OTP_FLAG_SEPARATE_PIN) == 0 {
        return Ok(None);
    }
    Ok(Some(doprompt(ui, None, "OTP Token PIN")?))
}

/// What the user chose: the token's index, the value, and the PIN when one was collected.
type Chosen = (usize, Zeroizing<Vec<u8>>, Option<Zeroizing<Vec<u8>>>);

/// MIT `prompt_for_token` (`lib/krb5/krb/preauth_otp.c:742-811`): pick a token and read its value.
/// One token is chosen; with several and any challenge the menu comes first; otherwise the value
/// comes first and filters the tokens by length and format, with a menu if several remain.
fn prompt_for_token(ui: &mut dyn AsPrompt, tis: &[OtpTokenInfo]) -> Result<Chosen, OtpFail> {
    if tis.is_empty() {
        return Err(fail(EINVAL, "Invalid argument"));
    }
    let all: Vec<usize> = (0..tis.len()).collect();
    let challengers = tis
        .iter()
        .filter(|t| odata(t.challenge.as_ref()).is_some())
        .count();
    let mut ti = (tis.len() == 1).then_some(0);
    let mut banner = None;
    if challengers > 0 {
        if ti.is_none() {
            ti = Some(prompt_for_tokeninfo(ui, &all, tis)?);
        }
        // MIT `make_challenge` (`lib/krb5/krb/preauth_otp.c:559-568`): "OTP Challenge: <challenge>\n" for a token that has one.
        banner = ti
            .and_then(|at| odata(tis[at].challenge.as_ref()))
            .map(|c| format!("OTP Challenge: {}\n", String::from_utf8_lossy(c)));
    }
    let value = doprompt(ui, banner.as_deref(), "Enter OTP Token Value")?;
    let at = if let Some(at) = ti {
        at
    } else {
        // MIT `filter_tokeninfos` (`lib/krb5/krb/preauth_otp.c:689-721`): the tokens whose
        // length and format the value has; none is an error, one is chosen, several get the menu.
        let kept: Vec<usize> = all
            .into_iter()
            .filter(|&i| value_matches(&value, &tis[i]))
            .collect();
        match kept.as_slice() {
            [] => {
                return Err(fail(
                    PREAUTH_FAILED,
                    "OTP value doesn't match any token formats",
                ));
            }
            [one] => *one,
            _ => prompt_for_tokeninfo(ui, &kept, tis)?,
        }
    };
    let pin = collect_pin(ui, &tis[at])?;
    Ok((at, value, pin))
}

/// MIT `make_request` (`lib/krb5/krb/preauth_otp.c:613-667`): the PA-OTP-REQUEST without its
/// `encData`. The flags keep only NEXTOTP; vendor, format, tokenID and algID come from the token;
/// a PIN is a field of its own for a separate one, else it prefixes the value.
/// MIT leaves `iteration_count` at 0 (`calloc`), so it is sent as 0 (`:619`).
/// MIT drops the combined value of a PIN prefix (`:654-663` sets its length to 0); this port sends it.
fn make_request(
    ti: &OtpTokenInfo,
    value: &[u8],
    pin: Option<&[u8]>,
    enc_data: EncryptedData,
) -> Result<PaOtpRequest, OtpFail> {
    if format(ti) == OTP_FORMAT_BASE64 {
        return Err(fail(ENOTSUP, "Operation not supported"));
    }
    let f = flags_u32(&ti.flags);
    let mut otp_value = value.to_vec();
    let mut pin_field = None;
    if f & OTP_FLAG_COLLECT_PIN != 0 {
        if f & OTP_FLAG_SEPARATE_PIN != 0 {
            let p = pin.ok_or_else(|| fail(EINVAL, "Invalid argument"))?;
            pin_field = nonempty(p);
        } else if let Some(p) = pin {
            otp_value = [p, value].concat();
        }
    }
    Ok(PaOtpRequest {
        flags: KerberosFlags::from_slice(&(f & OTP_FLAG_NEXTOTP).to_be_bytes()),
        nonce: None,
        enc_data,
        hash_alg: None,
        iteration_count: Some(0),
        otp_value: nonempty(&otp_value),
        pin: pin_field,
        challenge: None,
        time: None,
        counter: None,
        format: Some(format(ti)).filter(|&f| f != -1),
        token_id: odata(ti.token_id.as_ref()).and_then(nonempty),
        alg_id: odata(ti.alg_id.as_ref()).and_then(nonempty),
        vendor: odata(ti.vendor.as_ref()).and_then(nonempty),
    })
}

fn other_fail(error: Error) -> OtpFail {
    OtpFail {
        text: error.to_string(),
        error,
        code: PREAUTH_FAILED,
        interrupted: false,
    }
}

/// MIT `encrypt_nonce` (`lib/krb5/krb/preauth_otp.c:433-446`): the challenge's nonce as a
/// PA-OTP-ENC-REQUEST, encrypted in the armor key with key usage 45.
fn encrypt_nonce(armor: &ProtocolKey, chl: &PaOtpChallenge) -> Result<EncryptedData, Error> {
    let plain = encode(&PaOtpEncRequest {
        nonce: chl.nonce.clone(),
    })?;
    let cipher = encrypt(armor, KeyUsage::new(ku::PA_OTP_REQUEST)?, &plain)?;
    Ok(EncryptedData {
        etype: armor.etype().to_iana(),
        kvno: None,
        cipher: cipher.into(),
    })
}

/// A JSON string of `b` up to its first NUL: MIT stores the C string, so a value that starts with a
/// NUL is saved as `""`.
fn cstr_value(b: &[u8]) -> Value {
    Value::String(b.split(|&c| c == 0).next().unwrap_or_default().to_vec())
}

/// MIT `save_config_tokeninfo` (`lib/krb5/krb/preauth_otp.c:1044-1058`): the vendor, algID and
/// tokenID of the token used, in that order, for the ccache's preauth config. A field is saved when
/// its octets are not empty, and its value is the C string.
fn config_of(ti: &OtpTokenInfo) -> Value {
    let mut o = Value::Object(Vec::new());
    for (key, v) in [
        ("vendor", odata(ti.vendor.as_ref())),
        ("algID", odata(ti.alg_id.as_ref())),
        ("tokenID", odata(ti.token_id.as_ref())),
    ] {
        if let Some(v) = v {
            o.set(key, cstr_value(v));
        }
    }
    o
}

/// The config as `save_cc_config_out_data` stores it: JSON, and nothing when empty.
/// MIT `save_cc_config_out_data` (`lib/krb5/krb/get_in_tkt.c:1221-1231`): an object with no entry is not written.
pub(super) fn config_string(config: &Value) -> Option<Vec<u8>> {
    match config {
        Value::Object(entries) if !entries.is_empty() => Some(k5json::encode(config)),
        _ => None,
    }
}

/// Zeroes the octets of a decoded JSON value, so a reply's text does not outlive its reading.
fn wipe(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe),
        Value::Object(members) => {
            for (key, member) in members.iter_mut() {
                key.zeroize();
                wipe(member);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// MIT `codec_decode_answer` (`lib/krb5/krb/preauth_otp.c:374-422`): the responder's answer, a JSON
/// object `{"tokeninfo": n, "value": s, "pin": s}`. `None` when the answer is not usable, and the
/// prompts run instead.
///
/// The usable answers are the ones MIT reads: an object whose `tokeninfo` is an index of the tokens,
/// whose `value` is a string, and whose `pin` is a string or absent. Where MIT is undefined (an answer
/// that is not an object, or an object with no `value`):
/// MIT `codec_decode_answer` (`lib/krb5/krb/preauth_otp.c:385-412`): it returns with nothing set, or
/// with an uninitialised value, and the module crashes on it. Both are "no answer" here
/// (`docs/mit-deviations.md`).
fn decode_answer(answer: Option<&str>, n_tokens: usize) -> Option<Chosen> {
    let mut v = k5json::decode(answer?.as_bytes()).ok()?;
    let chosen = read_answer(&v, n_tokens);
    wipe(&mut v);
    chosen
}

/// The members of a decoded answer, as [`decode_answer`] reads them.
fn read_answer(v: &Value, n_tokens: usize) -> Option<Chosen> {
    if !matches!(v, Value::Object(_)) {
        return None;
    }
    let Some(Value::Number(index)) = v.member("tokeninfo") else {
        return None;
    };
    #[expect(
        clippy::cast_possible_truncation,
        reason = "MIT stores the JSON number in a krb5_int32 (preauth_otp.c:125)"
    )]
    let at = usize::try_from(*index as i32).ok()?;
    if at >= n_tokens {
        return None;
    }
    let value = Zeroizing::new(v.member("value")?.as_cstr()?.to_vec());
    let pin = match v.member("pin") {
        None => None,
        Some(p) => Some(Zeroizing::new(p.as_cstr()?.to_vec())),
    };
    Some((at, value, pin))
}

/// MIT `otp_client_process` (`lib/krb5/krb/preauth_otp.c:1062-1134`): a usable answer from the
/// responder names the token, its value and its PIN, with no prompt (`:1089-1096`); otherwise the
/// token is prompted for. Then build the PA-OTP-REQUEST for the armor key `armor`, and the config
/// entries to record. The caller makes `armor` the AS key and disables fallback.
pub(super) fn process(
    state: &OtpState,
    items: &ResponderItems,
    ui: &mut dyn AsPrompt,
    armor: &ProtocolKey,
) -> Result<(PaData, Value), OtpFail> {
    let chl = state
        .chl
        .as_ref()
        .ok_or_else(|| fail(ENOMEM, "Cannot allocate memory"))?;
    let (at, value, pin) = match decode_answer(items.get_answer(QUESTION_OTP), chl.token_info.len())
    {
        Some(chosen) => chosen,
        None => prompt_for_token(ui, &chl.token_info)?,
    };
    let ti = &chl.token_info[at];
    let enc = encrypt_nonce(armor, chl).map_err(other_fail)?;
    let req = make_request(ti, &value, pin.as_deref().map(Vec::as_slice), enc)?;
    let der = encode(&req).map_err(|e| other_fail(e.into()))?;
    Ok((
        PaData {
            padata_type: pa::OTP_REQUEST,
            padata_value: der.into(),
        },
        config_of(ti),
    ))
}

/// One token of the OTP responder question's challenge; `-1` is MIT's "not specified".
/// MIT `krb5_responder_otp_tokeninfo` (`include/krb5/krb5.hin:6713-6721`): the token's responder
/// flags, format and length, and its optional strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtpTokenView {
    /// `KRB5_RESPONDER_OTP_FLAGS_*` bits.
    pub flags: i32,
    /// The token's format, `-1` when not given.
    pub format: i32,
    /// The token's value length, `-1` when not given.
    pub length: i32,
    /// The vendor: MIT's C string, its octets up to the first NUL.
    pub vendor: Option<Vec<u8>>,
    /// The challenge to show the user: MIT's C string, its octets up to the first NUL.
    pub challenge: Option<Vec<u8>>,
    /// The token's identifier: MIT's C string, its octets up to the first NUL.
    pub token_id: Option<Vec<u8>>,
    /// The token's algorithm: MIT's C string, its octets up to the first NUL.
    pub alg_id: Option<Vec<u8>>,
}

/// The OTP responder question's challenge, decoded.
/// MIT `krb5_responder_otp_challenge` (`include/krb5/krb5.hin:6723-6726`): the service and the tokens
/// a responder may choose from, by index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtpChallengeView {
    /// The service the OTP is for: MIT's C string, its octets up to the first NUL.
    pub service: Option<Vec<u8>>,
    /// The tokens, in the order the answer's `tokeninfo` index counts them.
    pub tokeninfo: Vec<OtpTokenView>,
}

/// A string member as MIT's C string: `Ok(None)` when absent, `Err` when present and not a string.
/// MIT `codec_value_to_string` (`lib/krb5/krb/preauth_otp.c:57-76`): absent is `ENOENT`, another type is `EINVAL`.
fn string_member(o: &Value, key: &str) -> Result<Option<Vec<u8>>, ()> {
    match o.member(key) {
        None => Ok(None),
        Some(v) => v.as_cstr().map(|b| Some(b.to_vec())).ok_or(()),
    }
}

/// A number member as MIT's `krb5_int32`: `-1` when absent, `None` when present and not a number.
/// MIT `codec_value_to_int32` (`lib/krb5/krb/preauth_otp.c:113-127`): the JSON number is stored in a `krb5_int32`.
#[expect(
    clippy::cast_possible_truncation,
    reason = "MIT stores the JSON number in a krb5_int32 (preauth_otp.c:125)"
)]
fn int_member(o: &Value, key: &str) -> Option<i32> {
    match o.member(key) {
        None => Some(-1),
        Some(Value::Number(n)) => Some(*n as i32),
        Some(_) => None,
    }
}

/// MIT `codec_decode_tokeninfo` (`lib/krb5/krb/preauth_otp.c:264-311`): `flags` is required, the
/// rest optional, and a member of the wrong type fails the token.
fn token_view(o: &Value) -> Option<OtpTokenView> {
    if !matches!(o.member("flags"), Some(Value::Number(_))) {
        return None;
    }
    Some(OtpTokenView {
        flags: int_member(o, "flags")?,
        vendor: string_member(o, "vendor").ok()?,
        challenge: string_member(o, "challenge").ok()?,
        length: int_member(o, "length")?,
        format: int_member(o, "format")?,
        token_id: string_member(o, "tokenID").ok()?,
        alg_id: string_member(o, "algID").ok()?,
    })
}

/// MIT `codec_decode_challenge` (`lib/krb5/krb/preauth_otp.c:314-360`): an object with a `tokenInfo`
/// array of objects; any other shape is refused.
fn challenge_view(json: &[u8]) -> Option<OtpChallengeView> {
    let v = k5json::decode(json).ok()?;
    if !matches!(v, Value::Object(_)) {
        return None;
    }
    let Some(Value::Array(items)) = v.member("tokenInfo") else {
        return None;
    };
    let service = string_member(&v, "service").ok()?;
    let tokeninfo = items
        .iter()
        .map(|item| match item {
            Value::Object(_) => token_view(item),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    Some(OtpChallengeView { service, tokeninfo })
}

impl ResponderItems {
    /// The OTP question's challenge as a struct; `None` when no OTP question was asked.
    /// MIT `krb5_responder_otp_get_challenge` (`lib/krb5/krb/preauth_otp.c:1168-1189`): the challenge
    /// JSON decoded; one that does not decode is `ENOMEM`, as MIT returns it.
    ///
    /// # Errors
    ///
    /// [`Error::Message`] "Cannot allocate memory" when the challenge does not decode.
    pub fn otp_get_challenge(&self) -> Result<Option<OtpChallengeView>, Error> {
        let Some(json) = self.get_challenge(QUESTION_OTP) else {
            return Ok(None);
        };
        challenge_view(json)
            .map(Some)
            .ok_or_else(|| Error::Message("Cannot allocate memory".into()))
    }

    /// Answer the OTP question: token `ti`, with a value and a PIN where the token takes them.
    /// MIT `krb5_responder_otp_set_answer` (`lib/krb5/krb/preauth_otp.c:1191-1249`): the answer is
    /// `{"tokeninfo": ti, "value": ..., "pin": ...}`, the last two when given.
    ///
    /// # Errors
    ///
    /// [`Error::Message`] "Invalid argument" when the OTP question was not asked, or `ti` does not fit
    /// a JSON number.
    pub fn otp_set_answer(
        &mut self,
        ti: usize,
        value: Option<&str>,
        pin: Option<&str>,
    ) -> Result<(), Error> {
        let index = i64::try_from(ti).map_err(|_| Error::Message("Invalid argument".into()))?;
        let mut o = Value::Object(Vec::new());
        o.set("tokeninfo", Value::Number(index));
        if let Some(v) = value {
            o.set("value", string_value(v.as_bytes()));
        }
        if let Some(p) = pin {
            o.set("pin", string_value(p.as_bytes()));
        }
        let json = Zeroizing::new(k5json::encode(&o));
        wipe(&mut o);
        self.set_answer(QUESTION_OTP, Some(String::from_utf8_lossy(&json).as_ref()))
    }
}

#[cfg(test)]
mod tests;
