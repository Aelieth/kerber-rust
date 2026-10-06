//! The SPAKE clpreauth module.
//!
//! The client's groups are `[libdefaults] spake_preauth_groups`, edwards25519 when unset; with no
//! group it knows, there is no SPAKE module. A challenge in one of its groups gets a response whose
//! SF-NONE factor is encrypted in `K'[1]`, and `K'[0]` becomes the reply key; an empty PA-SPAKE, or a
//! challenge in a group it lacks, gets one support message. A failure before the response moves
//! the exchange to the next mechanism; after it there is no fallback.

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    ProtocolKey, SPAKE_DEFAULT_GROUPS_CLIENT, SpakeGroup, spake_parse_groups, string_to_key,
};
use krb5_types::spake::{PaSpake, SF_NONE, SpakeChallenge};
use krb5_types::{KrbError, PaData, err, pa};

use super::{
    AsOutcome, AsReqTimes, AsRequest, KdcMsg, S2kMaterial, build_as_req_from, classify_kdc_error,
    conf_preferred_preauth_types, find_pa, finish_as_rep, method_from_error, pick_key, req_sname,
    salt_cname, select_s2k, select_s2k_after, send_as, sort_krb5_padata_sequence, trace_keytab_gak,
    trace_preauth_input, trace_reply_padata,
};
use crate::error::Error;
use crate::preauth::{pa_spake_response, pa_spake_support};
use crate::trace;

/// MIT's name of the SPAKE module (`spake_client.c`).
const SPAKE_MODULE: &str = "spake";

/// The groups the client permits, in configuration order; none means no SPAKE module.
///
/// MIT `group_init_state` (`groups.c:213-239`): `[libdefaults] spake_preauth_groups`, the client default when unset; no permitted group fails the module's init.
pub(super) fn client_groups() -> Vec<SpakeGroup> {
    let value = krb5_config::load_krb5_conf()
        .and_then(|c| c.spake_preauth_groups)
        .map(|words| words.join(" "));
    spake_parse_groups(value.as_deref().unwrap_or(SPAKE_DEFAULT_GROUPS_CLIENT))
}

/// One AS exchange's SPAKE state.
///
/// MIT `reqstate` (`spake_client.c:41-47`): the support message sent (for the transcript), and whether a challenge was answered.
struct SpakeState {
    groups: Vec<SpakeGroup>,
    support: Option<Vec<u8>>,
    responded: bool,
}

/// How a SPAKE attempt ends.
pub(super) enum SpakeEnd {
    /// The AS exchange finished.
    Done(Box<AsOutcome>),
    /// The module failed before answering a challenge: the next mechanism runs on this error's
    /// METHOD-DATA.
    Fallback(Box<KrbError>),
}

/// What the module adds to the next request.
enum Round {
    /// PA-SPAKE to send, and `K'[0]` when it is a response.
    Send(PaData, Option<ProtocolKey>),
    /// The module failed on this message.
    Failed,
}

/// The support message: the client's groups in configuration order, kept for the transcript.
///
/// MIT `send_support` (`spake_client.c:149-178`): the permitted groups, saved in `st->support`.
fn send_support(st: &mut SpakeState) -> PaData {
    let support = pa_spake_support(&st.groups);
    st.support = Some(support.padata_value.as_ref().to_vec());
    trace::spake_send_support();
    support
}

/// The answer to a challenge.
///
/// MIT `process_challenge` (`spake_client.c:180-298`): a second challenge after a response fails; a group the client lacks gets support unless support was sent; a factor list without SF-NONE fails; otherwise the response, `K'[0]` the reply key, and no fallback after it.
#[expect(
    clippy::too_many_arguments,
    reason = "the AS round's state, no value type"
)]
fn process_challenge(
    st: &mut SpakeState,
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    etypes: &[i32],
    current: &KrbError,
    hint: &mut S2kMaterial,
    ch: &SpakeChallenge,
    der_msg: &[u8],
    body_der: &[u8],
) -> Result<Round, Error> {
    if st.responded {
        return Ok(Round::Failed);
    }
    let Some(group) = SpakeGroup::from_number(ch.group).filter(|g| st.groups.contains(g)) else {
        trace::spake_reject_challenge(ch.group);
        if st.support.is_some() {
            return Ok(Round::Failed);
        }
        return Ok(Round::Send(send_support(st), None));
    };
    trace::spake_receive_challenge(ch.group, ch.pubkey.as_ref());
    if !spake_contains_sf_none(ch) {
        return Ok(Round::Failed);
    }
    // MIT `k5_get_etype_info` (`lib/krb5/krb/preauth2.c:790-854`): the challenge's own etype-info, when it has any, replaces the hint's.
    *hint = select_s2k_after(
        current,
        &salt_cname(&req.cname),
        req.realm,
        etypes,
        hint.clone(),
    )?;
    let (etype, salt, params) = hint.clone();
    trace_keytab_gak(req, keys, etype);
    let ikey = pick_key(keys, Some(etype)).map_or_else(
        || string_to_key(etype, req.password, &salt, params.as_deref()),
        Ok,
    )?;
    let support = st.support.clone().unwrap_or_default();
    // A challenge element that does not decode fails the module, before the fallback is off.
    let Ok((resp, k0)) = pa_spake_response(
        &ikey,
        group,
        &support,
        der_msg,
        ch.pubkey.as_ref(),
        body_der,
    ) else {
        return Ok(Round::Failed);
    };
    st.responded = true;
    Ok(Round::Send(resp, Some(k0)))
}

/// The module's answer to the PA-SPAKE of one KDC message.
///
/// MIT `spake_process` (`spake_client.c:322-363`): an empty PA-SPAKE gets support, once; a challenge goes to `process_challenge`; a message that does not decode, encdata or any other type fails.
#[expect(
    clippy::too_many_arguments,
    reason = "the AS round's state, no value type"
)]
fn spake_round(
    st: &mut SpakeState,
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    etypes: &[i32],
    current: &KrbError,
    hint: &mut S2kMaterial,
    pa_in: &[u8],
    body_der: &[u8],
) -> Result<Round, Error> {
    if pa_in.is_empty() {
        if st.support.is_some() {
            return Ok(Round::Failed);
        }
        return Ok(Round::Send(send_support(st), None));
    }
    // MIT `spake_prep_questions` (`spake_client.c:123-130`): a message that does not decode leaves no message, and processing it fails.
    let Ok(msg) = decode::<PaSpake>(pa_in) else {
        return Ok(Round::Failed);
    };
    match msg {
        PaSpake::Challenge(ch) => {
            process_challenge(st, req, keys, etypes, current, hint, &ch, pa_in, body_der)
        }
        // MIT `process_encdata` (`spake_client.c:300-320`): no second factors, so encdata fails.
        PaSpake::EncData(_) | PaSpake::Support(_) | PaSpake::Response(_) => Ok(Round::Failed),
    }
}

/// SPAKE through the rounds of one AS exchange, from the error that offered it.
///
/// MIT `init_creds_step_reply` (`get_in_tkt.c:1727-1745`): MORE_PREAUTH_DATA_REQUIRED's padata is processed next, PREAUTH_FAILED notes the mechanism failed and takes the error's hint, and PREAUTH_REQUIRED's hint replaces the method data.
/// MIT `init_creds_step_request` (`get_in_tkt.c:1309-1345`): a failure without the fallback off moves to the next mechanism on the method data; with it off, the exchange fails.
///
/// # Errors
///
/// The KDC's error once a response was sent, or any other KDC error; [`Error::Asn1`] when
/// METHOD-DATA does not decode; [`Error::Crypto`] when a string-to-key fails; transport errors.
pub(super) fn continue_spake(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    nonce: u32,
    bound: &AsReqTimes,
    etypes: &[i32],
    err: &KrbError,
    groups: &[SpakeGroup],
) -> Result<SpakeEnd, Error> {
    let mut st = SpakeState {
        groups: groups.to_vec(),
        support: None,
        responded: false,
    };
    // MIT `method_padata`: what the next mechanism runs on.
    let mut method_err = err.clone();
    // MIT `more_padata`, else `method_padata`: what this round processes.
    let mut current = err.clone();
    // MIT `k5_preauth` (`lib/krb5/krb/preauth2.c:987-990`): each error's etype-info is read as it arrives; a challenge that answers a request carrying the cookie names none, so the hint's stands.
    let mut hint = select_s2k(err, &salt_cname(&req.cname), req.realm, etypes)?;
    // The error that started this round, past the first, whose padata the trace shows first.
    let mut again: Option<i32> = None;
    loop {
        let method = method_from_error(&current)?;
        // MIT `init_creds_step_request` (`get_in_tkt.c:1308-1352`): more padata continues the
        // chosen mechanism; a new hint is preauthentication from the KDC's method data.
        match again {
            Some(err::MORE_PREAUTH_DATA_REQUIRED) => {
                trace::init_creds_preauth_more(pa::SPAKE);
                trace_preauth_input(&method, etypes);
            }
            Some(_) if trace::enabled() => {
                trace::init_creds_preauth();
                trace_preauth_input(
                    &sort_krb5_padata_sequence(&method, &conf_preferred_preauth_types()),
                    etypes,
                );
            }
            _ => {}
        }
        let mut req2 = build_as_req_from(req, nonce, bound, None, etypes)?;
        let body_der = encode(&req2.0.req_body)?;
        let round = match find_pa(&method, pa::SPAKE) {
            Some(p) => spake_round(
                &mut st,
                req,
                keys,
                etypes,
                &current,
                &mut hint,
                p.padata_value.as_ref(),
                &body_der,
            )?,
            None => Round::Failed,
        };
        let Round::Send(module_pa, k0) = round else {
            // MIT `process_pa_data` (`preauth2.c:648-728`): the module's failure is traced.
            trace::preauth_process(
                SPAKE_MODULE,
                pa::SPAKE,
                true,
                trace::kdc_code(err::PREAUTH_FAILED),
                None,
            );
            if st.responded {
                return Err(Error::KrbError {
                    code: err::PREAUTH_FAILED,
                    text: Some("SPAKE failed after its response".into()),
                });
            }
            return Ok(SpakeEnd::Fallback(Box::new(method_err)));
        };
        // MIT `k5_preauth` (`lib/krb5/krb/preauth2.c:992-1019`): the KDC's cookie first, then the module's padata; `init_creds_step_request` appends 150 and 149.
        let mut padata: Vec<PaData> = find_pa(&method, pa::FX_COOKIE)
            .cloned()
            .into_iter()
            .collect();
        padata.push(module_pa);
        trace::preauth_process(SPAKE_MODULE, pa::SPAKE, true, 0, None);
        trace::preauth_output(&padata);
        padata.extend(req2.0.padata.take().unwrap_or_default());
        req2.0.padata = Some(padata);
        let wire = encode(&req2)?;
        match send_as(req, &wire)? {
            KdcMsg::AsRep(rep) => {
                trace_reply_padata(rep.0.padata.as_deref(), etypes, None);
                // A reply to support alone is in the long-term key, as MIT's `gak_fct` gives it.
                let key = match k0 {
                    Some(k) => {
                        trace::init_creds_as_key_preauth((&k).into());
                        Some(k)
                    }
                    None => pick_key(keys, Some(hint.0)),
                };
                return finish_as_rep(
                    rep,
                    nonce,
                    key,
                    req.password,
                    &req.cname,
                    req.realm,
                    Some(pa::SPAKE),
                    req.canonicalize,
                    &req_sname(req),
                    bound,
                    Some(&wire),
                    false,
                )
                .map(|out| SpakeEnd::Done(Box::new(out)));
            }
            KdcMsg::Error(e) if e.error_code == err::MORE_PREAUTH_DATA_REQUIRED => {
                again = Some(e.error_code);
                current = e;
            }
            KdcMsg::Error(e) if e.error_code == err::PREAUTH_FAILED && !st.responded => {
                return Ok(SpakeEnd::Fallback(Box::new(if e.e_data.is_some() {
                    e
                } else {
                    method_err
                })));
            }
            KdcMsg::Error(e) if e.error_code == err::PREAUTH_REQUIRED && !st.responded => {
                again = Some(e.error_code);
                method_err = e.clone();
                current = e;
            }
            KdcMsg::Error(e) => {
                return classify_kdc_error(&e).map(|out| SpakeEnd::Done(Box::new(out)));
            }
            KdcMsg::TgsRep => return Err(Error::UnexpectedPdu),
        }
    }
}

/// `--spake` in a `test-hooks` build: SPAKE with the configured groups, and no fallback.
///
/// # Errors
///
/// [`Error::ReplyMismatch`] "SPAKE required" when the client has no group or SPAKE would fall
/// back; otherwise as [`continue_spake`].
pub(super) fn spake_forced(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    nonce: u32,
    bound: &AsReqTimes,
    etypes: &[i32],
    err: &KrbError,
) -> Result<AsOutcome, Error> {
    let groups = client_groups();
    if groups.is_empty() {
        return Err(Error::ReplyMismatch("SPAKE required".into()));
    }
    match continue_spake(req, keys, nonce, bound, etypes, err, &groups)? {
        SpakeEnd::Done(out) => Ok(*out),
        SpakeEnd::Fallback(_) => Err(Error::ReplyMismatch("SPAKE required".into())),
    }
}

/// MIT `contains_sf_none` (`spake_client.c:51-51`): true when the challenge lists the SF-NONE
/// second factor, the only factor type this client can answer.
pub(super) fn spake_contains_sf_none(chal: &SpakeChallenge) -> bool {
    chal.factors.iter().any(|f| f.factor_type == SF_NONE)
}

pub(super) fn refuse_spake_skip(want_spake: bool) -> Result<(), Error> {
    if want_spake {
        Err(Error::ReplyMismatch("SPAKE required".into()))
    } else {
        Ok(())
    }
}

pub(super) fn refuse_spake_combo(req: &AsRequest<'_>) -> Result<(), Error> {
    if req.want_spake && (req.fast_armor.is_some() || req.pkinit.is_some()) {
        Err(Error::ReplyMismatch("SPAKE exclusive".into()))
    } else {
        Ok(())
    }
}
