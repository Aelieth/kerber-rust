//! The SPAKE clpreauth module.

use krb5_asn1::{decode, encode};
use krb5_config::Krb5Conf;
use krb5_crypto::{
    ProtocolKey, SPAKE_DEFAULT_GROUPS_CLIENT, SpakeGroup, spake_parse_groups, string_to_key,
};
use krb5_types::spake::{PaSpake, SF_NONE, SpakeChallenge};
use krb5_types::{KrbError, PaData, err, pa};

use super::clock::Clock;
use super::fast::ask_responder;
use super::password::{CANTREADPWD, ModuleFail, PasswordCell};
use super::{
    AsOutcome, AsRequest, KdcMsg, S2kMaterial, allowed_padata, build_as_req_from,
    classify_kdc_error, conf_preferred_preauth_types_for, find_pa, finish_as_rep,
    method_from_error, pick_key, req_sname, request_times, retried, salt_cname, select_s2k,
    select_s2k_after, send_as, sort_krb5_padata_sequence, trace_keytab_gak, trace_preauth_input,
    trace_reply_padata,
};
use crate::error::Error;
use crate::preauth::{pa_spake_response, pa_spake_support};
use crate::trace;

const SPAKE_MODULE: &str = "spake";

/// The groups the client permits, in configuration order; none means no SPAKE module.
/// MIT `group_init_state` (`groups.c:213-239`): `[libdefaults] spake_preauth_groups`, the client default when unset; no permitted group fails the module's init.
pub(super) fn client_groups(profile: &Krb5Conf) -> Vec<SpakeGroup> {
    let value = profile
        .spake_preauth_groups
        .as_ref()
        .map(|words| words.join(" "));
    spake_parse_groups(value.as_deref().unwrap_or(SPAKE_DEFAULT_GROUPS_CLIENT))
}

/// MIT `reqstate` (`spake_client.c:41-47`): the support message sent (for the transcript), and whether a challenge was answered.
struct SpakeState {
    groups: Vec<SpakeGroup>,
    support: Option<Vec<u8>>,
    responded: bool,
}

/// How a SPAKE attempt ends.
pub(super) enum SpakeEnd {
    Done(Box<AsOutcome>),
    /// METHOD-DATA. `fail` is the module's own failure, with its password read among the causes; it is `None` when the KDC refused the support message with `PREAUTH_FAILED`.
    /// `refusal` is the KDC's `PREAUTH_FAILED` that ended a support message: MIT keeps it, and reports it if the mechanisms after it fail too. `new_walk` says a request went out before the fallback, so the next mechanism runs in a new walk over the method data; without it the walk goes on from the mechanism after this one.
    Fallback {
        hint: Box<KrbError>,
        fail: Option<ModuleFail>,
        refusal: Option<Box<KrbError>>,
        new_walk: bool,
    },
}

enum Round {
    Send(PaData, Option<ProtocolKey>),
    Failed(ModuleFail),
}

/// What one round of the module under FAST adds to the inner request.
pub(super) enum FastRound {
    Send(PaData, Option<ProtocolKey>),
    Failed(ModuleFail),
}

const EINVAL: i64 = 22;

fn generic_failure() -> ModuleFail {
    let code = trace::kdc_code(err::PREAUTH_FAILED);
    ModuleFail::new(code, &trace::error_message(code))
}

/// MIT `send_support` (`spake_client.c:149-178`): the permitted groups, saved in `st->support`.
fn send_support(st: &mut SpakeState) -> PaData {
    let support = pa_spake_support(&st.groups);
    st.support = Some(support.padata_value.as_ref().to_vec());
    trace::spake_send_support();
    support
}

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
    pw: &mut PasswordCell<'_, '_>,
) -> Result<Round, Error> {
    if st.responded {
        return Ok(Round::Failed(generic_failure()));
    }
    let Some(group) = SpakeGroup::from_number(ch.group).filter(|g| st.groups.contains(g)) else {
        trace::spake_reject_challenge(ch.group);
        if st.support.is_some() {
            return Ok(Round::Failed(generic_failure()));
        }
        return Ok(Round::Send(send_support(st), None));
    };
    trace::spake_receive_challenge(ch.group, ch.pubkey.as_ref());
    if !spake_contains_sf_none(ch) {
        return Ok(Round::Failed(generic_failure()));
    }
    *hint = select_s2k_after(
        current,
        &salt_cname(&req.cname),
        req.realm,
        etypes,
        hint.clone(),
    )?;
    let (etype, salt, params) = hint.clone();
    trace_keytab_gak(req, keys, pw.unreadable_keytab(), etype);
    let ikey = match pick_key(keys, Some(etype)) {
        Some(key) => key,
        None => match pw.get() {
            Ok(password) => string_to_key(etype, &password, &salt, params.as_deref())?,
            Err(f) => return Ok(Round::Failed(f)),
        },
    };
    let support = st.support.clone().unwrap_or_default();
    let Ok((resp, k0)) = pa_spake_response(
        &ikey,
        group,
        &support,
        der_msg,
        ch.pubkey.as_ref(),
        body_der,
    ) else {
        return Ok(Round::Failed(ModuleFail::new(EINVAL, "Invalid argument")));
    };
    st.responded = true;
    Ok(Round::Send(resp, Some(k0)))
}

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
    pw: &mut PasswordCell<'_, '_>,
) -> Result<Round, Error> {
    if pa_in.is_empty() {
        if st.support.is_some() {
            return Ok(Round::Failed(generic_failure()));
        }
        return Ok(Round::Send(send_support(st), None));
    }
    let Ok(msg) = decode::<PaSpake>(pa_in) else {
        return Ok(Round::Failed(generic_failure()));
    };
    match msg {
        PaSpake::Challenge(ch) => process_challenge(
            st, req, keys, etypes, current, hint, &ch, pa_in, body_der, pw,
        ),
        // MIT `process_encdata` (`spake_client.c:300-320`): no second factors, so encdata fails.
        PaSpake::EncData(_) | PaSpake::Support(_) | PaSpake::Response(_) | PaSpake::Unknown => {
            Ok(Round::Failed(generic_failure()))
        }
    }
}

/// One FAST inner exchange's SPAKE module state.
pub(super) struct FastSpake {
    st: SpakeState,
    hint: S2kMaterial,
}

impl FastSpake {
    pub(super) fn begin(
        req: &AsRequest<'_>,
        etypes: &[i32],
        err: &KrbError,
    ) -> Result<Self, Error> {
        Ok(Self {
            st: SpakeState {
                groups: client_groups(req.profile),
                support: None,
                responded: false,
            },
            hint: select_s2k(err, &salt_cname(&req.cname), req.realm, etypes)?,
        })
    }

    /// The module's PA-SPAKE for this inner request, and the AS key FAST will strengthen.
    pub(super) fn round(
        &mut self,
        req: &AsRequest<'_>,
        keys: &[ProtocolKey],
        etypes: &[i32],
        current: &KrbError,
        body_der: &[u8],
        pw: &mut PasswordCell<'_, '_>,
    ) -> Result<FastRound, Error> {
        let method = method_from_error(current)?;
        let Some(p) = find_pa(&method, pa::SPAKE) else {
            let fail = generic_failure();
            fail.trace(SPAKE_MODULE, pa::SPAKE);
            return Ok(FastRound::Failed(fail));
        };
        let round = spake_round(
            &mut self.st,
            req,
            keys,
            etypes,
            current,
            &mut self.hint,
            p.padata_value.as_ref(),
            body_der,
            pw,
        )?;
        match round {
            Round::Send(module_pa, k0) => {
                trace::preauth_process(SPAKE_MODULE, pa::SPAKE, true, 0, None);
                Ok(FastRound::Send(module_pa, k0))
            }
            Round::Failed(fail) => {
                fail.trace(SPAKE_MODULE, pa::SPAKE);
                Ok(FastRound::Failed(fail))
            }
        }
    }

    /// The long-term key a reply to the support message alone is decrypted under: a keytab key, or the password's, read now if no module has read it.
    pub(super) fn long_term_key(
        &self,
        keys: &[ProtocolKey],
        pw: &mut PasswordCell<'_, '_>,
    ) -> Result<ProtocolKey, Error> {
        let (etype, salt, params) = self.hint.clone();
        if let Some(key) = pick_key(keys, Some(etype)) {
            return Ok(key);
        }
        let password = pw.get().map_err(ModuleFail::unwrapped)?;
        Ok(string_to_key(etype, &password, &salt, params.as_deref())?)
    }

    /// A challenge response was sent, so MIT `disable_fallback` is in force.
    pub(super) fn answered(&self) -> bool {
        self.st.responded
    }
}

/// Whether the PA-SPAKE value `pa_in` of a hint needs the AS key, which is when SPAKE asks the responder for the password. An empty one is a support message, and one that does not decode asks nothing; a challenge needs it when its group is one the client permits and its factors list SF-NONE.
pub(super) fn prep_needs_key(profile: &Krb5Conf, pa_in: &[u8]) -> bool {
    if pa_in.is_empty() {
        return false;
    }
    let Ok(PaSpake::Challenge(ch)) = decode::<PaSpake>(pa_in) else {
        return false;
    };
    SpakeGroup::from_number(ch.group).is_some_and(|g| client_groups(profile).contains(&g))
        && spake_contains_sf_none(&ch)
}

/// The trace lines that open a round after the first, from the error that `again` names.
pub(super) fn trace_round(
    again: Option<i32>,
    req: &AsRequest<'_>,
    method: &[PaData],
    etypes: &[i32],
) {
    match again {
        Some(err::MORE_PREAUTH_DATA_REQUIRED) => {
            trace::init_creds_preauth_more(pa::SPAKE);
            trace_preauth_input(method, etypes);
        }
        Some(_) if trace::enabled() => {
            trace::init_creds_preauth();
            trace_preauth_input(
                &sort_krb5_padata_sequence(
                    method,
                    &conf_preferred_preauth_types_for(req.profile, req.realm),
                ),
                etypes,
            );
        }
        _ => {}
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the AS round's state, no value type"
)]
pub(super) fn continue_spake(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    nonce: u32,
    etypes: &[i32],
    err: &KrbError,
    groups: &[SpakeGroup],
    clock: &Clock,
    pw: &mut PasswordCell<'_, '_>,
) -> Result<SpakeEnd, Error> {
    let mut st = SpakeState {
        groups: groups.to_vec(),
        support: None,
        responded: false,
    };
    let mut method_err = err.clone();
    let mut current = err.clone();
    let mut hint = select_s2k(err, &salt_cname(&req.cname), req.realm, etypes)?;
    let mut again: Option<i32> = None;
    loop {
        let method = method_from_error(&current)?;
        trace_round(again, req, &method, etypes);
        if again.is_some() {
            ask_responder(req, pw, None, &allowed_padata(req, &method))?;
        }
        let bound = request_times(req, clock);
        let mut req2 = build_as_req_from(req, nonce, &bound, None, etypes)?;
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
                pw,
            )?,
            None => Round::Failed(generic_failure()),
        };
        let (module_pa, k0) = match round {
            Round::Send(module_pa, k0) => (module_pa, k0),
            Round::Failed(fail) => {
                fail.trace(SPAKE_MODULE, pa::SPAKE);
                if fail.interrupted {
                    return Err(fail.error);
                }
                if st.responded {
                    return Err(Error::KrbError {
                        code: err::PREAUTH_FAILED,
                        text: Some("SPAKE failed after its response".into()),
                    });
                }
                return Ok(SpakeEnd::Fallback {
                    hint: Box::new(method_err),
                    fail: Some(fail),
                    refusal: None,
                    new_walk: again.is_some(),
                });
            }
        };
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
                // got now: a keytab key, else the password's, read if no module has read it.
                let key = match k0 {
                    Some(k) => {
                        trace::init_creds_as_key_preauth((&k).into());
                        Some(k)
                    }
                    None => pick_key(keys, Some(hint.0)),
                };
                let password = if key.is_none() {
                    pw.get().map_err(ModuleFail::unwrapped)?
                } else {
                    zeroize::Zeroizing::new(Vec::new())
                };
                return finish_as_rep(
                    req.profile,
                    rep,
                    nonce,
                    key,
                    &password,
                    &req.cname,
                    req.realm,
                    Some(pa::SPAKE),
                    req.canonicalize,
                    &req_sname(req),
                    &bound,
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
                if retried(&e) {
                    clock.note(&e, false);
                }
                return Ok(SpakeEnd::Fallback {
                    hint: Box::new(if e.e_data.is_some() {
                        e.clone()
                    } else {
                        method_err
                    }),
                    fail: None,
                    refusal: Some(Box::new(e)),
                    new_walk: true,
                });
            }
            KdcMsg::Error(e) if e.error_code == err::PREAUTH_REQUIRED && !st.responded => {
                if retried(&e) {
                    clock.note(&e, false);
                }
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
pub(super) fn spake_forced(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    nonce: u32,
    etypes: &[i32],
    err: &KrbError,
    clock: &Clock,
    pw: &mut PasswordCell<'_, '_>,
) -> Result<AsOutcome, Error> {
    let groups = client_groups(req.profile);
    if groups.is_empty() {
        return Err(Error::ReplyMismatch("SPAKE required".into()));
    }
    match continue_spake(req, keys, nonce, etypes, err, &groups, clock, pw)? {
        SpakeEnd::Done(out) => Ok(*out),
        SpakeEnd::Fallback { fail: Some(f), .. } if f.code == CANTREADPWD => {
            Err(Error::PreauthFailed(Box::new(f.error)))
        }
        SpakeEnd::Fallback { .. } => Err(Error::ReplyMismatch("SPAKE required".into())),
    }
}

/// MIT `contains_sf_none` (`spake_client.c:51-51`): true when the challenge lists the SF-NONE second factor, the only factor type this client can answer.
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
