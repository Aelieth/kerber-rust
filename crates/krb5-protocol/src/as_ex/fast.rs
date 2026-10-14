//! RFC 6113 FAST armor on the AS exchange (`lib/krb5/krb/fast.c`
//! `krb5int_fast_process_response` / `krb5int_fast_process_error`).

use super::clock::Clock;
use super::ec::{EC_MODULE, client_challenge, reply_code};
use super::otp::{self, OTP_MODULE, OtpState};
use super::password::{ModuleFail, PasswordCell};
use super::responder::{QUESTION_PASSWORD, ResponderItems};
use super::spake::{FastRound, trace_round};
use super::{
    AsOutcome, AsPrompt, AsReqTimes, AsRequest, ENCTS_MODULE, KdcMsg, allowed_padata,
    build_as_req_from, classify_kdc_error, encrypted_timestamp_disabled, find_pa, finish_as_rep,
    first_etype, gak_found, kdc_error, method_from_error, pa_enc_timestamp_at, pick_info2,
    pick_key, req_sname, request_times, salt_cname, select_s2k, send_as, sort_krb5_padata_sequence,
    trace_keytab_gak, trace_preauth_input, trace_reply_padata,
};
use crate::error::Error;
use crate::keytab::KeytabFailure;
use crate::preauth::{
    apply_strengthen, armor_key, attach_fast, build_fast_armor, unwrap_fast_rep_checked,
    verify_fast_finished,
};
use crate::trace;
use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
use krb5_types::k5json::{self, Value};
use krb5_types::{AsRep, EtypeInfo2, KrbError, MethodData, PaData, PrincipalName, err, pa};

/// Ticket used as RFC 6113 FAST AP-REQUEST armor.
pub struct FastArmor {
    /// Armor ticket (usually a TGT).
    pub ticket: krb5_types::Ticket,
    /// Session key of `ticket`.
    pub session: ProtocolKey,
    /// Client realm in the armor authenticator.
    pub crealm: krb5_types::Realm,
    /// Client name in the armor authenticator.
    pub cname: PrincipalName,
}

/// MIT `init_creds_step_reply` (`get_in_tkt.c:1727-1728`): only a preauth-required error that is
/// marked retry continues. An outer error that did not unwrap is returned as itself, and the
/// cookie leads the inner padata on the retry.
/// MIT `fast_armor_ap_request` (`lib/krb5/krb/fast.c:52-108`): the armor ticket's session key, the
/// armor authenticator and the armor key are traced as they are made.
#[expect(
    clippy::too_many_arguments,
    reason = "the AS round's state, no value type"
)]
pub(super) fn continue_fast(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    unreadable: Option<&KeytabFailure>,
    nonce: u32,
    bound: &AsReqTimes,
    etypes: &[i32],
    clock: &Clock,
    prompt: Option<&mut dyn AsPrompt>,
) -> Result<AsOutcome, Error> {
    let armor = req
        .fast_armor
        .ok_or_else(|| Error::ReplyMismatch("FAST armor missing".into()))?;
    let sub = ProtocolKey::random(armor.session.etype())?;
    let akey = armor_key(&armor.session, Some(&sub))?;
    // RFC 6113 reply-key base is the PA-ETYPE-INFO2 long-term key, not preferred()[0].
    let ap = fast_armor_ap(armor, &sub)?;
    trace::fast_armor_ccache_key((&armor.session).into());
    trace::mk_req(
        trace::Princ::new(&armor.cname, armor.crealm.as_bytes()),
        trace::Princ::new(&armor.ticket.sname, armor.ticket.realm.as_bytes()),
        0,
        Some((&sub).into()),
        (&armor.session).into(),
    );
    trace::fast_armor_key((&akey).into());
    let mut probe = build_as_req_from(req, nonce, bound, None, etypes)?;
    trace::init_creds_preauth_none();
    attach_fast(&mut probe, &ap, &akey, Vec::new())?;
    trace::fast_encode();
    let wire = encode(&probe)?;
    match send_as(req, &wire)? {
        KdcMsg::AsRep(rep) => {
            // MIT `decrypt_as_reply` (`lib/krb5/krb/get_in_tkt.c:96-123`): no module answered, so the reply key is got now, from the password.
            let mut pw = PasswordCell::new(
                prompt,
                req.password,
                !keys.is_empty() || unreadable.is_some(),
            )
            .with_unreadable_keytab(unreadable);
            finish_fast_as(
                req,
                keys,
                nonce,
                etypes,
                &akey,
                ReplyKey::Gak(&mut pw),
                rep,
                &wire,
                bound,
            )
        }
        KdcMsg::Error(e) => {
            let FastErrorMaterial {
                err: inner,
                cookie,
                retry,
            } = fast_error_material(&akey, &e, nonce)?;
            // MIT `init_creds_step_reply` (`get_in_tkt.c:1721-1724`): only
            // `PREAUTH_REQUIRED && retry` continues; an outer error that did not unwrap
            // (retry = 0) is returned as-is — no second AS-REQ, whatever its code.
            if !retry || inner.error_code != err::PREAUTH_REQUIRED {
                return classify_kdc_error(&inner);
            }
            // The KDC's time, authenticated by the armor.
            clock.note(&inner, true);
            // MIT `get_as_key` (`lib/krb5/krb/preauth2.c:438-457`): the password is read when a
            // mechanism first needs the key, not before one is chosen; OTP never needs it.
            let mut pw = PasswordCell::new(
                prompt,
                req.password,
                !keys.is_empty() || unreadable.is_some(),
            )
            .with_unreadable_keytab(unreadable);
            let cc_in: Option<Value> = req
                .ticket
                .pa_config_in
                .as_ref()
                .and_then(|j| k5json::decode(j).ok())
                .filter(|v| matches!(v, Value::Object(_)));
            let mut otp_state = OtpState::default();
            // MIT `process_pa_data` (`lib/krb5/krb/preauth2.c:699-704`): the first failure of a
            // real mechanism is the one kept; if none answers, that is what the exchange reports.
            let mut first_failure: Option<Error> = None;
            // MIT `init_creds_step_reply` (`get_in_tkt.c:1731-1740`): PREAUTH_FAILED on a
            // mechanism that has not disabled fallback notes it failed and tries the next one.
            let mut current = inner;
            let mut cookie_slot = cookie;
            let mut skip: Vec<i32> = Vec::new();
            let mut saved_method: Vec<PaData> = Vec::new();
            let mut last_fail: Option<KrbError> = None;
            'rounds: loop {
                let mut method = sort_krb5_padata_sequence(
                    &method_from_error(&current).unwrap_or_default(),
                    &super::conf_preferred_preauth_types_for(req.realm),
                );
                // MIT `pa_type_allowed` (`lib/krb5/krb/preauth2.c:627-631`): a type the input cache does not allow is not tried.
                method.retain(|p| req.ticket.preauth_allowed(p.padata_type));
                if fast_mechanism(&method, &skip).is_err() && !saved_method.is_empty() {
                    method.clone_from(&saved_method);
                }
                if trace::enabled() {
                    trace::init_creds_preauth();
                    trace_preauth_input(&method, etypes);
                }
                // MIT `k5_preauth` (`lib/krb5/krb/preauth2.c:1004-1016`): every module with a padata
                // in the list prepares first, and the responder answers what was asked, before a
                // mechanism is chosen; a failure there ends the exchange.
                let items = ask_responder(
                    req,
                    &mut pw,
                    Some((&mut otp_state, cc_in.as_ref())),
                    &method,
                )?;
                // MIT `process_pa_data` (`lib/krb5/krb/preauth2.c:667-723`): the real mechanisms in
                // the list's order; one that fails is traced and the next one is tried, and a
                // keyboard interrupt ends the walk.
                loop {
                    let mech = match fast_mechanism(&method, &skip) {
                        Ok(mech) => mech,
                        Err(e) => {
                            return match (last_fail, first_failure) {
                                (Some(err), _) => Err(kdc_error(&err)),
                                (None, Some(first)) => Err(Error::PreauthFailed(Box::new(first))),
                                (None, None) => Err(e),
                            };
                        }
                    };
                    let (fail, new_walk) = match mech {
                        pa::OTP_CHALLENGE => {
                            match otp::process(&otp_state, &items, pw.ui(), &akey) {
                                Ok((pa142, config)) => {
                                    return finish_fast_otp(
                                        req,
                                        nonce,
                                        etypes,
                                        clock,
                                        armor,
                                        &sub,
                                        &akey,
                                        cookie_slot,
                                        pa142,
                                        &config,
                                    );
                                }
                                Err(f) => {
                                    f.trace(OTP_MODULE, pa::OTP_CHALLENGE);
                                    (f, false)
                                }
                            }
                        }
                        pa::SPAKE => {
                            saved_method.clone_from(&method);
                            match finish_fast_spake(
                                req,
                                keys,
                                nonce,
                                etypes,
                                clock,
                                armor,
                                &sub,
                                &akey,
                                &current,
                                cookie_slot.clone(),
                                &mut pw,
                            )? {
                                SpakeFast::Done(out) => return Ok(*out),
                                SpakeFast::Next { err, cookie: next } => {
                                    skip.push(pa::SPAKE);
                                    last_fail = Some((*err).clone());
                                    current = *err;
                                    cookie_slot = next;
                                    continue 'rounds;
                                }
                                SpakeFast::Failed { fail, new_walk } => (fail, new_walk),
                            }
                        }
                        _ => match fast_key_mechanism(
                            req,
                            keys,
                            nonce,
                            etypes,
                            clock,
                            armor,
                            &sub,
                            &akey,
                            &current,
                            cookie_slot.as_ref(),
                            mech,
                            &mut pw,
                        )? {
                            Ok(out) => return Ok(out),
                            Err(f) => (f, false),
                        },
                    };
                    if fail.interrupted {
                        return Err(fail.error);
                    }
                    skip.push(mech);
                    first_failure.get_or_insert(fail.error);
                    if new_walk {
                        continue 'rounds;
                    }
                }
            }
        }
        KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
    }
}

/// Encrypted challenge or encrypted timestamp under armor: the module gets the AS key, then answers
/// the hint with the request that carries its padata, and no other mechanism follows. A password
/// the prompter cannot read fails the module before any request is sent, and the walk goes on.
/// MIT `ec_process` (`lib/krb5/krb/preauth_ec.c:63-64`): `get_as_key` runs first, and its error is the module's.
/// MIT `encts_process` (`lib/krb5/krb/preauth_encts.c:75-77`): the same for encrypted timestamp.
/// MIT `process_pa_data` (`lib/krb5/krb/preauth2.c:684-686`): the failure is traced under the module's name.
///
/// # Errors
///
/// The exchange's error once the request is sent, or an error that is no module's failure.
#[expect(
    clippy::too_many_arguments,
    reason = "the FAST retry's existing locals"
)]
fn fast_key_mechanism(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    nonce: u32,
    etypes: &[i32],
    clock: &Clock,
    armor: &FastArmor,
    sub: &ProtocolKey,
    akey: &ProtocolKey,
    current: &KrbError,
    cookie: Option<&PaData>,
    mech: i32,
    pw: &mut PasswordCell<'_, '_>,
) -> Result<Result<AsOutcome, ModuleFail>, Error> {
    let name = if mech == pa::ENCRYPTED_CHALLENGE {
        EC_MODULE
    } else {
        ENCTS_MODULE
    };
    // MIT `encts_process` (`lib/krb5/krb/preauth_encts.c:68-73`): the realm's disable fails the module before it asks for the key.
    if mech == pa::ENC_TIMESTAMP && encrypted_timestamp_disabled(req.realm) {
        let f = ModuleFail::encts_disabled();
        f.trace(name, mech);
        return Ok(Err(f));
    }
    let (etype, salt, params) = select_s2k(current, &salt_cname(&req.cname), req.realm, etypes)?;
    trace_keytab_gak(req, keys, pw.unreadable_keytab(), etype);
    let client_key = match pick_key(keys, Some(etype)) {
        Some(key) => key,
        None => match pw.get() {
            Ok(password) => string_to_key(etype, &password, &salt, params.as_deref())?,
            Err(f) => {
                f.trace(name, mech);
                return Ok(Err(f));
            }
        },
    };
    // MIT k5_preauth copies the FX-COOKIE (copy_cookie) before the
    // preauth module's PA data, so the cookie leads the inner padata.
    let mut inner_pa = Vec::new();
    if let Some(c) = cookie {
        inner_pa.push(c.clone());
    }
    if mech == pa::ENCRYPTED_CHALLENGE {
        // MIT `ec_process` takes the time without an unauthenticated offset.
        let (now, usec) = clock.now(false);
        // MIT `ec_process` (`lib/krb5/krb/preauth_ec.c:108-112`): the challenge key is made from the client key with `krb5_c_fx_cf2_simple`, which fails with the key's code when it is a des3 key MIT refuses, and that is the module's failure.
        match client_challenge(akey, &client_key, (&now, usec)) {
            Ok(p) => inner_pa.push(p),
            Err(e @ (Error::DesBadParity | Error::DesWeakKey)) => {
                let f = ModuleFail::des_key(e);
                f.trace(name, mech);
                return Ok(Err(f));
            }
            Err(e) => return Err(e),
        }
        trace::preauth_process(EC_MODULE, mech, true, 0, None);
    } else {
        if gak_found(keys, &client_key, etype) {
            trace::preauth_enc_ts_key_gak((&client_key).into());
        }
        // MIT `encts_process` (`lib/krb5/krb/preauth_encts.c:87-97`): `krb5_encrypt_helper` fails with the key's code when the key is a des3 key MIT refuses, and that is the module's failure.
        match pa_enc_timestamp_at(&client_key, clock.now(true), true) {
            Ok(p) => inner_pa.push(p),
            Err(e @ (Error::DesBadParity | Error::DesWeakKey)) => {
                let f = ModuleFail::des_key(e);
                f.trace(name, mech);
                return Ok(Err(f));
            }
            Err(e) => return Err(e),
        }
        trace::preauth_process(ENCTS_MODULE, mech, true, 0, None);
    }
    trace::preauth_output(&inner_pa);
    let ap = fast_armor_ap(armor, sub)?;
    let bound = &request_times(req, clock);
    let mut req2 = build_as_req_from(req, nonce, bound, None, etypes)?;
    attach_fast(&mut req2, &ap, akey, inner_pa)?;
    trace::fast_encode();
    let wire = encode(&req2)?;
    match send_as(req, &wire)? {
        KdcMsg::AsRep(rep) => finish_fast_as(
            req,
            keys,
            nonce,
            etypes,
            akey,
            ReplyKey::Preauth(client_key, mech),
            rep,
            &wire,
            bound,
        ),
        KdcMsg::Error(e) => classify_kdc_error(&fast_error_material(akey, &e, nonce)?.err),
        KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
    }
    .map(Ok)
}

/// One call of MIT's `k5_preauth` up to its modules: every module with a padata in `method`
/// prepares its questions, the responder answers what was asked, and its answer to the password
/// question is offered to the cell as the password. `otp` is the OTP module's state and the input
/// cache's config, present only where that module runs (under FAST).
/// MIT `k5_preauth` (`lib/krb5/krb/preauth2.c:1004-1016`): `fill_response_items`, then the responder when a question was asked.
///
/// # Errors
///
/// The OTP module's preparation failing, or the responder's error: either ends the exchange.
pub(super) fn ask_responder(
    req: &AsRequest<'_>,
    pw: &mut PasswordCell<'_, '_>,
    otp: Option<(&mut OtpState, Option<&Value>)>,
    method: &[PaData],
) -> Result<ResponderItems, Error> {
    let mut items = ResponderItems::default();
    fill_response_items(
        &mut items,
        otp,
        method,
        pw.asks_question(),
        encrypted_timestamp_disabled(req.realm),
    )?;
    call_responder(pw, &mut items)?;
    Ok(items)
}

/// The responder is called when `items` holds a question, and its answer to the password question
/// is offered to the cell.
/// MIT `k5_preauth` (`lib/krb5/krb/preauth2.c:1010-1016`): the responder is called only when a module asked a question.
fn call_responder(pw: &mut PasswordCell<'_, '_>, items: &mut ResponderItems) -> Result<(), Error> {
    if !items.is_empty()
        && let Some(r) = pw.responder()
    {
        r.respond(items)?;
    }
    pw.offer(items.get_answer(QUESTION_PASSWORD));
    Ok(())
}

/// The password question put to the responder before a reply's key is got: no preauth module
/// answered the AS-REQ, so the reply is decrypted under a key made from the password.
/// MIT `decrypt_as_reply` (`lib/krb5/krb/get_in_tkt.c:96-111`): with a responder, `gak_fct` is called for its question before it is called for the key, and the responder runs when it asked one.
/// MIT `krb5_get_as_key_password` (`lib/krb5/krb/gic_pwd.c:30-38`): the question is asked only while no password is held.
///
/// # Errors
///
/// The responder's error, which ends the exchange.
pub(super) fn ask_gak_question(pw: &mut PasswordCell<'_, '_>) -> Result<(), Error> {
    let mut items = ResponderItems::default();
    if pw.asks_question() {
        items.ask_question(QUESTION_PASSWORD, Some(b"".as_slice()));
    }
    call_responder(pw, &mut items)
}

/// MIT `fill_response_items` (`lib/krb5/krb/preauth2.c:937-965`): every loaded module with a padata
/// in the list prepares its questions in the list's order, and a failure ends the round.
/// MIT `ec_prep_questions` (`lib/krb5/krb/preauth_ec.c:36-45`): encrypted challenge asks the password question.
/// MIT `encts_prep_questions` (`lib/krb5/krb/preauth_encts.c:33-47`): encrypted timestamp asks it too, unless the realm disables it.
/// MIT `spake_prep_questions` (`plugins/preauth/spake/spake_client.c:119-141`): SPAKE asks it for a challenge it can answer, and for nothing else.
/// MIT `krb5_get_as_key_password` (`lib/krb5/krb/gic_pwd.c:30-38`): the question is asked only when the caller gave neither a password nor a keytab, and no module holds the password yet.
fn fill_response_items(
    items: &mut ResponderItems,
    mut otp: Option<(&mut OtpState, Option<&Value>)>,
    method: &[PaData],
    ask_password: bool,
    encts_off: bool,
) -> Result<(), Error> {
    let otp_on = crate::clpreauth::loaded(OTP_MODULE);
    let ec_on = ask_password && crate::clpreauth::loaded(EC_MODULE);
    let encts_on = ask_password && !encts_off && crate::clpreauth::loaded(ENCTS_MODULE);
    let spake_on = ask_password && crate::clpreauth::loaded("spake");
    for p in method {
        match p.padata_type {
            pa::OTP_CHALLENGE if otp_on => {
                if let Some((state, cc_in)) = otp.as_mut() {
                    otp::prep_questions(state, p, *cc_in, items)?;
                }
            }
            pa::ENCRYPTED_CHALLENGE if ec_on => {
                items.ask_question(QUESTION_PASSWORD, Some(b"".as_slice()));
            }
            pa::ENC_TIMESTAMP if encts_on => {
                items.ask_question(QUESTION_PASSWORD, Some(b"".as_slice()));
            }
            pa::SPAKE if spake_on && super::spake::prep_needs_key(p.padata_value.as_ref()) => {
                items.ask_question(QUESTION_PASSWORD, Some(b"".as_slice()));
            }
            _ => {}
        }
    }
    Ok(())
}

/// The PA-OTP-REQUEST goes out in the FAST request and its reply ends the exchange: the armor key
/// is the AS key, and an error reply is the KDC's, with no other mechanism after it.
/// MIT `otp_client_process` (`lib/krb5/krb/preauth_otp.c:1118-1127`): `set_as_key(armor key)`, then `disable_fallback`.
/// MIT `init_creds_step_request` (`lib/krb5/krb/get_in_tkt.c:1334-1336`): with fallback disabled a failed request is the error returned.
#[expect(
    clippy::too_many_arguments,
    reason = "the FAST retry's existing locals"
)]
fn finish_fast_otp(
    req: &AsRequest<'_>,
    nonce: u32,
    etypes: &[i32],
    clock: &Clock,
    armor: &FastArmor,
    sub: &ProtocolKey,
    akey: &ProtocolKey,
    cookie: Option<PaData>,
    pa142: PaData,
    config: &Value,
) -> Result<AsOutcome, Error> {
    let mut inner_pa = Vec::new();
    if let Some(c) = cookie {
        inner_pa.push(c);
    }
    inner_pa.push(pa142);
    trace::preauth_process(OTP_MODULE, pa::OTP_CHALLENGE, true, 0, None);
    trace::preauth_output(&inner_pa);
    let ap = fast_armor_ap(armor, sub)?;
    let bound = &request_times(req, clock);
    let mut req2 = build_as_req_from(req, nonce, bound, None, etypes)?;
    attach_fast(&mut req2, &ap, akey, inner_pa)?;
    trace::fast_encode();
    let wire = encode(&req2)?;
    match send_as(req, &wire)? {
        KdcMsg::AsRep(rep) => {
            let mut out = finish_fast_as(
                req,
                &[],
                nonce,
                etypes,
                akey,
                ReplyKey::Preauth(akey.clone(), pa::OTP_CHALLENGE),
                rep,
                &wire,
                bound,
            )?;
            out.pa_config = otp::config_string(config);
            Ok(out)
        }
        KdcMsg::Error(e) => classify_kdc_error(&fast_error_material(akey, &e, nonce)?.err),
        KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
    }
}

/// How a SPAKE attempt under FAST ended.
enum SpakeFast {
    /// The exchange finished.
    Done(Box<AsOutcome>),
    /// Support was sent and the KDC answered `PREAUTH_FAILED`. MIT disables fallback only after
    /// a challenge response, so the next loaded mechanism still runs.
    Next {
        err: Box<KrbError>,
        cookie: Option<PaData>,
    },
    /// The module failed before it answered, its password read among the causes. The failure is
    /// traced, and MIT's walk goes on to the next real mechanism of the list.
    /// MIT `process_pa_data` (`lib/krb5/krb/preauth2.c:699-723`): a real type that fails is noted failed, and the loop tries the next.
    /// MIT `init_creds_step_request` (`lib/krb5/krb/get_in_tkt.c:1343-1348`): a failure that came after a request was sent (the challenge was a reply to the support message) is followed by a new walk over the method data (`new_walk`).
    Failed { fail: ModuleFail, new_walk: bool },
}

/// SPAKE inside FAST, the way MIT's `process_pa_data` runs it when PA-SPAKE is the first real
/// mechanism in the hint. The inner body is the transcript body. A challenge's `K'[0]` is the
/// AS key that FAST then strengthens; a support-only round uses the long-term key, made when a
/// reply needs it. A `PREAUTH_FAILED` before a challenge response is [`SpakeFast::Next`]; a module
/// that fails before it answers, a password it could not read among the causes, is
/// [`SpakeFast::Failed`].
#[expect(
    clippy::too_many_arguments,
    reason = "the FAST retry's existing locals"
)]
fn finish_fast_spake(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    nonce: u32,
    etypes: &[i32],
    clock: &Clock,
    armor: &FastArmor,
    sub: &ProtocolKey,
    akey: &ProtocolKey,
    err: &KrbError,
    mut cookie: Option<PaData>,
    pw: &mut PasswordCell<'_, '_>,
) -> Result<SpakeFast, Error> {
    let mut spake = super::spake::FastSpake::begin(req, etypes, err)?;
    let mut current = err.clone();
    let mut sent = false;
    // The error that started a round past the first, whose padata the trace shows first.
    let mut again: Option<i32> = None;
    for _ in 0..4 {
        let listed = method_from_error(&current)?;
        trace_round(again, req, &listed, etypes);
        if again.is_some() {
            ask_responder(req, pw, None, &allowed_padata(req, &listed))?;
        }
        let bound = request_times(req, clock);
        let mut req2 = build_as_req_from(req, nonce, &bound, None, etypes)?;
        let body_der = encode(&req2.0.req_body)?;
        let (module_pa, as_key) = match spake.round(req, keys, etypes, &current, &body_der, pw)? {
            FastRound::Send(module_pa, as_key) => (module_pa, as_key),
            FastRound::Failed(fail) => {
                return Ok(SpakeFast::Failed {
                    fail,
                    new_walk: sent,
                });
            }
        };
        let answered = spake.answered();
        let mut inner_pa = Vec::new();
        if let Some(c) = cookie.clone() {
            inner_pa.push(c);
        }
        inner_pa.push(module_pa);
        trace::preauth_output(&inner_pa);
        let ap = fast_armor_ap(armor, sub)?;
        attach_fast(&mut req2, &ap, akey, inner_pa)?;
        trace::fast_encode();
        let wire = encode(&req2)?;
        sent = true;
        match send_as(req, &wire)? {
            KdcMsg::AsRep(rep) => {
                // MIT `decrypt_as_reply` (`lib/krb5/krb/get_in_tkt.c:115-123`): a reply to the
                // support message alone is decrypted under the long-term key, got now.
                let client_key = match as_key {
                    Some(k) => k,
                    None => spake.long_term_key(keys, pw)?,
                };
                return Ok(SpakeFast::Done(Box::new(finish_fast_as(
                    req,
                    keys,
                    nonce,
                    etypes,
                    akey,
                    ReplyKey::Preauth(client_key, pa::SPAKE),
                    rep,
                    &wire,
                    &bound,
                )?)));
            }
            KdcMsg::Error(e) => {
                let mat = fast_error_material(akey, &e, nonce)?;
                let code = mat.err.error_code;
                if mat.retry && code == err::PREAUTH_FAILED && !answered {
                    clock.note(&mat.err, true);
                    return Ok(SpakeFast::Next {
                        err: Box::new(mat.err),
                        cookie: mat.cookie,
                    });
                }
                if !mat.retry
                    || (code != err::PREAUTH_REQUIRED && code != err::MORE_PREAUTH_DATA_REQUIRED)
                {
                    return Err(kdc_error(&mat.err));
                }
                clock.note(&mat.err, true);
                cookie = mat.cookie;
                again = Some(code);
                current = mat.err;
            }
            KdcMsg::TgsRep => return Err(Error::UnexpectedPdu),
        }
    }
    Err(Error::ReplyMismatch(
        "Generic preauthentication failure".into(),
    ))
}

/// Where the key a FAST reply is decrypted under comes from.
enum ReplyKey<'a, 'p, 'g> {
    /// A preauth module's AS key and the pa-type of the module.
    Preauth(ProtocolKey, i32),
    /// No module answered: `gak_fct` makes it, from the password.
    Gak(&'a mut PasswordCell<'p, 'g>),
}

/// MIT `krb5int_fast_process_response` (`fast.c:548-556`): once the finished checksum holds, the
/// reply client is the finished client. The outer client name and padata are unauthenticated and
/// are not consulted again after that replacement.
/// MIT `krb5int_fast_reply_key` (`lib/krb5/krb/fast.c:570-592`): the strengthened reply key is
/// traced after the key it strengthens.
/// `preauth` is the AS key the request's preauth used and its mechanism; after encrypted
/// challenge the KDC's challenge in the reply is decrypted, and the AS key stays the reply key.
#[expect(clippy::too_many_arguments, reason = "client AS, not a params struct")]
fn finish_fast_as(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    nonce: u32,
    etypes: &[i32],
    akey: &ProtocolKey,
    reply_key: ReplyKey<'_, '_, '_>,
    mut rep: AsRep,
    wire: &[u8],
    bound: &AsReqTimes,
) -> Result<AsOutcome, Error> {
    trace::fast_decode();
    let fast = unwrap_fast_rep_checked(akey, &rep.0.padata, nonce)?;
    let ec = match &reply_key {
        ReplyKey::Preauth(k, pa::ENCRYPTED_CHALLENGE) => reply_code(&fast.padata, akey, k),
        _ => None,
    };
    trace_reply_padata(
        Some(&fast.padata),
        etypes,
        ec.map(|code| (EC_MODULE, pa::ENCRYPTED_CHALLENGE, code)),
    );
    let pa_type = match &reply_key {
        ReplyKey::Preauth(_, mech) => Some(*mech),
        ReplyKey::Gak(_) => None,
    };
    let client_key = match reply_key {
        ReplyKey::Preauth(k, _) => {
            trace::init_creds_as_key_preauth((&k).into());
            k
        }
        ReplyKey::Gak(pw) => fast_base_key(req, keys, etypes, &fast, rep.0.enc_part.etype, pw)?,
    };
    let reply_key = match &fast.strengthen_key {
        Some(sk) => {
            let k = apply_strengthen(sk, &client_key)?;
            trace::fast_reply_key((&k).into());
            k
        }
        None => client_key,
    };
    let finished = fast.finished.as_ref().ok_or_else(|| {
        Error::ReplyMismatch("FAST response missing finish message in KDC reply".into())
    })?;
    verify_fast_finished(akey, &rep.0.ticket, finished)?;
    // MIT `krb5int_fast_process_response` (`fast.c:548-558`): once the
    // finished checksum holds, the reply's client *is* the finished message's
    // client and the reply padata is the FAST-inner list — the outer cname /
    // crealm / padata are unauthenticated and never looked at again.
    // MIT `verify_as_reply` (`get_in_tkt.c:236-241`): compares the replaced client.
    rep.0.crealm = finished.crealm.clone();
    rep.0.cname = finished.cname.clone();
    rep.0.padata = Some(fast.padata.clone());
    finish_as_rep(
        rep,
        nonce,
        Some(reply_key),
        req.password,
        &req.cname,
        req.realm,
        pa_type,
        req.canonicalize,
        &req_sname(req),
        bound,
        // MIT verifies the enc-pa-rep checksum under FAST too, over the
        // outer request with the (strengthened) reply key.
        Some(wire),
        true,
    )
}

/// The first real clpreauth mechanism in the KDC's list that this client will run under armor.
///
/// MIT `process_pa_data` (`lib/krb5/krb/preauth2.c:648-728`): a real mechanism runs only for a
/// type in the KDC's list, the first that a loaded module serves, in that list's order. SPAKE
/// comes before encrypted challenge when the hint lists it first (live `kinit -T` with
/// `disable = encrypted_timestamp`). Encrypted timestamp runs only when the list offers it.
/// MIT `enc_ts_get` (`kdc/kdc_preauth_encts.c:37-41`): the KDC withholds encrypted timestamp from
/// an armored request. A type whose module `[plugins] clpreauth` did not leave loaded is skipped.
///
/// # Errors
///
/// [`Error::ReplyMismatch`] "Generic preauthentication failure" (MIT `KRB5_PREAUTH_FAILED`) when
/// the list offers none of those loaded modules.
pub(super) fn fast_mechanism(method: &[PaData], skip: &[i32]) -> Result<i32, Error> {
    method
        .iter()
        .map(|p| p.padata_type)
        .find(|&t| {
            !skip.contains(&t)
                && matches!(
                    crate::clpreauth::owner_of(t),
                    Some(
                        crate::clpreauth::Owner::Spake
                            | crate::clpreauth::Owner::EncChallenge
                            | crate::clpreauth::Owner::EncTs
                            | crate::clpreauth::Owner::Otp
                    )
                )
        })
        .ok_or_else(|| Error::ReplyMismatch("Generic preauthentication failure".into()))
}

/// MIT `decrypt_as_reply` (`lib/krb5/krb/get_in_tkt.c:47-136`): with no key from preauth, the
/// reply key is got for the FAST reply's etype-info, and traced with its salt.
fn fast_base_key(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    etypes: &[i32],
    fast: &krb5_types::fast::KrbFastResponse,
    enc_etype: i32,
    pw: &mut PasswordCell<'_, '_>,
) -> Result<ProtocolKey, Error> {
    let default_salt = salt_cname(&req.cname).default_salt(req.realm);
    let material = fast.padata.iter().find_map(|p| {
        if p.padata_type != pa::ETYPE_INFO2 {
            return None;
        }
        let info: EtypeInfo2 = decode(p.padata_value.as_ref()).ok()?;
        pick_info2(&info, &default_salt, etypes)
    });
    let (etype, salt, params) = if let Some(m) = material {
        m
    } else {
        trace::init_creds_salt_princ(&default_salt);
        (
            EncryptionType::known(enc_etype).unwrap_or_else(|_| first_etype(etypes)),
            default_salt,
            None,
        )
    };
    // MIT `decrypt_as_reply` (`lib/krb5/krb/get_in_tkt.c:96-117`): the responder is asked before the key is got, and the key is got after the salt is traced.
    ask_gak_question(pw)?;
    trace::init_creds_gak(&salt, params.as_deref().unwrap_or_default());
    trace_keytab_gak(req, keys, pw.unreadable_keytab(), etype);
    let key = if let Some(key) = pick_key(keys, Some(etype)) {
        key
    } else {
        let password = pw.get().map_err(ModuleFail::unwrapped)?;
        string_to_key(etype, &password, &salt, params.as_deref())?
    };
    if gak_found(keys, &key, etype) {
        trace::init_creds_as_key_gak((&key).into());
    }
    Ok(key)
}

fn fast_armor_ap(armor: &FastArmor, sub: &ProtocolKey) -> Result<krb5_types::ApReq, Error> {
    build_fast_armor(
        armor.ticket.clone(),
        &armor.session,
        &armor.crealm,
        &armor.cname,
        Some(sub),
    )
}

/// What MIT `krb5int_fast_process_error` hands back for a KRB-ERROR received under an armor key.
/// MIT `krb5int_fast_process_error` (`fast.c:428-511`): hands back the error to act on, the FAST
/// padata and the retry flag for a KRB-ERROR received under an armor key.
pub(crate) struct FastErrorMaterial {
    /// The error to act on: the FX-ERROR inner error when the FAST envelope
    /// unwrapped, else the outer error as received.
    pub(crate) err: KrbError,
    /// FX-COOKIE from the *decrypted* FAST response padata only.
    pub(crate) cookie: Option<PaData>,
    /// MIT `*retry`: the inner padata carries more than the FX-ERROR and a
    /// cookie. False for every outer-error outcome — the client stops.
    pub(crate) retry: bool,
}

/// MIT `krb5int_fast_process_error` (`fast.c:445-495`): with an armor key, the e_data must
/// decode as a padata sequence whose PA-FX-FAST decrypts under the armor key with the request
/// nonce; when it does not ("the KDC does not understand FAST" — or a man in the middle stripped
/// it) the outer error is the fatal answer with `retry = 0` and nothing from it is trusted (no
/// cookie, no method data). A decrypted response without FX-ERROR is
/// `KRB5KDC_ERR_PREAUTH_FAILED` "Expecting FX_ERROR pa-data inside FAST container". Otherwise
/// the inner error replaces the outer one, the inner padata is the method data, and `retry` is
/// set only when that list has more than the FX-ERROR entry and includes an FX-COOKIE.
///
/// The inner error's `e_data` is filled with the inner padata when it is
/// empty so `method_from_error` / `select_s2k` read the protected hints.
///
/// # Errors
///
/// [`Error::KrbError`] `PREAUTH_FAILED` when the decrypted FAST response has no FX-ERROR, and
/// [`Error::Asn1`] when that FX-ERROR does not decode or the inner padata does not re-encode.
pub(crate) fn fast_error_material(
    akey: &ProtocolKey,
    err: &KrbError,
    nonce: u32,
) -> Result<FastErrorMaterial, Error> {
    let outer_fatal = || {
        Ok(FastErrorMaterial {
            err: err.clone(),
            cookie: None,
            retry: false,
        })
    };
    let Some(ed) = &err.e_data else {
        return outer_fatal();
    };
    let Ok(method) = decode::<MethodData>(ed.as_ref()) else {
        return outer_fatal();
    };
    // MIT `decrypt_fast_reply` (`lib/krb5/krb/fast.c:359-415`): traced once the e-data is a padata
    // sequence, before PA-FX-FAST is looked for.
    trace::fast_decode();
    let Some(fx) = find_pa(&method, pa::FX_FAST) else {
        return outer_fatal();
    };
    let Ok(fast) = unwrap_fast_rep_checked(akey, &Some(vec![fx.clone()]), nonce) else {
        return outer_fatal();
    };
    let types: Vec<i32> = fast.padata.iter().map(|p| p.padata_type).collect();
    tracing::info!(
        event = krb5_log::events::CLIENT_FAST,
        component = "krb5-protocol",
        outcome = "ok",
        inner_padata = ?types,
    );
    let Some(fx_err) = find_pa(&fast.padata, pa::FX_ERROR) else {
        return Err(Error::KrbError {
            code: err::PREAUTH_FAILED,
            text: Some("Expecting FX_ERROR pa-data inside FAST container".into()),
        });
    };
    let mut inner: KrbError = decode(fx_err.padata_value.as_ref())?;
    if inner.e_data.is_none() {
        inner.e_data = Some(encode(&fast.padata)?.into());
    }
    let cookie = find_pa(&fast.padata, pa::FX_COOKIE).cloned();
    let retry = fast.padata.len() > 1 && cookie.is_some();
    Ok(FastErrorMaterial {
        err: inner,
        cookie,
        retry,
    })
}

#[cfg(test)]
mod tests {
    use super::fast_mechanism;
    use krb5_types::{PaData, pa};

    fn pa_of(padata_type: i32) -> PaData {
        PaData {
            padata_type,
            padata_value: Vec::<u8>::new().into(),
        }
    }

    fn pin(extra: &str) {
        krb5_config::isolate_test_krb5();
        let dir = krb5_testkit::scratch_dir("pg3-fast-mech");
        let path = dir.join("krb5.conf");
        std::fs::write(
            &path,
            format!(
                "[libdefaults]\n    default_realm = KERBER.TEST\n    dns_lookup_kdc = false\n    dns_lookup_realm = false\n{extra}"
            ),
        )
        .unwrap();
        krb5_config::set_test_krb5_paths(Some(vec![path]));
    }

    #[test]
    fn disable_encrypted_timestamp_leaves_encrypted_challenge() {
        pin("[plugins]\n    clpreauth = {\n        disable = encrypted_timestamp\n    }\n");
        let method = vec![pa_of(pa::ENC_TIMESTAMP), pa_of(pa::ENCRYPTED_CHALLENGE)];
        assert_eq!(
            fast_mechanism(&method, &[]).unwrap(),
            pa::ENCRYPTED_CHALLENGE
        );
        let only_ts = vec![pa_of(pa::ENC_TIMESTAMP)];
        let err = fast_mechanism(&only_ts, &[]).unwrap_err();
        assert!(
            err.to_string()
                .contains("Generic preauthentication failure"),
            "a disabled encrypted_timestamp is not a FAST mechanism, got {err}"
        );
    }

    #[test]
    fn a_loaded_encrypted_timestamp_is_still_chosen_first() {
        pin("");
        let method = vec![pa_of(pa::ENC_TIMESTAMP), pa_of(pa::ENCRYPTED_CHALLENGE)];
        assert_eq!(fast_mechanism(&method, &[]).unwrap(), pa::ENC_TIMESTAMP);
    }

    #[test]
    fn spake_listed_before_encrypted_challenge_is_the_fast_mechanism() {
        pin("");
        let method = vec![
            pa_of(pa::FX_FAST),
            pa_of(pa::SPAKE),
            pa_of(pa::ENCRYPTED_CHALLENGE),
        ];
        assert_eq!(fast_mechanism(&method, &[]).unwrap(), pa::SPAKE);
    }

    #[test]
    fn a_disabled_spake_lets_encrypted_challenge_run_under_armor() {
        pin("[plugins]\n    clpreauth = {\n        disable = spake\n    }\n");
        let method = vec![pa_of(pa::SPAKE), pa_of(pa::ENCRYPTED_CHALLENGE)];
        assert_eq!(
            fast_mechanism(&method, &[]).unwrap(),
            pa::ENCRYPTED_CHALLENGE
        );
    }

    #[test]
    fn a_failed_spake_is_not_chosen_again() {
        pin("");
        let method = vec![pa_of(pa::SPAKE), pa_of(pa::ENCRYPTED_CHALLENGE)];
        assert_eq!(
            super::fast_mechanism(&method, &[pa::SPAKE]).unwrap(),
            pa::ENCRYPTED_CHALLENGE
        );
    }
}
