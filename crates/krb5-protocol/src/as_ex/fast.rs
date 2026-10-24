//! RFC 6113 FAST armor on the AS exchange.

use krb5_config::Krb5Conf;

use super::clock::Clock;
use super::ec::{EC_MODULE, client_challenge, reply_code};
use super::otp::{self, OTP_MODULE, OtpState};
use super::password::{ModuleFail, PasswordCell};
use super::responder::{QUESTION_PASSWORD, ResponderItems};
use super::spake::{FastRound, trace_round};
use super::{
    AsOutcome, AsPrompt, AsReqTimes, AsRequest, ENCTS_MODULE, KdcMsg, Pkinit, PkinitClient,
    allowed_padata, build_as_req_from, classify_kdc_error, encrypted_timestamp_disabled,
    fallback_s2k, find_pa, finish_as_rep, first_etype, gak_found, kdc_error, learned_s2k,
    long_term_as_key, method_from_error, pa_enc_timestamp_at, pick_info2, pick_key, req_sname,
    request_times, salt_cname, select_s2k, send_as, sort_krb5_padata_sequence, trace_keytab_gak,
    trace_preauth_input, trace_reply_padata,
};
use crate::error::Error;
use crate::keytab::KeytabFailure;
use crate::preauth::{
    apply_strengthen, armor_key, attach_fast, pkinit_reply_key_agile, unwrap_fast_rep_checked,
    verify_fast_finished,
};
use crate::trace;
use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
use krb5_types::k5json::{self, Value};
use krb5_types::pkinit::{KxGroup, KxKey};
use krb5_types::{AsRep, EtypeInfo2, KrbError, MethodData, PaData, PrincipalName, err, pa};

pub struct FastArmor {
    pub ticket: krb5_types::Ticket,
    pub session: ProtocolKey,
    pub crealm: krb5_types::Realm,
    pub cname: PrincipalName,
}

// MIT: `fast_armor_ap_request` (lib/krb5/krb/fast.c:52-108)
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
    let (sub, akey, ap) = armor_ap_request(armor, Some(req.profile))?;
    let mut probe = build_as_req_from(req, nonce, bound, None, etypes)?;
    trace::init_creds_preauth_none();
    attach_fast(&mut probe, &ap, &akey, Vec::new())?;
    trace::fast_encode();
    let wire = encode(&probe)?;
    match send_as(req, &wire)? {
        KdcMsg::AsRep(rep) => {
            // MIT: `decrypt_as_reply` (lib/krb5/krb/get_in_tkt.c:96-123)
            // no module answered, so the reply key is got now, from the password.
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
            if !retry || inner.error_code != err::PREAUTH_REQUIRED {
                return classify_kdc_error(&inner);
            }
            clock.note(&inner, true);
            // MIT: `get_as_key` (lib/krb5/krb/preauth2.c:438-457)
            // The password is read when a mechanism first needs the key; OTP never needs it.
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
            let mut first_failure: Option<Error> = None;
            let mut current = inner;
            let mut cookie_slot = cookie;
            let mut skip: Vec<i32> = Vec::new();
            let mut saved_method: Vec<PaData> = Vec::new();
            let mut last_fail: Option<KrbError> = None;
            let pkinit = req.pkinit.is_some();
            let mut prepared = false;
            'rounds: loop {
                let mut method = sort_krb5_padata_sequence(
                    &method_from_error(&current).unwrap_or_default(),
                    &super::conf_preferred_preauth_types_for(req.profile, req.realm),
                );
                // MIT: `pa_type_allowed` (lib/krb5/krb/preauth2.c:627-631)
                // a type the input cache does not allow is not tried.
                method.retain(|p| req.ticket.preauth_allowed(p.padata_type));
                if fast_mechanism(req.profile, &method, &skip, pkinit).is_err()
                    && !saved_method.is_empty()
                {
                    method.clone_from(&saved_method);
                }
                if trace::enabled() {
                    trace::init_creds_preauth();
                    trace_preauth_input(&method, etypes);
                }
                // MIT: `k5_preauth` (lib/krb5/krb/preauth2.c:1004-1016)
                // Modules with padata prepare, and the responder answers, before one is chosen.
                super::pkinit_prepare(req, &method, &mut prepared);
                let items = ask_responder(
                    req,
                    &mut pw,
                    Some((&mut otp_state, cc_in.as_ref())),
                    &method,
                )?;
                loop {
                    let mech = match fast_mechanism(req.profile, &method, &skip, pkinit) {
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
                        pa::PK_AS_REQ => match req.pkinit {
                            Some(Pkinit::Failed(f)) => (super::pkinit_fails(f), false),
                            Some(Pkinit::Client(pk)) => {
                                return finish_fast_pkinit(
                                    req,
                                    keys,
                                    &mut pw,
                                    nonce,
                                    etypes,
                                    clock,
                                    armor,
                                    &sub,
                                    &akey,
                                    &current,
                                    cookie_slot.as_ref(),
                                    pk,
                                );
                            }
                            None => {
                                return Err(Error::preauth_no_mech());
                            }
                        },
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
                                        learned_s2k(
                                            &current,
                                            &salt_cname(&req.cname),
                                            req.realm,
                                            etypes,
                                        ),
                                        &mut pw,
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

// MIT: `encts_process` (lib/krb5/krb/preauth_encts.c:75-77)
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
    if mech == pa::ENC_TIMESTAMP && encrypted_timestamp_disabled(req.profile, req.realm) {
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
    let mut inner_pa = Vec::new();
    if let Some(c) = cookie {
        inner_pa.push(c.clone());
    }
    if mech == pa::ENCRYPTED_CHALLENGE {
        let (now, usec) = clock.now(false);
        // A des3 key MIT refuses fails the challenge with that key's code.
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
        // A des3 key MIT refuses fails the timestamp with that key's code.
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
    let ap = fast_armor_ap(armor, sub, Some(req.profile))?;
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
            ReplyKey::Preauth(
                client_key,
                mech,
                learned_s2k(current, &salt_cname(&req.cname), req.realm, etypes),
                pw,
            ),
            rep,
            &wire,
            bound,
        ),
        KdcMsg::Error(e) => classify_kdc_error(&fast_error_material(akey, &e, nonce)?.err),
        KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
    }
    .map(Ok)
}

pub(super) fn ask_responder(
    req: &AsRequest<'_>,
    pw: &mut PasswordCell<'_, '_>,
    otp: Option<(&mut OtpState, Option<&Value>)>,
    method: &[PaData],
) -> Result<ResponderItems, Error> {
    let mut items = ResponderItems::default();
    fill_response_items(
        req.profile,
        &mut items,
        otp,
        method,
        pw.asks_question(),
        encrypted_timestamp_disabled(req.profile, req.realm),
    )?;
    call_responder(pw, &mut items)?;
    Ok(items)
}

fn call_responder(pw: &mut PasswordCell<'_, '_>, items: &mut ResponderItems) -> Result<(), Error> {
    if !items.is_empty()
        && let Some(r) = pw.responder()
    {
        r.respond(items)?;
    }
    pw.offer(items.get_answer(QUESTION_PASSWORD));
    Ok(())
}

// MIT: `krb5_get_as_key_password` (lib/krb5/krb/gic_pwd.c:30-38)
/// the question is asked only while no password is held.
pub(super) fn ask_gak_question(pw: &mut PasswordCell<'_, '_>) -> Result<(), Error> {
    let mut items = ResponderItems::default();
    if pw.asks_question() {
        items.ask_question(QUESTION_PASSWORD, Some(b"".as_slice()));
    }
    call_responder(pw, &mut items)
}

// MIT: `fill_response_items` (lib/krb5/krb/preauth2.c:937-965)
// MIT: `ec_prep_questions` (lib/krb5/krb/preauth_ec.c:36-45)
// MIT: `encts_prep_questions` (lib/krb5/krb/preauth_encts.c:33-47)
/// encrypted timestamp asks it too, unless the realm disables it.
// MIT: `spake_prep_questions` (plugins/preauth/spake/spake_client.c:119-141)
/// SPAKE asks it for a challenge it can answer, and for nothing else.
fn fill_response_items(
    profile: &Krb5Conf,
    items: &mut ResponderItems,
    mut otp: Option<(&mut OtpState, Option<&Value>)>,
    method: &[PaData],
    ask_password: bool,
    encts_off: bool,
) -> Result<(), Error> {
    let otp_on = crate::clpreauth::loaded(profile, OTP_MODULE);
    let ec_on = ask_password && crate::clpreauth::loaded(profile, EC_MODULE);
    let encts_on = ask_password && !encts_off && crate::clpreauth::loaded(profile, ENCTS_MODULE);
    let spake_on = ask_password && crate::clpreauth::loaded(profile, "spake");
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
            pa::SPAKE
                if spake_on && super::spake::prep_needs_key(profile, p.padata_value.as_ref()) =>
            {
                items.ask_question(QUESTION_PASSWORD, Some(b"".as_slice()));
            }
            _ => {}
        }
    }
    Ok(())
}

// MIT: `otp_client_process` (lib/krb5/krb/preauth_otp.c:1118-1127)
/// `set_as_key(armor key)`, then `disable_fallback`.
// MIT: `init_creds_step_request` (lib/krb5/krb/get_in_tkt.c:1334-1336)
/// with fallback disabled a failed request is the error returned.
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
    learned: Option<super::LearnedSalt>,
    pw: &mut PasswordCell<'_, '_>,
) -> Result<AsOutcome, Error> {
    let mut inner_pa = Vec::new();
    if let Some(c) = cookie {
        inner_pa.push(c);
    }
    inner_pa.push(pa142);
    trace::preauth_process(OTP_MODULE, pa::OTP_CHALLENGE, true, 0, None);
    trace::preauth_output(&inner_pa);
    let ap = fast_armor_ap(armor, sub, Some(req.profile))?;
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
                ReplyKey::Preauth(akey.clone(), pa::OTP_CHALLENGE, learned, pw),
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

enum SpakeFast {
    Done(Box<AsOutcome>),
    Next {
        err: Box<KrbError>,
        cookie: Option<PaData>,
    },
    // MIT: `process_pa_data` (lib/krb5/krb/preauth2.c:699-723)
    // MIT: `init_creds_step_request` (lib/krb5/krb/get_in_tkt.c:1343-1348)
    Failed {
        fail: ModuleFail,
        new_walk: bool,
    },
}

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
        let ap = fast_armor_ap(armor, sub, Some(req.profile))?;
        attach_fast(&mut req2, &ap, akey, inner_pa)?;
        trace::fast_encode();
        let wire = encode(&req2)?;
        sent = true;
        match send_as(req, &wire)? {
            KdcMsg::AsRep(rep) => {
                let learned = spake.learned();
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
                    ReplyKey::Preauth(client_key, pa::SPAKE, learned, pw),
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
    Err(Error::preauth_no_mech())
}

enum ReplyKey<'a, 'p, 'g> {
    Preauth(
        ProtocolKey,
        i32,
        Option<super::LearnedSalt>,
        &'a mut PasswordCell<'p, 'g>,
    ),
    Gak(&'a mut PasswordCell<'p, 'g>),
    Pkinit(
        &'a KxKey,
        &'a PkinitClient,
        Option<super::LearnedSalt>,
        &'a mut PasswordCell<'p, 'g>,
    ),
}

#[expect(
    clippy::too_many_arguments,
    reason = "the FAST retry's existing locals"
)]
fn finish_fast_pkinit(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    pw: &mut PasswordCell<'_, '_>,
    nonce: u32,
    etypes: &[i32],
    clock: &Clock,
    armor: &FastArmor,
    sub: &ProtocolKey,
    akey: &ProtocolKey,
    current: &KrbError,
    cookie: Option<&PaData>,
    pk: &PkinitClient,
) -> Result<AsOutcome, Error> {
    let mut dh_size = pk.dh_size();
    let method = method_from_error(current).unwrap_or_default();
    let token = find_pa(&method, pa::AS_FRESHNESS)
        .map(|p| p.padata_value.as_ref())
        .filter(|v| !v.is_empty());
    let mut nonce = nonce;
    let mut tryagain: Option<super::Retry> = None;
    for _ in 1..super::MAX_IN_TKT_LOOPS {
        let group = KxGroup::for_bits(dh_size).unwrap_or(KxGroup::Modp2048);
        let bound = &request_times(req, clock);
        let mut req2 = build_as_req_from(req, nonce, bound, None, etypes)?;
        let mut inner_pa: Vec<PaData> = match &tryagain {
            None => cookie.into_iter().cloned().collect(),
            Some(_) => Vec::new(),
        };
        trace::pkinit_dh_proposing_group(group.desc());
        let kp =
            KxKey::generate(group).ok_or_else(|| Error::Crypto("PKINIT key exchange".into()))?;
        inner_pa.push(super::pkinit_padata(
            req,
            pk,
            &kp,
            nonce,
            &req2.0.req_body,
            token,
            clock,
        )?);
        if let Some(super::Retry(cookie)) = &tryagain {
            inner_pa.extend(cookie.iter().cloned());
            trace::preauth_tryagain(super::PKINIT_MODULE, pa::PK_AS_REQ, 0, None);
            trace::preauth_tryagain_output(&inner_pa);
        } else {
            trace::preauth_process(super::PKINIT_MODULE, pa::PK_AS_REQ, true, 0, None);
            trace::preauth_output(&inner_pa);
        }
        let ap = fast_armor_ap(armor, sub, Some(req.profile))?;
        attach_fast(&mut req2, &ap, akey, inner_pa)?;
        trace::fast_encode();
        let wire = encode(&req2)?;
        match send_as(req, &wire)? {
            KdcMsg::AsRep(rep) => {
                let learned = learned_s2k(current, &salt_cname(&req.cname), req.realm, etypes);
                return finish_fast_as(
                    req,
                    keys,
                    nonce,
                    etypes,
                    akey,
                    ReplyKey::Pkinit(&kp, pk, learned, pw),
                    rep,
                    &wire,
                    bound,
                );
            }
            KdcMsg::Error(e) => {
                let mat = fast_error_material(akey, &e, nonce)?;
                let tried = !matches!(
                    mat.err.error_code,
                    err::PREAUTH_REQUIRED | err::PREAUTH_FAILED | err::MORE_PREAUTH_DATA_REQUIRED
                );
                match (mat.retry && tried)
                    .then(|| super::pkinit_tryagain(&mat.err, &mut dh_size))
                    .flatten()
                {
                    Some(retry) => {
                        tryagain = Some(retry);
                        nonce = super::random_nonce()?;
                    }
                    None => return classify_kdc_error(&mat.err),
                }
            }
            KdcMsg::TgsRep => return Err(Error::UnexpectedPdu),
        }
    }
    Err(Error::Message(
        "Looping detected inside krb5_get_in_tkt".into(),
    ))
}

// MIT: `krb5int_fast_process_response` (fast.c:548-556)
/// Once the finished checksum holds, the reply client is the finished client.
// MIT: `krb5int_fast_reply_key` (lib/krb5/krb/fast.c:570-592)
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
    let module = match &reply_key {
        ReplyKey::Preauth(k, pa::ENCRYPTED_CHALLENGE, _, _) => {
            reply_code(&fast.padata, akey, k).map(|code| (EC_MODULE, pa::ENCRYPTED_CHALLENGE, code))
        }
        _ => None,
    };
    if matches!(reply_key, ReplyKey::Pkinit(..)) {
        trace_preauth_input(&fast.padata, etypes);
    } else {
        trace_reply_padata(Some(&fast.padata), etypes, module);
    }
    let pa_type = match &reply_key {
        ReplyKey::Preauth(_, mech, _, _) => Some(*mech),
        ReplyKey::Pkinit(..) => Some(pa::PK_AS_REQ),
        ReplyKey::Gak(_) => None,
    };
    let (client_key, held) = match reply_key {
        ReplyKey::Preauth(k, _, learned, pw) => {
            trace::init_creds_as_key_preauth((&k).into());
            (k, Some((learned, pw)))
        }
        ReplyKey::Pkinit(kp, pk, learned, pw) => match pkinit_reply_key_agile(
            kp,
            &Some(fast.padata.clone()),
            EncryptionType::known(rep.0.enc_part.etype)?,
            pk.trust(),
            wire,
            &req.cname,
            req.realm,
        ) {
            Ok(k) => {
                if fast.padata.iter().any(|p| p.padata_type == pa::PK_AS_REP) {
                    trace::preauth_process(super::PKINIT_MODULE, pa::PK_AS_REP, true, 0, None);
                }
                trace::preauth_output(&[]);
                trace::init_creds_as_key_preauth((&k).into());
                (k, Some((learned, pw)))
            }
            Err(Error::PkinitReply { code, text }) => {
                super::ModuleFail::new(code, &text).trace(super::PKINIT_MODULE, pa::PK_AS_REP);
                trace::preauth_output(&[]);
                (
                    fast_base_key(req, keys, etypes, &fast, rep.0.enc_part.etype, pw)?,
                    None,
                )
            }
            Err(e) => return Err(e),
        },
        ReplyKey::Gak(pw) => (
            fast_base_key(req, keys, etypes, &fast, rep.0.enc_part.etype, pw)?,
            None,
        ),
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
    // The outer cname, crealm and padata are unauthenticated and are not read again.
    // MIT: `verify_as_reply` (get_in_tkt.c:236-241)
    // compares the replaced client.
    rep.0.crealm = finished.crealm.clone();
    rep.0.cname = finished.cname.clone();
    rep.0.padata = Some(fast.padata.clone());
    if let Some((learned, pw)) = held {
        let (salt, params) = fallback_s2k(
            rep.0.padata.as_deref(),
            etypes,
            learned,
            &rep.0.cname,
            &rep.0.crealm,
        );
        let mut fallback = |et: EncryptionType| {
            let base = long_term_as_key(req, keys, pw, et, &salt, params.as_deref())?;
            match &fast.strengthen_key {
                Some(sk) => {
                    let k = apply_strengthen(sk, &base)?;
                    trace::fast_reply_key((&k).into());
                    Ok(k)
                }
                None => Ok(base),
            }
        };
        finish_as_rep(
            req.profile,
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
            Some(wire),
            true,
            Some(&mut fallback),
        )
    } else {
        finish_as_rep(
            req.profile,
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
            Some(wire),
            true,
            None,
        )
    }
}

// MIT: `enc_ts_get` (kdc/kdc_preauth_encts.c:37-41)
/// The KDC withholds encrypted timestamp from an armored request.
pub(super) fn fast_mechanism(
    profile: &Krb5Conf,
    method: &[PaData],
    skip: &[i32],
    pkinit: bool,
) -> Result<i32, Error> {
    method
        .iter()
        .map(|p| p.padata_type)
        .find(|&t| {
            !skip.contains(&t)
                && match crate::clpreauth::owner_of(profile, t) {
                    Some(crate::clpreauth::Owner::Pkinit) => pkinit,
                    Some(
                        crate::clpreauth::Owner::Spake
                        | crate::clpreauth::Owner::EncChallenge
                        | crate::clpreauth::Owner::EncTs
                        | crate::clpreauth::Owner::Otp,
                    ) => true,
                    _ => false,
                }
        })
        .ok_or(Error::preauth_no_mech())
}

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

fn armor_ap_request(
    armor: &FastArmor,
    profile: Option<&krb5_config::Krb5Conf>,
) -> Result<(ProtocolKey, ProtocolKey, krb5_types::ApReq), Error> {
    let sub = ProtocolKey::random(armor.session.etype())?;
    let akey = armor_key(&armor.session, Some(&sub))?;
    let ap = fast_armor_ap(armor, &sub, profile)?;
    trace::fast_armor_ccache_key((&armor.session).into());
    trace::mk_req(
        trace::Princ::new(&armor.cname, armor.crealm.as_bytes()),
        trace::Princ::new(&armor.ticket.sname, armor.ticket.realm.as_bytes()),
        0,
        Some((&sub).into()),
        (&armor.session).into(),
    );
    trace::fast_armor_key((&akey).into());
    Ok((sub, akey, ap))
}

// MIT: `krb5_init_creds_set_service` (lib/krb5/krb/get_in_tkt.c:1057-1072)
pub fn set_service_restart(armor: &FastArmor) -> Result<(), Error> {
    armor_ap_request(armor, None).map(|_| ())
}

fn fast_armor_ap(
    armor: &FastArmor,
    sub: &ProtocolKey,
    profile: Option<&krb5_config::Krb5Conf>,
) -> Result<krb5_types::ApReq, Error> {
    crate::preauth::build_fast_armor_profile(
        armor.ticket.clone(),
        &armor.session,
        &armor.crealm,
        &armor.cname,
        Some(sub),
        profile,
    )
}

// MIT: `krb5int_fast_process_error` (fast.c:428-511)
pub(crate) struct FastErrorMaterial {
    pub(crate) err: KrbError,
    /// FX-COOKIE comes from the decrypted FAST padata only.
    pub(crate) cookie: Option<PaData>,
    /// retry is false for an outer error; the client stops.
    pub(crate) retry: bool,
}

/// A missing FX-ERROR inside FAST is PREAUTH_FAILED.
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
    // MIT: `decrypt_fast_reply` (lib/krb5/krb/fast.c:359-415)
    // traced once the e-data is a padata sequence, before PA-FX-FAST is looked for.
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

    fn pin(extra: &str) -> krb5_config::Krb5Conf {
        krb5_config::Krb5Conf::parse(&format!(
            "[libdefaults]\n    default_realm = KERBER.TEST\n    dns_lookup_kdc = false\n    dns_lookup_realm = false\n{extra}"
        ))
        .unwrap()
    }

    #[test]
    fn disable_encrypted_timestamp_leaves_encrypted_challenge() {
        let profile =
            pin("[plugins]\n    clpreauth = {\n        disable = encrypted_timestamp\n    }\n");
        let method = vec![pa_of(pa::ENC_TIMESTAMP), pa_of(pa::ENCRYPTED_CHALLENGE)];
        assert_eq!(
            fast_mechanism(&profile, &method, &[], false).unwrap(),
            pa::ENCRYPTED_CHALLENGE
        );
        let only_ts = vec![pa_of(pa::ENC_TIMESTAMP)];
        let err = fast_mechanism(&profile, &only_ts, &[], false).unwrap_err();
        assert!(
            matches!(err, crate::error::Error::PreauthNoMech),
            "a disabled encrypted_timestamp is not a FAST mechanism, got {err}"
        );
    }

    #[test]
    fn a_loaded_encrypted_timestamp_is_still_chosen_first() {
        let profile = pin("");
        let method = vec![pa_of(pa::ENC_TIMESTAMP), pa_of(pa::ENCRYPTED_CHALLENGE)];
        assert_eq!(
            fast_mechanism(&profile, &method, &[], false).unwrap(),
            pa::ENC_TIMESTAMP
        );
    }

    #[test]
    fn spake_listed_before_encrypted_challenge_is_the_fast_mechanism() {
        let profile = pin("");
        let method = vec![
            pa_of(pa::FX_FAST),
            pa_of(pa::SPAKE),
            pa_of(pa::ENCRYPTED_CHALLENGE),
        ];
        assert_eq!(
            fast_mechanism(&profile, &method, &[], false).unwrap(),
            pa::SPAKE
        );
    }

    #[test]
    fn a_disabled_spake_lets_encrypted_challenge_run_under_armor() {
        let profile = pin("[plugins]\n    clpreauth = {\n        disable = spake\n    }\n");
        let method = vec![pa_of(pa::SPAKE), pa_of(pa::ENCRYPTED_CHALLENGE)];
        assert_eq!(
            fast_mechanism(&profile, &method, &[], false).unwrap(),
            pa::ENCRYPTED_CHALLENGE
        );
    }

    #[test]
    fn a_failed_spake_is_not_chosen_again() {
        let profile = pin("");
        let method = vec![pa_of(pa::SPAKE), pa_of(pa::ENCRYPTED_CHALLENGE)];
        assert_eq!(
            super::fast_mechanism(&profile, &method, &[pa::SPAKE], false).unwrap(),
            pa::ENCRYPTED_CHALLENGE
        );
    }
}
