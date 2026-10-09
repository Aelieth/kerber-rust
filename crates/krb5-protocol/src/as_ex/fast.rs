//! RFC 6113 FAST armor on the AS exchange (`lib/krb5/krb/fast.c`
//! `krb5int_fast_process_response` / `krb5int_fast_process_error`).

use super::clock::Clock;
use super::ec::{EC_MODULE, client_challenge, reply_code};
use super::{
    AsOutcome, AsReqTimes, AsRequest, ENCTS_MODULE, KdcMsg, PasswordPrompt, build_as_req_from,
    classify_kdc_error, find_pa, finish_as_rep, first_etype, gak_found, method_from_error,
    pa_enc_timestamp_at, pick_info2, pick_key, req_sname, request_times, salt_cname, select_s2k,
    send_as, sort_krb5_padata_sequence, trace_keytab_gak, trace_preauth_input, trace_reply_padata,
    with_prompted,
};
use crate::error::Error;
use crate::preauth::{
    apply_strengthen, armor_key, attach_fast, build_fast_armor, unwrap_fast_rep_checked,
    verify_fast_finished,
};
use crate::trace;
use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
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
pub(super) fn continue_fast(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    nonce: u32,
    bound: &AsReqTimes,
    etypes: &[i32],
    clock: &Clock,
    prompt: Option<&mut PasswordPrompt<'_>>,
) -> Result<AsOutcome, Error> {
    let armor = req
        .fast_armor
        .ok_or_else(|| Error::ReplyMismatch("FAST armor missing".into()))?;
    let mut raw = vec![0u8; armor.session.etype().key_len()];
    getrandom::getrandom(&mut raw).map_err(|e| Error::transport_msg(e.to_string()))?;
    let sub = ProtocolKey::from_bytes(armor.session.etype(), &raw)?;
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
        KdcMsg::AsRep(rep) => with_prompted(req, prompt, false, |req| {
            finish_fast_as(req, keys, nonce, etypes, &akey, None, rep, &wire, bound)
        }),
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
            with_prompted(req, prompt, true, |req| {
                // MIT `init_creds_step_reply` (`get_in_tkt.c:1731-1740`): PREAUTH_FAILED on a
                // mechanism that has not disabled fallback notes it failed and tries the next one.
                let mut current = inner;
                let mut cookie_slot = cookie;
                let mut skip: Vec<i32> = Vec::new();
                let mut saved_method: Vec<PaData> = Vec::new();
                let mut last_fail: Option<KrbError> = None;
                loop {
                    let mut method = sort_krb5_padata_sequence(
                        &method_from_error(&current).unwrap_or_default(),
                        &super::conf_preferred_preauth_types_for(req.realm),
                    );
                    if fast_mechanism(&method, &skip).is_err() && !saved_method.is_empty() {
                        method.clone_from(&saved_method);
                    }
                    if trace::enabled() {
                        trace::init_creds_preauth();
                        trace_preauth_input(&method, etypes);
                    }
                    let mech = match fast_mechanism(&method, &skip) {
                        Ok(mech) => mech,
                        Err(e) => {
                            return match last_fail {
                                Some(err) => Err(kdc_error(&err)),
                                None => Err(e),
                            };
                        }
                    };
                    saved_method = method;
                    if mech == pa::SPAKE {
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
                            cookie_slot,
                        )? {
                            SpakeFast::Done(out) => return Ok(*out),
                            SpakeFast::Next { err, cookie: next } => {
                                skip.push(pa::SPAKE);
                                last_fail = Some((*err).clone());
                                current = *err;
                                cookie_slot = next;
                                continue;
                            }
                        }
                    }
                    let (etype, salt, params) =
                        select_s2k(&current, &salt_cname(&req.cname), req.realm, etypes)?;
                    trace_keytab_gak(req, keys, etype);
                    let client_key = pick_key(keys, Some(etype)).map_or_else(
                        || string_to_key(etype, req.password, &salt, params.as_deref()),
                        Ok,
                    )?;
                    // MIT k5_preauth copies the FX-COOKIE (copy_cookie) before the
                    // preauth module's PA data, so the cookie leads the inner padata.
                    let mut inner_pa = Vec::new();
                    if let Some(c) = cookie_slot {
                        inner_pa.push(c);
                    }
                    if mech == pa::ENCRYPTED_CHALLENGE {
                        // MIT `ec_process` takes the time without an unauthenticated offset.
                        let (now, usec) = clock.now(false);
                        inner_pa.push(client_challenge(&akey, &client_key, (&now, usec))?);
                        trace::preauth_process(EC_MODULE, mech, true, 0, None);
                    } else {
                        if gak_found(keys, &client_key, etype) {
                            trace::preauth_enc_ts_key_gak((&client_key).into());
                        }
                        inner_pa.push(pa_enc_timestamp_at(&client_key, clock.now(true), true)?);
                        trace::preauth_process(ENCTS_MODULE, mech, true, 0, None);
                    }
                    trace::preauth_output(&inner_pa);
                    let ap = fast_armor_ap(armor, &sub)?;
                    let bound = &request_times(req, clock);
                    let mut req2 = build_as_req_from(req, nonce, bound, None, etypes)?;
                    attach_fast(&mut req2, &ap, &akey, inner_pa)?;
                    trace::fast_encode();
                    let wire = encode(&req2)?;
                    return match send_as(req, &wire)? {
                        KdcMsg::AsRep(rep) => finish_fast_as(
                            req,
                            keys,
                            nonce,
                            etypes,
                            &akey,
                            Some((client_key, mech)),
                            rep,
                            &wire,
                            bound,
                        ),
                        KdcMsg::Error(e) => {
                            classify_kdc_error(&fast_error_material(&akey, &e, nonce)?.err)
                        }
                        KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
                    };
                }
            })
        }
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
}

/// The KDC error, as [`classify_kdc_error`] returns it.
fn kdc_error(err: &KrbError) -> Error {
    match classify_kdc_error(err) {
        Err(e) => e,
        Ok(_) => Error::UnexpectedPdu,
    }
}

/// SPAKE inside FAST, the way MIT's `process_pa_data` runs it when PA-SPAKE is the first real
/// mechanism in the hint. The inner body is the transcript body. A challenge's `K'[0]` is the
/// AS key that FAST then strengthens; a support-only round uses the long-term key. A
/// `PREAUTH_FAILED` before a challenge response is [`SpakeFast::Next`].
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
) -> Result<SpakeFast, Error> {
    let mut spake = super::spake::FastSpake::begin(req, etypes, err)?;
    let mut current = err.clone();
    for _ in 0..4 {
        let bound = request_times(req, clock);
        let mut req2 = build_as_req_from(req, nonce, &bound, None, etypes)?;
        let body_der = encode(&req2.0.req_body)?;
        let (module_pa, client_key) = spake.round(req, keys, etypes, &current, &body_der)?;
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
        match send_as(req, &wire)? {
            KdcMsg::AsRep(rep) => {
                return Ok(SpakeFast::Done(Box::new(finish_fast_as(
                    req,
                    keys,
                    nonce,
                    etypes,
                    akey,
                    Some((client_key, pa::SPAKE)),
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
                current = mat.err;
            }
            KdcMsg::TgsRep => return Err(Error::UnexpectedPdu),
        }
    }
    Err(Error::ReplyMismatch(
        "Generic preauthentication failure".into(),
    ))
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
    preauth: Option<(ProtocolKey, i32)>,
    mut rep: AsRep,
    wire: &[u8],
    bound: &AsReqTimes,
) -> Result<AsOutcome, Error> {
    trace::fast_decode();
    let fast = unwrap_fast_rep_checked(akey, &rep.0.padata, nonce)?;
    let ec = match &preauth {
        Some((k, pa::ENCRYPTED_CHALLENGE)) => reply_code(&fast.padata, akey, k),
        _ => None,
    };
    trace_reply_padata(
        Some(&fast.padata),
        etypes,
        ec.map(|code| (EC_MODULE, pa::ENCRYPTED_CHALLENGE, code)),
    );
    let pa_type = preauth.as_ref().map(|(_, mech)| *mech);
    let client_key = match preauth {
        Some((k, _)) => {
            trace::init_creds_as_key_preauth((&k).into());
            k
        }
        None => fast_base_key(req, keys, etypes, &fast, rep.0.enc_part.etype)?,
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
    trace::init_creds_gak(&salt, params.as_deref().unwrap_or_default());
    trace_keytab_gak(req, keys, etype);
    let key = pick_key(keys, Some(etype)).map_or_else(
        || string_to_key(etype, req.password, &salt, params.as_deref()),
        Ok,
    )?;
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
