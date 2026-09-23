//! RFC 6113 FAST armor on the AS exchange (`lib/krb5/krb/fast.c`
//! `krb5int_fast_process_response` / `krb5int_fast_process_error`).

use super::{
    AsOutcome, AsReqTimes, AsRequest, KdcMsg, build_as_req_from, classify, classify_kdc_error,
    find_pa, finish_as_rep, first_etype, pa_enc_timestamp, pick_info2, pick_key, req_sname,
    salt_cname, select_s2k,
};
use crate::error::Error;
use crate::preauth::{
    apply_strengthen, armor_key, attach_fast, build_fast_armor, unwrap_fast_rep_checked,
    verify_fast_finished,
};
use crate::transport::exchange;
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

pub(super) fn continue_fast(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    nonce: u32,
    bound: &AsReqTimes,
    etypes: &[i32],
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
    let mut probe = build_as_req_from(req, nonce, bound, None, etypes)?;
    attach_fast(&mut probe, &ap, &akey, Vec::new())?;
    let wire = encode(&probe)?;
    let reply = exchange(req.kdc, &wire)?;
    match classify(&reply)? {
        KdcMsg::AsRep(rep) => {
            finish_fast_as(req, keys, nonce, etypes, &akey, None, rep, &wire, bound)
        }
        KdcMsg::Error(e) => {
            let FastErrorMaterial {
                err: inner,
                cookie,
                retry,
            } = fast_error_material(&akey, &e, nonce)?;
            // `get_in_tkt.c:1721-1724`: only `PREAUTH_REQUIRED && retry`
            // continues; an outer error that did not unwrap (retry = 0) is
            // returned as-is — no second AS-REQ, whatever its code.
            if !retry || inner.error_code != err::PREAUTH_REQUIRED {
                return classify_kdc_error(&inner);
            }
            let (etype, salt, params) =
                select_s2k(&inner, &salt_cname(&req.cname), req.realm, etypes)?;
            let client_key = pick_key(keys, Some(etype)).map_or_else(
                || string_to_key(etype, req.password, &salt, params.as_deref()),
                Ok,
            )?;
            // MIT k5_preauth copies the FX-COOKIE (copy_cookie) before the
            // preauth module's PA data, so the cookie leads the inner padata.
            let mut inner_pa = Vec::new();
            if let Some(c) = cookie {
                inner_pa.push(c);
            }
            inner_pa.push(pa_enc_timestamp(&client_key)?);
            let ap = fast_armor_ap(armor, &sub)?;
            let mut req2 = build_as_req_from(req, nonce, bound, None, etypes)?;
            attach_fast(&mut req2, &ap, &akey, inner_pa)?;
            let wire = encode(&req2)?;
            let reply = exchange(req.kdc, &wire)?;
            match classify(&reply)? {
                KdcMsg::AsRep(rep) => finish_fast_as(
                    req,
                    keys,
                    nonce,
                    etypes,
                    &akey,
                    Some(client_key),
                    rep,
                    &wire,
                    bound,
                ),
                KdcMsg::Error(e) => classify_kdc_error(&fast_error_material(&akey, &e, nonce)?.err),
                KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
            }
        }
        KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
    }
}

#[expect(clippy::too_many_arguments, reason = "client AS, not a params struct")]
fn finish_fast_as(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    nonce: u32,
    etypes: &[i32],
    akey: &ProtocolKey,
    client_key: Option<ProtocolKey>,
    mut rep: AsRep,
    wire: &[u8],
    bound: &AsReqTimes,
) -> Result<AsOutcome, Error> {
    let fast = unwrap_fast_rep_checked(akey, &rep.0.padata, nonce)?;
    let sent_preauth = client_key.is_some();
    let client_key = match client_key {
        Some(k) => k,
        None => fast_base_key(
            keys,
            req.password,
            &req.cname,
            req.realm,
            etypes,
            &fast,
            rep.0.enc_part.etype,
        )?,
    };
    let reply_key = match &fast.strengthen_key {
        Some(sk) => apply_strengthen(sk, &client_key)?,
        None => client_key,
    };
    let finished = fast.finished.as_ref().ok_or_else(|| {
        Error::ReplyMismatch("FAST response missing finish message in KDC reply".into())
    })?;
    verify_fast_finished(akey, &rep.0.ticket, finished)?;
    // MIT `krb5int_fast_process_response` (`fast.c:548-558`): once the
    // finished checksum holds, the reply's client *is* the finished message's
    // client and the reply padata is the FAST-inner list — the outer cname /
    // crealm / padata are unauthenticated and never looked at again
    // (`get_in_tkt.c:236-241` compares the replaced client).
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
        sent_preauth.then_some(pa::ENC_TIMESTAMP),
        req.canonicalize,
        &req_sname(req),
        bound,
        // MIT verifies the enc-pa-rep checksum under FAST too, over the
        // outer request with the (strengthened) reply key.
        Some(wire),
        true,
    )
}

fn fast_base_key(
    keys: &[ProtocolKey],
    password: &[u8],
    cname: &PrincipalName,
    realm: &str,
    etypes: &[i32],
    fast: &krb5_types::fast::KrbFastResponse,
    enc_etype: i32,
) -> Result<ProtocolKey, Error> {
    let default_salt = salt_cname(cname).default_salt(realm);
    let material = fast.padata.iter().find_map(|p| {
        if p.padata_type != pa::ETYPE_INFO2 {
            return None;
        }
        let info: EtypeInfo2 = decode(p.padata_value.as_ref()).ok()?;
        pick_info2(&info, &default_salt, etypes)
    });
    let (etype, salt, params) = match material {
        Some(m) => m,
        None => (
            EncryptionType::known(enc_etype).unwrap_or_else(|_| first_etype(etypes)),
            default_salt,
            None,
        ),
    };
    pick_key(keys, Some(etype))
        .map_or_else(
            || string_to_key(etype, password, &salt, params.as_deref()),
            Ok,
        )
        .map_err(Into::into)
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

/// What MIT `krb5int_fast_process_error` (`fast.c:428-511`) hands back for a
/// KRB-ERROR received under an armor key.
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

/// MIT `krb5int_fast_process_error` with an armor key (`fast.c:445-495`):
/// the e_data must decode as a padata sequence whose PA-FX-FAST decrypts
/// under the armor key with the request nonce; when it does not ("the KDC
/// does not understand FAST" — or a man in the middle stripped it) the outer
/// error is the fatal answer with `retry = 0` and nothing from it is trusted
/// (no cookie, no method data). A decrypted response without FX-ERROR is
/// `KRB5KDC_ERR_PREAUTH_FAILED` "Expecting FX_ERROR pa-data inside FAST
/// container". Otherwise the inner error replaces the outer one, the inner
/// padata is the method data, and `retry` is set only when that list has
/// more than the FX-ERROR entry and includes an FX-COOKIE.
///
/// The inner error's `e_data` is filled with the inner padata when it is
/// empty so `method_from_error` / `select_s2k` read the protected hints.
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
    let Some(fx) = find_pa(&method, pa::FX_FAST) else {
        return outer_fatal();
    };
    let Ok(fast) = unwrap_fast_rep_checked(akey, &Some(vec![fx.clone()]), nonce) else {
        return outer_fatal();
    };
    let types: Vec<i32> = fast.padata.iter().map(|p| p.padata_type).collect();
    tracing::info!(
        event = "client.fast",
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
