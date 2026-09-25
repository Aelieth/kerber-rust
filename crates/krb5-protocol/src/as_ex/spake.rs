//! SPAKE client (`plugins/preauth/spake/spake_client.c`
//! `contains_sf_none` / the P-256 response).

use super::{
    AsOutcome, AsReqTimes, AsRequest, KdcMsg, build_as_req_from, classify, classify_kdc_error,
    find_pa, finish_as_rep, method_from_error, pick_key, req_sname, salt_cname, select_s2k,
};
use crate::error::Error;
use crate::preauth::{pa_spake_response, pa_spake_support};
use crate::transport::exchange;
use krb5_asn1::{decode, encode};
use krb5_crypto::{ProtocolKey, string_to_key};
use krb5_types::{KrbError, PaData, err, pa};

pub(super) fn continue_spake(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    nonce: u32,
    bound: &AsReqTimes,
    etypes: &[i32],
    err: &KrbError,
) -> Result<AsOutcome, Error> {
    let support = pa_spake_support();
    let method = method_from_error(err)?;
    if spake_challenge(&method)?.is_some() {
        return send_spake_response(req, keys, nonce, bound, etypes, err, &support);
    }
    let mut padata = Vec::new();
    if let Some(c) = find_pa(&method, pa::FX_COOKIE) {
        padata.push(c.clone());
    }
    padata.push(support.clone());
    let second = build_as_req_from(req, nonce, bound, Some(padata), etypes)?;
    let wire = encode(&second)?;
    let reply = exchange(req.kdc, &wire)?;
    match classify(&reply)? {
        KdcMsg::AsRep(_) => Err(Error::ReplyMismatch("SPAKE required".into())),
        KdcMsg::Error(e)
            if e.error_code == err::PREAUTH_REQUIRED
                || e.error_code == err::MORE_PREAUTH_DATA_REQUIRED =>
        {
            send_spake_response(req, keys, nonce, bound, etypes, &e, &support)
        }
        KdcMsg::Error(e) => classify_kdc_error(&e),
        KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
    }
}

/// MIT `process_challenge` (`spake_client.c:221-222`): a challenge that does not offer SF-NONE is preauth-failed.
/// The cookie is placed ahead of the SPAKE response so the freshness and enc-pa-rep advertisements stay on the request.
fn send_spake_response(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    nonce: u32,
    bound: &AsReqTimes,
    etypes: &[i32],
    err: &KrbError,
    support: &PaData,
) -> Result<AsOutcome, Error> {
    let method = method_from_error(err)?;
    let (spa, chal) = spake_challenge(&method)?
        .ok_or_else(|| Error::ReplyMismatch("SPAKE challenge missing".into()))?;
    if chal.group != krb5_types::spake::GROUP_P256 {
        return Err(Error::ReplyMismatch(format!(
            "SPAKE group {} (want P-256)",
            chal.group
        )));
    }
    // MIT spake_client.c:221: without second-factor support the only
    // answerable challenge is one that offers SF-NONE; a challenge whose
    // factor list omits it is KRB5KDC_ERR_PREAUTH_FAILED there, so refuse it
    // rather than deriving a key against a factor set we cannot satisfy.
    if !spake_contains_sf_none(&chal) {
        return Err(Error::ReplyMismatch(
            "SPAKE challenge offers no SF-NONE factor".into(),
        ));
    }
    let cookie = find_pa(&method, pa::FX_COOKIE)
        .cloned()
        .ok_or_else(|| Error::ReplyMismatch("SPAKE FX_COOKIE missing".into()))?;
    let (etype, salt, params) = select_s2k(err, &salt_cname(&req.cname), req.realm, etypes)?;
    let ikey = pick_key(keys, Some(etype)).map_or_else(
        || string_to_key(etype, req.password, &salt, params.as_deref()),
        Ok,
    )?;
    let mut req2 = build_as_req_from(req, nonce, bound, None, etypes)?;
    let body_der = encode(&req2.0.req_body)?;
    let (resp, k0) = pa_spake_response(
        &ikey,
        support.padata_value.as_ref(),
        spa.padata_value.as_ref(),
        chal.pubkey.as_ref(),
        &body_der,
    )?;
    // MIT k5_preauth copies the FX-COOKIE first, then the module's PA-SPAKE,
    // and init_creds_step_request appends the info_pa_permitted pair (150,
    // 149) that build_as_req already put on the list; replacing the list here
    // dropped 149, so the KDC echoed no enc-pa-rep checksum (KDCREP_MODIFIED).
    let mut padata = vec![cookie, resp];
    padata.extend(req2.0.padata.take().unwrap_or_default());
    req2.0.padata = Some(padata);
    let wire = encode(&req2)?;
    let reply = exchange(req.kdc, &wire)?;
    match classify(&reply)? {
        KdcMsg::AsRep(rep) => finish_as_rep(
            rep,
            nonce,
            Some(k0),
            req.password,
            &req.cname,
            req.realm,
            Some(pa::SPAKE),
            req.canonicalize,
            &req_sname(req),
            bound,
            Some(&wire),
            false,
        ),
        KdcMsg::Error(e) => classify_kdc_error(&e),
        KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
    }
}

/// MIT `contains_sf_none` (spake_client.c:51): true when the challenge lists
/// the SF-NONE second factor, the only factor type this client can answer.
pub(super) fn spake_contains_sf_none(chal: &krb5_types::spake::SpakeChallenge) -> bool {
    chal.factors
        .iter()
        .any(|f| f.factor_type == krb5_types::spake::SF_NONE)
}

fn spake_challenge(
    method: &[PaData],
) -> Result<Option<(PaData, krb5_types::spake::SpakeChallenge)>, Error> {
    let Some(p) = find_pa(method, pa::SPAKE) else {
        return Ok(None);
    };
    // PREAUTH_REQUIRED advertises an empty PA-SPAKE (MIT `spake_kdc.c:321`).
    // That is not a challenge; `spake_client.c:151` sends support instead.
    if p.padata_value.as_ref().is_empty() {
        return Ok(None);
    }
    match decode::<krb5_types::spake::PaSpake>(p.padata_value.as_ref())? {
        krb5_types::spake::PaSpake::Challenge(c) => Ok(Some((p.clone(), c))),
        _ => Ok(None),
    }
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
