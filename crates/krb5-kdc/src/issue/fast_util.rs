//! FAST (`fast_util.c`): hide-client-names, `check_fast_options`, and
//! the AS FAST error wrap (`kdc_fast_handle_error`).

use krb5_asn1::{decode, encode};
use krb5_types::{AsReq, HostAddress, KdcReqBody, MethodData, PaData, TgsReq, err, pa};

use super::kdc_util::{kdc_req_body_der, process_tgs_header};
use super::reply::encode_krb_error;
use super::tgs_req::extract_pa_tgs;
use crate::error::Error;
use crate::kdb::PrincipalRead;
use crate::preauth::{
    FastOk, decode_edata_padata, unwrap_fast, unwrap_fast_tgs, with_fx_cookie, wrap_fast_rep,
};
use crate::status;

/// RFC 6113 bit 1 (`KRB5_FAST_OPTION_HIDE_CLIENT_NAMES`, MIT 0x40000000): the
/// only non-reserved critical FAST option, honoured rather than refused.
const FAST_HIDE_CLIENT_NAMES_BIT: usize = 1;

pub(super) fn check_fast_options(opts: &krb5_types::fast::FastOptions) -> Result<(), Error> {
    // MIT fast_util.c:226 rejects only UNSUPPORTED_CRITICAL_FAST_OPTIONS =
    // 0xbfff0000 (RFC bits 0 and 2..15). Bit 1 (hide-client-names) is honoured
    // (kdc_fast_hide_client), so it is skipped here rather than refused.
    let n = opts.len().min(16);
    for i in 0..n {
        if i == FAST_HIDE_CLIENT_NAMES_BIT {
            continue;
        }
        if opts[i] {
            return Err(crate::preauth::proto_fast(
                err::UNKNOWN_CRITICAL_FAST_OPTION,
                "FAST option",
            ));
        }
    }
    Ok(())
}

/// MIT `kdc_fast_hide_client` (fast_util.c:444): the request set RFC 6113
/// bit 1, so the reply's outer client name/realm become the anonymous principal.
pub(super) fn fast_hides_client(opts: &krb5_types::fast::FastOptions) -> bool {
    opts.len() > FAST_HIDE_CLIENT_NAMES_BIT && opts[FAST_HIDE_CLIENT_NAMES_BIT]
}

pub(super) fn peek_as_hides_client(store: &dyn PrincipalRead, req: &AsReq, raw: &[u8]) -> bool {
    let encoded;
    let body = if let Some(slice) = kdc_req_body_der(raw) {
        slice
    } else {
        encoded = match encode(&req.0.req_body) {
            Ok(b) => b,
            Err(_) => return false,
        };
        &encoded
    };
    unwrap_fast(store, req, body)
        .ok()
        .flatten()
        .is_some_and(|f| fast_hides_client(&f.fast_options))
}

pub(super) fn peek_tgs_hides_client(
    store: &dyn PrincipalRead,
    req: &TgsReq,
    raw: &[u8],
    sender: Option<&HostAddress>,
) -> bool {
    let encoded;
    let body = if let Some(slice) = kdc_req_body_der(raw) {
        slice
    } else {
        encoded = match encode(&req.0.req_body) {
            Ok(b) => b,
            Err(_) => return false,
        };
        &encoded
    };
    let Some(pa_tgs) = extract_pa_tgs(req.0.padata.as_deref()) else {
        return false;
    };
    let Ok(header) = process_tgs_header(store, pa_tgs.as_ref(), body, sender) else {
        return false;
    };
    unwrap_fast_tgs(
        store,
        req.0.padata.as_deref(),
        pa_tgs.as_ref(),
        header.authenticator.subkey.as_ref(),
        &header.session,
    )
    .ok()
    .flatten()
    .is_some_and(|f| fast_hides_client(&f.fast_options))
}

pub(super) fn wrap_as_fast(
    store: &dyn PrincipalRead,
    fast: Option<&FastOk>,
    err: Error,
    body: &KdcReqBody,
) -> Error {
    let Some(f) = fast else {
        return err;
    };
    let (code, text, inner_ed, as_preauth, detail) = match err {
        Error::PreauthRequired { e_data } => {
            let method = decode::<MethodData>(&e_data).unwrap_or_default();
            let inner = encode(&method).unwrap_or_default();
            (err::PREAUTH_REQUIRED, None, inner, Some(method), None)
        }
        Error::Protocol {
            code,
            text,
            e_data,
            detail,
        } => (code, text, e_data.unwrap_or_default(), None, detail),
        Error::Crypto(d) => (
            err::PREAUTH_FAILED,
            Some(status::PREAUTH_FAILED.to_owned()),
            Vec::new(),
            None,
            Some(d).filter(|s| !s.is_empty()),
        ),
        Error::Asn1(d) => (
            err::GENERIC,
            Some(status::UNKNOWN_REASON.to_owned()),
            Vec::new(),
            None,
            Some(d).filter(|s| !s.is_empty()),
        ),
        other => (
            err::GENERIC,
            Some(status::UNKNOWN_REASON.to_owned()),
            Vec::new(),
            None,
            Some(other.to_string()).filter(|s| !s.is_empty()),
        ),
    };
    let mut padata = as_preauth.unwrap_or_else(|| decode_edata_padata(&inner_ed));
    padata = with_fx_cookie(store, body.cname.as_ref(), padata);
    // MIT kdc_fast_handle_error (fast_util.c:384-386): the inner PA-FX-ERROR
    // KRB-ERROR has empty e_data; the caller's e_data (plus cookie) travels
    // as FAST inner padata next to FX-ERROR.
    let inner_err = encode_krb_error(store, code, text.as_deref(), None, Some(body), false);
    padata.push(PaData {
        padata_type: pa::FX_ERROR,
        padata_value: inner_err.into(),
    });
    match wrap_fast_rep(&f.armor_key, padata, None, f.nonce, None) {
        Ok(pa) => match encode(&vec![pa]) {
            Ok(outer) => {
                if code == err::PREAUTH_REQUIRED {
                    Error::PreauthRequired { e_data: outer }
                } else {
                    Error::Protocol {
                        code,
                        text,
                        e_data: Some(outer),
                        detail,
                    }
                }
            }
            Err(e) => e.into(),
        },
        Err(e) => e,
    }
}
