//! TGS policy (`tgs_policy.c`): constraints, `check_tgs_s4u2self`,
//! `check_tgs_u2u`, and `svc_pol_fns`.

use krb5_types::{EncTicketPart, KdcReqBody, KerberosTime, PrincipalName, err, flag_bit};

use super::kdc_util::{attr, check_db_times, utf8_realm, validate_as_request};
use crate::ad::{S4u2Self, SecondTicket, pac_client_info_eq};
use crate::error::Error;
use crate::kdb::{PrincipalRead, lookup_principal_id};
use crate::preauth::proto;
use crate::status;
use crate::store::{
    KDB_DISALLOW_ALL_TIX, KDB_DISALLOW_DUP_SKEY, KDB_DISALLOW_POSTDATED, KDB_DISALLOW_RENEWABLE,
    KDB_DISALLOW_SVR, KDB_DISALLOW_TGT_BASED, KDB_REQUIRES_HW_AUTH, KDB_REQUIRES_PRE_AUTH,
    Principal,
};

/// MIT `check_tgs_u2u` (`tgs_policy.c:575-598`): same check.
pub(super) fn check_tgs_u2u(
    store: &dyn PrincipalRead,
    stkt: Option<&SecondTicket>,
    dest: &Principal,
) -> Result<(), Error> {
    let Some(st) = stkt else {
        return Err(proto(err::BADOPTION, status::NO_2ND_TKT));
    };
    if !st.server.name.is_local_tgs_principal(&st.server.realm)
        || !st.server.name.is_krbtgt_for(&dest.realm)
    {
        return Err(proto(err::POLICY, status::SECOND_TKT_NOT_TGS));
    }
    let crealm = utf8_realm(&st.part.crealm)?;
    let id = lookup_principal_id(&st.part.cname, crealm);
    let Some(client) = store.fetch(&id)? else {
        return Err(proto(err::SERVER_NOMATCH, status::SECOND_TKT_MISMATCH));
    };
    if client.name != dest.name || client.realm != dest.realm {
        return Err(proto(err::SERVER_NOMATCH, status::SECOND_TKT_MISMATCH));
    }
    Ok(())
}

fn non_tgt_option(body: &KdcReqBody) -> bool {
    body.kdc_options.bit(flag_bit::FORWARDED)
        || body.kdc_options.bit(flag_bit::PROXY)
        || body.kdc_options.bit(flag_bit::RENEW)
        || body.kdc_options.bit(flag_bit::VALIDATE)
}

/// MIT `check_tgs_nontgt` (`tgs_policy.c:636-638`): renew, forward, or proxy of a ticket whose server does not match the request, realm included, is rejected.
/// A requested forward, proxy, or postdate that the ticket does not allow is rejected, and a renew past renew-till is expired.
#[expect(clippy::too_many_arguments, reason = "MIT passes args positionally")]
pub(super) fn check_tgs_constraints_skeleton(
    body: &KdcReqBody,
    header_sname: &PrincipalName,
    header_realm: &str,
    enc_tkt: &EncTicketPart,
    req_sname: &PrincipalName,
    req_realm: &str,
    renew: bool,
    validate: bool,
) -> Result<(), Error> {
    if body.kdc_options.bit(flag_bit::FORWARDED) && !enc_tkt.flags.bit(flag_bit::FORWARDABLE) {
        return Err(proto(err::BADOPTION, status::TGT_NOT_FORWARDABLE));
    }
    if body.kdc_options.bit(flag_bit::PROXY) && !enc_tkt.flags.bit(flag_bit::PROXIABLE) {
        return Err(proto(err::BADOPTION, status::TGT_NOT_PROXIABLE));
    }
    if (body.kdc_options.bit(flag_bit::MAY_POSTDATE) || body.kdc_options.bit(flag_bit::POSTDATED))
        && !enc_tkt.flags.bit(flag_bit::MAY_POSTDATE)
    {
        return Err(proto(err::BADOPTION, status::TGT_NOT_POSTDATABLE));
    }
    if validate && !enc_tkt.flags.invalid() {
        return Err(proto(err::BADOPTION, status::VALIDATE_VALID_TICKET));
    }
    if renew && !enc_tkt.flags.renewable() {
        return Err(proto(err::BADOPTION, status::TICKET_NOT_RENEWABLE));
    }
    if enc_tkt.flags.invalid() && !validate {
        return Err(proto(err::TKT_NYV, status::TICKET_NOT_VALID));
    }
    if validate {
        let now = KerberosTime::now();
        let start = enc_tkt.starttime.as_ref().unwrap_or(&enc_tkt.authtime);
        if now.delta_seconds(start) < 0 {
            return Err(proto(err::TKT_NYV, status::NOT_YET_VALID));
        }
    }
    if renew {
        let now = KerberosTime::now();
        match &enc_tkt.renew_till {
            Some(till) if till.unix_seconds() <= now.unix_seconds() => {
                return Err(proto(err::TKT_EXPIRED, status::TKT_EXPIRED));
            }
            None => return Err(proto(err::TKT_EXPIRED, status::TKT_EXPIRED)),
            Some(_) => {}
        }
    }
    if non_tgt_option(body) {
        // MIT `check_tgs_nontgt` (`tgs_policy.c:636-636`): krb5_principal_compare includes the realm.
        if header_sname != req_sname || header_realm != req_realm {
            return Err(proto(err::SERVER_NOMATCH, status::RENEW_SERVER_MISMATCH));
        }
        if body.kdc_options.bit(flag_bit::PROXY) && req_sname.is_krbtgt() {
            return Err(proto(err::BADOPTION, status::CANT_PROXY_TGT));
        }
    } else {
        if !header_sname.is_krbtgt() {
            return Err(proto(err::NOT_US, status::BAD_TGS_SERVER_NAME));
        }
        if !header_sname.is_krbtgt_for(req_realm) {
            return Err(proto(err::NOT_US, status::BAD_TGS_SERVER_INSTANCE));
        }
    }
    Ok(())
}

/// MIT `check_tgs_s4u2self` (`tgs_policy.c:262-358`): same check.
pub(super) fn check_tgs_s4u2self(
    store: &dyn PrincipalRead,
    body: &krb5_types::KdcReqBody,
    s4u: &S4u2Self,
    header_cross: bool,
    is_referral: bool,
    enc_tkt: &EncTicketPart,
    header_pac: Option<&[u8]>,
) -> Result<(), Error> {
    if s4u2self_as_invalid_options(body) {
        return Err(proto(err::BADOPTION, status::INVALID_S4U2SELF_OPTIONS));
    }
    if !header_cross && is_referral {
        return Err(proto(err::S_PRINCIPAL_UNKNOWN, status::LOOKING_UP_SERVER));
    }
    if s4u.local.is_some() && header_cross && !is_referral {
        return Err(proto(
            err::C_PRINCIPAL_UNKNOWN,
            status::NOT_CROSS_REALM_REQUEST,
        ));
    }
    if s4u.local.is_none() && !header_cross {
        return Err(proto(err::POLICY, status::S4U2SELF_CLIENT_NOT_OURS));
    }
    if s4u.local.is_none() && s4u.user.name_string.is_empty() {
        return Err(proto(err::POLICY, status::INVALID_XREALM_S4U2SELF_REQUEST));
    }
    let Some(raw) = header_pac else {
        return Err(proto(err::TGT_REVOKED, status::S4U2SELF_NO_PAC));
    };
    let parsed = krb5_types::pac::Pac::parse(raw)
        .map_err(|_| proto(err::BADOPTION, status::S4U2SELF_LOCAL_PAC_CLIENT))?;
    let authtime = enc_tkt.authtime.unix_seconds();
    if let Some(ref client) = s4u.local {
        if !pac_client_info_eq(&parsed, authtime, &enc_tkt.cname.components_joined(), None) {
            return Err(proto(err::BADOPTION, status::S4U2SELF_LOCAL_PAC_CLIENT));
        }
        let empty = crate::store::Principal::from_keys(
            PrincipalName::new(PrincipalName::NT_UNKNOWN, std::iter::empty::<&str>()),
            String::new(),
            Vec::new(),
            Vec::new(),
            crate::store::PrincipalFields {
                requires_preauth: false,
                max_life: 0,
                locked: false,
                pw_expire: 0,
            },
        );
        validate_as_request(store, client, &empty, body)?;
    } else if !pac_client_info_eq(
        &parsed,
        authtime,
        &s4u.user.components_joined(),
        Some(&s4u.realm),
    ) {
        return Err(proto(err::BADOPTION, status::S4U2SELF_FOREIGN_PAC_CLIENT));
    }
    Ok(())
}

fn s4u2self_as_invalid_options(body: &krb5_types::KdcReqBody) -> bool {
    body.kdc_options.bit(flag_bit::FORWARDED)
        || body.kdc_options.bit(flag_bit::PROXY)
        || body.kdc_options.bit(flag_bit::VALIDATE)
        || body.kdc_options.bit(flag_bit::RENEW)
        || body.kdc_options.bit(flag_bit::ENC_TKT_IN_SKEY)
        || body.kdc_options.bit(flag_bit::CNAME_IN_ADDL_TKT)
}

pub(super) fn check_tgs_policy_flags(
    server: &Principal,
    body: &krb5_types::KdcReqBody,
    header_is_tgt: bool,
    tkt: &EncTicketPart,
) -> Result<(), Error> {
    // MIT `check_tgs_svc_policy` (`tgs_policy.c:201-215`): deny_opts, deny_all, reqd_flags, svc_time.
    // deny_opts:
    if attr(server, KDB_DISALLOW_RENEWABLE) && body.kdc_options.bit(flag_bit::RENEWABLE) {
        return Err(proto(err::POLICY, status::NON_RENEWABLE_TICKET));
    }
    if attr(server, KDB_DISALLOW_POSTDATED) && body.kdc_options.bit(flag_bit::MAY_POSTDATE) {
        return Err(proto(err::CANNOT_POSTDATE, status::NON_POSTDATABLE_TICKET));
    }
    if attr(server, KDB_DISALLOW_DUP_SKEY) && body.kdc_options.bit(flag_bit::ENC_TKT_IN_SKEY) {
        return Err(proto(err::POLICY, status::DUP_SKEY_DISALLOWED));
    }
    // deny_all:
    if attr(server, KDB_DISALLOW_ALL_TIX) {
        return Err(proto(err::S_PRINCIPAL_UNKNOWN, status::SERVER_LOCKED_OUT));
    }
    if attr(server, KDB_DISALLOW_SVR) && !body.kdc_options.bit(flag_bit::ENC_TKT_IN_SKEY) {
        return Err(proto(err::MUST_USE_USER2USER, status::SERVER_NOT_ALLOWED));
    }
    if attr(server, KDB_DISALLOW_TGT_BASED) && header_is_tgt {
        return Err(proto(err::POLICY, status::TGT_BASED_NOT_ALLOWED));
    }
    // reqd_flags:
    if attr(server, KDB_REQUIRES_HW_AUTH) && !tkt.flags.bit(flag_bit::HW_AUTHENT) {
        return Err(proto(err::GENERIC, status::NO_HW_PREAUTH));
    }
    if attr(server, KDB_REQUIRES_PRE_AUTH) && !tkt.flags.bit(flag_bit::PRE_AUTHENT) {
        return Err(proto(err::GENERIC, status::NO_PREAUTH));
    }
    // MIT `check_tgs_svc_time` (`tgs_policy.c:190-198`): svc_time last in `svc_pol_fns`, before
    // MIT `check_tgs_req` (`do_tgs_req.c:897-902`): `check_indicators`.
    check_db_times(None, server)?;
    Ok(())
}
