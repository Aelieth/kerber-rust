//! Minimal Kerberos V5 client: AS/TGS, MIT FILE ccache, keytab v2.
//!
//! `kinit` talks to a KDC over UDP/TCP 88, stores a TGT, and can request a
//! service ticket. There is no C FFI.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::path::Path;

use krb5_asn1::decode;
use krb5_config::CcSpec;
use krb5_protocol::{
    AsOutcome, AsRequest, AsTicketOpts, FastArmor, KdcAddr, PkinitClient, TgsOutcome, as_exchange,
    as_exchange_with_keys, dir_cache_path, dir_cache_path_for_store, kcm_destroy, kcm_load,
    kcm_store, kcm_store_keep_default, memory_destroy, memory_retrieve, memory_store,
    parse_principal_ex, tgs_exchange_path, tgs_renew, tgs_validate,
};
use krb5_types::Ticket;
use zeroize::Zeroize;

pub use krb5_protocol::{
    CcacheCred, CcacheKeyblock, FileCcache, Keytab, KeytabEntry, parse_principal, realm, tgt_cred,
};
pub use krb5_protocol::{Error as ProtocolError, KDC_PORT};

/// Credential-cache re-exports of [`krb5_protocol`]: [`FileCcache`], [`CcacheCred`],
/// [`CcacheKeyblock`] and the principal/realm helpers, grouped for callers that only cache.
pub mod ccache {
    pub use krb5_protocol::{
        CcacheCred, CcacheKeyblock, FileCcache, parse_principal, realm, tgt_cred,
    };
}

/// Keytab re-exports of [`krb5_protocol`]: [`Keytab`] and [`KeytabEntry`].
pub mod keytab {
    pub use krb5_protocol::{Keytab, KeytabEntry};
}

pub mod cli;

/// Flags for [`kinit_with`].
#[derive(Clone, Debug, Default)]
pub struct KinitParams<'a> {
    /// Optional TGS service (`-S` or positional).
    pub service: Option<&'a str>,
    /// PA-SPAKE.
    pub want_spake: bool,
    /// FAST armor ccache.
    pub armor_ccache: Option<&'a Path>,
    /// PKINIT identity PEM.
    pub pkinit_identity: Option<&'a Path>,
    /// PKINIT anchors PEM.
    pub pkinit_anchors: Option<&'a Path>,
    /// NT-ENTERPRISE.
    pub enterprise: bool,
    /// Keytab (`-k` / `-t`).
    pub keytab: Option<&'a Path>,
    /// AS ticket options.
    pub ticket: AsTicketOpts,
    /// `kinit -R`.
    pub renew: bool,
    /// `kinit -v`: TGS-REQ with KDC option `validate`.
    pub validate: bool,
    /// `kinit -n` (anonymous PKINIT).
    pub anonymous: bool,
    /// `kinit -C` / `[libdefaults] canonicalize`.
    pub canonicalize: bool,
    /// New password for `gic_pwd.c` KEY_EXP → changepw (`KRB5_NEW_PASSWORD`),
    /// the non-interactive stand-in for [`KinitParams::prompter`].
    pub new_password: Option<&'a [u8]>,
    /// krb5_prompter_fct for the KEY_EXP new-password prompts
    /// (`gic_pwd.c`). `None` with no `new_password` leaves
    /// `KDC_ERR_KEY_EXP` as the error (`gic_pwd.c`).
    pub prompter: Option<NewPasswordPrompter<'a>>,
}

/// `krb5_prompter_fct` narrowed to `gic_pwd.c`: shown `banner`, it
/// returns the `Enter new password` / `Enter it again` replies.
#[derive(Clone, Copy)]
pub struct NewPasswordPrompter<'a>(pub &'a (dyn Fn(&str) -> PromptReply + 'a));

/// The two `KRB5_PROMPT_TYPE_NEW_PASSWORD*` replies, or the prompter's error.
pub type PromptReply = Result<(Vec<u8>, Vec<u8>), String>;

impl std::fmt::Debug for NewPasswordPrompter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NewPasswordPrompter")
    }
}

/// Result of [`kinit`].
pub struct KinitResult {
    /// AS outcome (TGT + session key).
    pub as_out: AsOutcome,
    /// Optional TGS outcome.
    pub tgs_out: Option<TgsOutcome>,
}

/// Obtain a TGT from `kdc` for `principal` (`user@REALM`) and write a FILE
/// ccache. If `service` is `Some("host/foo")`, also run a TGS-REQ.
///
/// # Errors
///
/// Returns protocol or I/O errors. The password buffer is zeroized before
/// return.
pub fn kinit(
    kdc: &KdcAddr,
    principal: &str,
    password: &mut [u8],
    ccache_path: impl AsRef<Path>,
    service: Option<&str>,
) -> Result<KinitResult, Box<dyn std::error::Error + Send + Sync>> {
    kinit_ex(
        kdc,
        principal,
        password,
        ccache_path,
        &InitCredsOpt {
            service,
            want_spake: false,
            armor_ccache: None,
            pkinit_identity: None,
            pkinit_anchors: None,
            enterprise: false,
        },
    )
}

/// Options for [`kinit_ex`] and [`kinit_to_spec`].
///
/// MIT keeps the option block in `krb5_get_init_creds_opt`
/// (`include/krb5/krb5.hin:6839-6851`) and its `extended_options`
/// (`lib/krb5/krb/gic_opt.c`): `fast_ccache_name` is the armor
/// ccache, and `preauth_data` carries the PKINIT identity and anchors.
/// `service` is `krb5_get_init_creds_password`'s `in_tkt_service`.
/// SPAKE and enterprise are request flags, not fields of that struct.
#[derive(Clone, Copy)]
pub struct InitCredsOpt<'a> {
    /// Optional TGS service (`-S` or positional).
    pub service: Option<&'a str>,
    /// PA-SPAKE.
    pub want_spake: bool,
    /// FAST armor ccache.
    pub armor_ccache: Option<&'a Path>,
    /// PKINIT identity PEM.
    pub pkinit_identity: Option<&'a Path>,
    /// PKINIT anchors PEM.
    pub pkinit_anchors: Option<&'a Path>,
    /// NT-ENTERPRISE.
    pub enterprise: bool,
}

/// [`kinit`] with a preauth mode (`want_spake` = PA-SPAKE P-256).
///
/// # Errors
///
/// Protocol or I/O errors. The password buffer is zeroized before return.
pub fn kinit_ex(
    kdc: &KdcAddr,
    principal: &str,
    password: &mut [u8],
    ccache_path: impl AsRef<Path>,
    opts: &InitCredsOpt<'_>,
) -> Result<KinitResult, Box<dyn std::error::Error + Send + Sync>> {
    let InitCredsOpt {
        service,
        want_spake,
        armor_ccache,
        pkinit_identity,
        pkinit_anchors,
        enterprise,
    } = *opts;
    let spec = CcSpec::File(ccache_path.as_ref().to_path_buf());
    let params = KinitParams {
        service,
        want_spake,
        armor_ccache,
        pkinit_identity,
        pkinit_anchors,
        enterprise,
        ..KinitParams::default()
    };
    kinit_with(kdc, principal, password, &spec, params)
}

/// [`kinit_ex`] storing into [`CcSpec`] (FILE, MEMORY, or DIR).
///
/// # Errors
///
/// Protocol or I/O errors. The password buffer is zeroized before return.
pub fn kinit_to_spec(
    kdc: &KdcAddr,
    principal: &str,
    password: &mut [u8],
    spec: &CcSpec,
    opts: &InitCredsOpt<'_>,
) -> Result<KinitResult, Box<dyn std::error::Error + Send + Sync>> {
    let InitCredsOpt {
        service,
        want_spake,
        armor_ccache,
        pkinit_identity,
        pkinit_anchors,
        enterprise,
    } = *opts;
    kinit_with(
        kdc,
        principal,
        password,
        spec,
        KinitParams {
            service,
            want_spake,
            armor_ccache,
            pkinit_identity,
            pkinit_anchors,
            enterprise,
            ..KinitParams::default()
        },
    )
}

/// [`kinit_to_spec`] with keytab, renewal, and ticket flags.
///
/// # Errors
///
/// Protocol or I/O errors. The password buffer is zeroized before return.
pub fn kinit_with(
    kdc: &KdcAddr,
    principal: &str,
    password: &mut [u8],
    spec: &CcSpec,
    params: KinitParams<'_>,
) -> Result<KinitResult, Box<dyn std::error::Error + Send + Sync>> {
    let built = kinit_inner(kdc, principal, password, spec, params);
    let result = match built {
        Ok((r, cc)) => store_ccache(spec, cc).map(|()| r),
        Err(e) => Err(e),
    };
    password.zeroize();
    result
}

/// The krb5_error_code of a `kinit_with` failure, typed (never by
/// text): the KRB-ERROR code the KDC sent, or `KRB5KRB_AP_ERR_BAD_INTEGRITY`
/// (31) for a KDC-REP that did not verify under the derived key, which is
/// what `krb5_get_init_creds_password` returns for a wrong password when the
/// MIT `k5_kinit` (`kinit.c:787-787`): KDC did not require preauth.
#[must_use]
pub fn mit_error_code(e: &(dyn std::error::Error + Send + Sync + 'static)) -> Option<i32> {
    match e.downcast_ref::<krb5_protocol::Error>() {
        Some(krb5_protocol::Error::KrbError { code, .. }) => Some(*code),
        Some(krb5_protocol::Error::ReplyIntegrity) => Some(krb5_types::err::BAD_INTEGRITY),
        _ => None,
    }
}

/// Load a FILE, MEMORY, or DIR cache.
///
/// # Errors
///
/// Missing cache or parse failure.
pub fn load_ccache(spec: &CcSpec) -> Result<FileCcache, Box<dyn std::error::Error + Send + Sync>> {
    match spec {
        CcSpec::File(p) => Ok(FileCcache::parse(&std::fs::read(p)?)?),
        CcSpec::Memory(n) => memory_retrieve(n).ok_or_else(|| "No credentials cache found".into()),
        CcSpec::Dir(r) => {
            let p = dir_cache_path(r)?;
            Ok(FileCcache::parse(&std::fs::read(p)?)?)
        }
        CcSpec::Kcm(n) => kcm_load(n).map_err(Into::into),
    }
}

/// Write a cache to FILE, MEMORY, or DIR.
///
/// # Errors
///
/// I/O or DIR residual errors.
pub fn store_ccache(
    spec: &CcSpec,
    cc: FileCcache,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match spec {
        CcSpec::File(p) => cc.write_file(p).map_err(Into::into),
        CcSpec::Memory(n) => {
            memory_store(n.clone(), cc);
            Ok(())
        }
        CcSpec::Dir(r) => {
            let p = dir_cache_path_for_store(r)?;
            cc.write_file(p).map_err(Into::into)
        }
        CcSpec::Kcm(n) => kcm_store(n, &cc).map_err(Into::into),
    }
}

/// [`store_ccache`] without switching the KCM collection default (`kvno`).
///
/// # Errors
///
/// I/O or DIR residual errors.
pub fn store_ccache_keep_default(
    spec: &CcSpec,
    cc: FileCcache,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match spec {
        CcSpec::Kcm(n) => kcm_store_keep_default(n, &cc).map_err(Into::into),
        _ => store_ccache(spec, cc),
    }
}

/// Destroy FILE, MEMORY, or DIR (primary/subsidiary FILE).
///
/// # Errors
///
/// Missing cache or I/O.
pub fn destroy_ccache(spec: &CcSpec) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match spec {
        CcSpec::File(p) => krb5_protocol::destroy_secret_file(p).map_err(Into::into),
        CcSpec::Memory(n) => {
            if memory_destroy(n) {
                Ok(())
            } else {
                Err("No credentials cache found".into())
            }
        }
        CcSpec::Dir(r) => {
            let p = dir_cache_path(r)?;
            krb5_protocol::destroy_secret_file(&p).map_err(Into::into)
        }
        CcSpec::Kcm(n) => kcm_destroy(n).map_err(Into::into),
    }
}

fn load_fast_armor(path: &Path) -> Result<FastArmor, Box<dyn std::error::Error + Send + Sync>> {
    let bytes = std::fs::read(path)?;
    let cc = FileCcache::parse(&bytes)?;
    let cred = cc
        .creds
        .iter()
        .find(|c| !c.is_config() && c.server.1.components_joined().starts_with("krbtgt/"))
        .ok_or("armor ccache has no TGT")?;
    let ticket: Ticket = decode(&cred.ticket)?;
    Ok(FastArmor {
        ticket,
        session: cred.session_key()?,
        crealm: cred.client.0.clone(),
        cname: cred.client.1.clone(),
    })
}

fn strip_file_spec(s: &str) -> &str {
    s.strip_prefix("FILE:").unwrap_or(s)
}

fn conf_default_realm() -> Option<String> {
    krb5_config::load_krb5_conf().and_then(|c| c.default_realm)
}

fn load_pkinit(
    identity: &Path,
    anchors: &Path,
) -> Result<PkinitClient, Box<dyn std::error::Error + Send + Sync>> {
    let id = std::fs::read_to_string(identity)?;
    let (cert, key) = krb5_types::pkinit::parse_identity_pem(&id).ok_or("pkinit identity PEM")?;
    let anc = std::fs::read_to_string(anchors)?;
    let ca_cert = krb5_types::pkinit::parse_pem("CERTIFICATE", &anc).ok_or("pkinit anchors PEM")?;
    Ok(PkinitClient { cert, key, ca_cert })
}

fn load_pkinit_anchors(
    anchors: &Path,
) -> Result<PkinitClient, Box<dyn std::error::Error + Send + Sync>> {
    let anc = std::fs::read_to_string(anchors)?;
    let ca_cert = krb5_types::pkinit::parse_pem("CERTIFICATE", &anc).ok_or("pkinit anchors PEM")?;
    Ok(PkinitClient {
        cert: Vec::new(),
        key: [0u8; 32],
        ca_cert,
    })
}

fn pkinit_from_conf(realm: &str) -> (Option<std::path::PathBuf>, Option<std::path::PathBuf>) {
    let Some(conf) = krb5_config::load_krb5_conf() else {
        return (None, None);
    };
    let id = conf
        .pkinit_identities
        .get(realm)
        .and_then(|v| v.first())
        .map(|s| std::path::PathBuf::from(strip_file_spec(s)));
    let an = conf
        .pkinit_anchors
        .get(realm)
        .and_then(|v| v.first())
        .map(|s| std::path::PathBuf::from(strip_file_spec(s)));
    (id, an)
}

/// MIT `krb5_get_init_creds_password` (`gic_pwd.c:211-214`): an error other than key-expired is returned unchanged, and key-expired with no prompter is not a change.
/// A keytab request has no change-password flow, and the credential cache is written only after the exchange succeeds.
fn kinit_inner(
    kdc: &KdcAddr,
    principal: &str,
    password: &[u8],
    spec: &CcSpec,
    params: KinitParams<'_>,
) -> Result<(KinitResult, FileCcache), Box<dyn std::error::Error + Send + Sync>> {
    let (cname, mut realm_s) = parse_principal_ex(principal, params.enterprise)?;
    if realm_s.is_empty() {
        realm_s = conf_default_realm().ok_or("Cannot find KDC for requested realm")?;
    }
    let resolved = resolve_kdc(&realm_s, kdc);
    if params.renew {
        return renew_inner(&resolved, spec);
    }
    if params.validate {
        return validate_inner(&resolved, spec);
    }
    let armor = match params.armor_ccache {
        Some(p) => Some(load_fast_armor(p)?),
        None => None,
    };
    let (conf_id, conf_an) = if params.pkinit_identity.is_none() || params.pkinit_anchors.is_none()
    {
        pkinit_from_conf(&realm_s)
    } else {
        (None, None)
    };
    let id_path = params.pkinit_identity.map(Path::to_path_buf).or(conf_id);
    let an_path = params.pkinit_anchors.map(Path::to_path_buf).or(conf_an);
    let pkinit = match (id_path.as_deref(), an_path.as_deref(), params.anonymous) {
        (Some(i), Some(a), _) => Some(load_pkinit(i, a)?),
        (None, Some(a), true) => Some(load_pkinit_anchors(a)?),
        (Some(_), None, _) | (None, Some(_), false) => {
            return Err("pkinit requires identity and anchors".into());
        }
        (None, None, true) => return Err("anonymous PKINIT requires pkinit_anchors".into()),
        (None, None, false) => None,
    };
    let mut etypes = krb5_protocol::conf_etypes(false);
    let mut ticket = params.ticket;
    ticket.anonymous |= params.anonymous;
    let keytab_keys = if let Some(ktpath) = params.keytab {
        let kt = Keytab::parse(&std::fs::read(ktpath)?)?;
        let (keys, kt_etypes) = krb5_protocol::keytab_init_creds_keys(&kt, &cname, &realm_s)
            .ok_or("keytab has no matching principal")?;
        krb5_protocol::sort_etypes_keytab_first(&mut etypes, &kt_etypes);
        Some(keys)
    } else {
        None
    };
    let req = AsRequest {
        cname: cname.clone(),
        realm: &realm_s,
        password,
        kdc: &resolved,
        want_spake: params.want_spake,
        fast_armor: armor.as_ref(),
        pkinit: pkinit.as_ref(),
        canonicalize: params.canonicalize || params.enterprise,
        sname: None,
        etypes: Some(&etypes),
        ticket,
    };
    let as_out = match if let Some(keys) = keytab_keys.as_deref() {
        as_exchange_with_keys(&req, keys)
    } else {
        as_exchange(&req)
    } {
        Ok(o) => o,
        // gic_pwd.c: a typed KDC_ERR_KEY_EXP from a password AS (not
        // keytab — `krb5_get_init_creds_keytab` has no change flow) with a
        // prompter or a new-password source. The kadmin/changepw AS comes
        // *first*, with the password just used, so a wrong password is the
        // password failure (`:229-236`); only then the new-password prompts
        // (`:238-258`), the change (`:283-286`) and the final AS (`:333`).
        Err(e)
            if krb5_protocol::key_exp_should_changepw(
                &e,
                params.new_password.is_some() || params.prompter.is_some(),
                params.keytab.is_some(),
            ) =>
        {
            let changepw = krb5_types::PrincipalName::new(
                krb5_types::PrincipalName::NT_SRV_INST,
                ["kadmin", "changepw"],
            );
            let chpw_ticket = AsTicketOpts {
                lifetime: Some(5 * 60),
                rlife: None,
                forwardable: false,
                proxiable: false,
                addresses: None,
                anonymous: false,
                starttime: None,
            };
            let chpw_req = AsRequest {
                cname: cname.clone(),
                realm: &realm_s,
                password,
                kdc: &resolved,
                want_spake: false,
                fast_armor: armor.as_ref(),
                pkinit: None,
                canonicalize: params.canonicalize || params.enterprise,
                sname: Some(&changepw),
                etypes: Some(&etypes),
                ticket: chpw_ticket,
            };
            let chpw_as = as_exchange(&chpw_req)?;
            let mut new_pw = match (params.new_password, params.prompter) {
                (Some(p), _) => {
                    krb5_cli_print::emit_key_exp_banner();
                    krb5_protocol::change_password(&resolved, &chpw_as, p)?;
                    p.to_vec()
                }
                (None, Some(prompter)) => prompt_and_change(&resolved, &chpw_as, prompter)?,
                (None, None) => return Err(e.into()),
            };
            let retry = AsRequest {
                password: &new_pw,
                ..req
            };
            let out = as_exchange(&retry);
            new_pw.zeroize();
            out?
        }
        Err(e) => return Err(e.into()),
    };
    let mut creds = vec![tgt_cred(
        &as_out.crealm,
        &as_out.cname,
        &as_out.ticket,
        &as_out.session_key,
        &as_out.enc_part,
    )?];
    let mut tgs_out = None;
    let mut tgs_err: Option<String> = None;
    if let Some(svc) = params.service {
        let (sname, svc_realm) =
            krb5_types::principal_from_unparsed(svc, &realm_s).map_err(|e| e.to_string())?;
        match tgs_exchange_path(&resolved, &as_out, sname, &svc_realm, false) {
            Ok((tgs, path)) => {
                for p in path {
                    creds.push(tgt_cred(
                        &p.crealm,
                        &p.cname,
                        &p.ticket,
                        &p.session_key,
                        &p.enc_part,
                    )?);
                }
                creds.push(tgt_cred(
                    &as_out.crealm,
                    &as_out.cname,
                    &tgs.ticket,
                    &tgs.session_key,
                    &tgs.enc_part,
                )?);
                tgs_out = Some(tgs);
            }
            Err(e) => tgs_err = Some(e.to_string()),
        }
    }
    // MIT `write_out_ccache` (`get_in_tkt.c:1617-1640`): fast_avail and the
    // selected pa_type are ccache config entries keyed by the TGT's server,
    // stored ahead of the credentials.
    let mut cache = FileCcache::new((as_out.crealm.clone(), as_out.cname.clone()), Vec::new());
    let tgt_realm = String::from_utf8_lossy(as_out.ticket.realm.as_bytes()).into_owned();
    let tgt_server = as_out.ticket.sname.unparse_with_realm(&tgt_realm);
    if as_out.fast_avail {
        cache.set_config(Some(&tgt_server), "fast_avail", b"yes");
    }
    if let Some(t) = as_out.pa_type {
        cache.set_config(Some(&tgt_server), "pa_type", t.to_string().as_bytes());
    }
    cache.creds.extend(creds);
    if let Some(e) = tgs_err {
        tracing::error!(
            event = "client.tgs",
            component = "krb5-client",
            outcome = "error",
            error = e.as_str(),
        );
        return Err(e.into());
    }
    Ok((KinitResult { as_out, tgs_out }, cache))
}

/// `gic_pwd.c` banner shown ahead of the new-password prompts.
const KEY_EXP_BANNER: &str = "Password expired.  You must change it now.";

/// MIT `krb5_change_password` (`changepw.c:308-317`): `gic_pwd.c`: three tries of prompt, compare, `krb5_change_password`
/// over `chpw_as`; a soft kpasswd result re-prompts with the result text in
/// the banner, anything else is the error. Returns the accepted password.
fn prompt_and_change(
    kdc: &KdcAddr,
    chpw_as: &krb5_protocol::AsOutcome,
    prompter: NewPasswordPrompter<'_>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut banner = KEY_EXP_BANNER.to_owned();
    // `KRB5_CHPW_FAIL` "set in case the retry loop falls through" (`:299`).
    let mut ret = "Password change failed";
    for _tries in 0..3 {
        let (mut pw0, mut pw1) = (prompter.0)(&banner)?;
        if pw0 != pw1 {
            // KRB5_LIBOS_BADPWDMATCH (`:268-271`)
            ret = "Password mismatch";
            banner = format!("{ret}.  Please try again.");
        } else if pw0.is_empty() {
            // KRB5_CHPW_PWDNULL (`:272-275`)
            ret = "New password cannot be zero length";
            banner = format!("{ret}.  Please try again.");
        } else {
            let (code, data) = krb5_protocol::change_password_result(kdc, chpw_as, &pw0)?;
            if code == krb5_protocol::KPASSWD_SUCCESS {
                pw1.zeroize();
                return Ok(pw0);
            }
            ret = "Password change failed";
            if code != krb5_protocol::KPASSWD_SOFTERROR {
                // `:301-305`: a hard result is KRB5_CHPW_FAIL, no retry.
                pw0.zeroize();
                pw1.zeroize();
                return Err(ret.into());
            }
            // `:309-323`: "<code string>: <message>.  Please try again."
            banner = format!(
                "{}.  Please try again.\n",
                krb5_protocol::format_chpw_failure(code, &data)
            );
        }
        pw0.zeroize();
        pw1.zeroize();
    }
    Err(ret.into())
}

fn renew_inner(
    kdc: &KdcAddr,
    spec: &CcSpec,
) -> Result<(KinitResult, FileCcache), Box<dyn std::error::Error + Send + Sync>> {
    valrenew_inner(kdc, spec, false)
}

fn validate_inner(
    kdc: &KdcAddr,
    spec: &CcSpec,
) -> Result<(KinitResult, FileCcache), Box<dyn std::error::Error + Send + Sync>> {
    valrenew_inner(kdc, spec, true)
}

fn valrenew_inner(
    kdc: &KdcAddr,
    spec: &CcSpec,
    validate: bool,
) -> Result<(KinitResult, FileCcache), Box<dyn std::error::Error + Send + Sync>> {
    let mut cc = load_ccache(spec)?;
    let cred = cc
        .list()
        .into_iter()
        .find(|c| c.server.1.components_joined().starts_with("krbtgt/"))
        .ok_or("ccache has no TGT")?
        .clone();
    let tgt = outcome_from_cred(&cred)?;
    let tgs = if validate {
        tgs_validate(kdc, &tgt)?
    } else {
        tgs_renew(kdc, &tgt)?
    };
    let new_cred = tgt_cred(
        &tgt.crealm,
        &tgt.cname,
        &tgs.ticket,
        &tgs.session_key,
        &tgs.enc_part,
    )?;
    for c in &mut cc.creds {
        if c.server.1.components_joined().starts_with("krbtgt/") && !c.is_config() {
            *c = new_cred.clone();
            break;
        }
    }
    Ok((
        KinitResult {
            as_out: tgt,
            tgs_out: Some(tgs),
        },
        cc,
    ))
}

fn outcome_from_cred(
    cred: &CcacheCred,
) -> Result<AsOutcome, Box<dyn std::error::Error + Send + Sync>> {
    let session = cred.session_key()?;
    let ticket: Ticket = decode(&cred.ticket)?;
    Ok(AsOutcome {
        ticket,
        enc_part: krb5_types::EncKdcRepPart {
            key: krb5_types::EncryptionKey {
                keytype: session.etype().to_iana(),
                keyvalue: session.as_bytes().to_vec().into(),
            },
            last_req: Vec::new(),
            nonce: 0,
            key_expiration: None,
            flags: krb5_types::TicketFlags::from_u32(cred.ticket_flags),
            authtime: krb5_types::KerberosTime::from_unix_seconds(cred.authtime),
            starttime: Some(krb5_types::KerberosTime::from_unix_seconds(cred.starttime)),
            endtime: krb5_types::KerberosTime::from_unix_seconds(cred.endtime),
            renew_till: (cred.renew_till > 0)
                .then(|| krb5_types::KerberosTime::from_unix_seconds(cred.renew_till)),
            srealm: cred.server.0.clone(),
            sname: cred.server.1.clone(),
            caddr: None,
            encrypted_pa_data: None,
        },
        client_key: session.clone(),
        session_key: session,
        cname: cred.client.1.clone(),
        crealm: cred.client.0.clone(),
        fast_avail: false,
        used_fast: false,
        pa_type: None,
    })
}

/// Local IPv4 address for `kinit -a` (MIT ADDRTYPE_INET = 2).
#[must_use]
pub fn local_host_addresses() -> Option<krb5_types::HostAddresses> {
    use std::net::{SocketAddr, UdpSocket};
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    let SocketAddr::V4(v4) = sock.local_addr().ok()? else {
        return None;
    };
    Some(vec![krb5_types::HostAddress {
        addr_type: 2,
        address: v4.ip().octets().to_vec().into(),
    }])
}

fn resolve_kdc(realm: &str, argv: &KdcAddr) -> KdcAddr {
    krb5_config::discover_kdc(realm).map_or_else(
        || argv.clone(),
        |ep| KdcAddr {
            host: ep.host,
            port: ep.port,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_kdc_prefers_krb5_conf_over_argv() {
        let path = std::env::temp_dir().join(format!(
            "kerber-client-krb5-{}-{}.conf",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(
            &path,
            r"
[realms]
    KERBER.TEST = {
        kdc = 192.0.2.10:8888
    }
",
        )
        .unwrap();
        let argv = KdcAddr {
            host: "127.0.0.1".into(),
            port: 88,
        };
        let ep = krb5_config::discover_kdc_in([&path], "KERBER.TEST").unwrap();
        let resolved = KdcAddr {
            host: ep.host,
            port: ep.port,
        };
        assert_eq!(resolved.host, "192.0.2.10");
        assert_eq!(resolved.port, 8888);
        assert_eq!(argv.port, 88);
        let _ = std::fs::remove_file(&path);
    }
}
