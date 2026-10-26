#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::path::Path;

use krb5_asn1::decode;
use krb5_config::{CcSpec, ClientContext, Krb5Conf};
use krb5_protocol::{
    AsOutcome, AsPrompt, AsRequest, AsTicketOpts, FastArmor, KdcAddr, KeytabFailure, Pkinit,
    PkinitClient, PkinitFailure, PreauthPrompt, TgsOutcome, as_exchange, as_exchange_defer_fast,
    as_exchange_interactive, as_exchange_with_keys, as_exchange_with_keys_defer_fast,
    as_exchange_with_unreadable_keytab, as_exchange_with_unreadable_keytab_defer_fast,
    dir_cache_path, dir_cache_path_for_store, kcm_destroy, kcm_load, kcm_store,
    kcm_store_keep_default, memory_destroy, memory_retrieve, memory_store, parse_principal_ex,
    read_keytab_file, tgs_exchange_path,
};
use krb5_types::Ticket;
use krb5_types::pkinit::{CertMatchError, IdentityError};
use zeroize::{Zeroize, Zeroizing};

pub use krb5_protocol::{
    CcacheCred, CcacheKeyblock, FileCcache, Keytab, KeytabEntry, parse_principal, realm, tgt_cred,
};
pub use krb5_protocol::{
    ClPreauth, clear_thread_clpreauth, register_clpreauth, set_thread_clpreauth,
};
pub use krb5_protocol::{Error as ProtocolError, KDC_PORT};

pub mod ccache {
    pub use krb5_protocol::{
        CcacheCred, CcacheKeyblock, FileCcache, parse_principal, realm, tgt_cred,
    };
}

pub mod keytab {
    pub use krb5_protocol::{Keytab, KeytabEntry};
}

pub mod ccol;
pub mod cli;
pub mod creds;
pub mod errmsg;
pub mod trace;

use errmsg::{Code, Krb5Error};

#[must_use]
pub fn cache_file_path(spec: &CcSpec) -> Option<std::path::PathBuf> {
    match spec {
        CcSpec::File(p) => Some(p.clone()),
        CcSpec::Dir(r) => dir_read_path(r).ok(),
        CcSpec::Memory(_) | CcSpec::Kcm(_) => None,
    }
}

pub fn dir_read_path(residual: &str) -> std::io::Result<std::path::PathBuf> {
    let dir = Path::new(residual);
    if !residual.starts_with(':')
        && std::fs::symlink_metadata(dir).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    {
        return Ok(dir.join("tkt"));
    }
    dir_cache_path(residual)
}

// MIT: `kcm_get_princ` (cc_kcm.c:933-953)
#[must_use]
pub fn cache_read_error(
    ctx: &ClientContext,
    spec: &CcSpec,
    e: &(dyn std::error::Error + Send + Sync + 'static),
) -> Krb5Error {
    let io = e.downcast_ref::<std::io::Error>();
    let missing = io.is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound);
    match spec {
        CcSpec::Kcm(_) if io.is_some_and(krb5_protocol::kcm_no_server) => {
            Krb5Error::of(Code::KcmNoServer)
        }
        CcSpec::Kcm(n) if missing => {
            let name = if n.is_empty() {
                krb5_protocol::kcm_primary_name(&ctx.profile).unwrap_or_default()
            } else {
                n.clone()
            };
            Krb5Error::new(
                Code::FccNofile,
                format!("Credentials cache 'KCM:{name}' not found"),
            )
        }
        CcSpec::Kcm(_) => io.map_or_else(
            || Krb5Error::new(Code::Other, e.to_string()),
            Krb5Error::from_kcm,
        ),
        CcSpec::Memory(_) if missing => Krb5Error::of(Code::FccNofile),
        _ => match (io, cache_file_path(spec)) {
            (Some(io), Some(path)) => Krb5Error::from_file_cache(io, &path),
            (Some(io), None) if missing => Krb5Error::new(Code::FccNofile, io.to_string()),
            _ if e.to_string() == "No credentials cache found" => Krb5Error::of(Code::FccNofile),
            _ => Krb5Error::new(Code::Other, e.to_string()),
        },
    }
}

// MIT: `os_init_paths` (init_os_ctx.c:389-391)
// no file that opens is an empty profile.
#[allow(
    clippy::disallowed_methods,
    reason = "MIT krb5_init_context: the program's one read of its profile and environment"
)]
pub fn init_context() -> Result<ClientContext, Krb5Error> {
    let ctx = ClientContext::from_env().map_err(|e| match e {
        krb5_config::Error::Io(e) => Krb5Error::from_os(&e),
        krb5_config::Error::Profile(p, _) => Krb5Error::of(Code::Profile(p)),
        e => Krb5Error::new(Code::Other, e.to_string()),
    })?;
    // MIT: `krb5_init_context_profile` (lib/krb5/krb/init_ctx.c:209-217)
    krb5_protocol::trace::init();
    Ok(ctx)
}

pub const DEFKTNAME: &str = "FILE:/etc/krb5.keytab";
pub const DEFCKTNAME: &str = "FILE:/var/kerberos/krb5/user/%{euid}/client.keytab";

// MIT: `kt_default_name` (ktdefname.c:35-57)
#[must_use]
pub fn kt_default_name(ctx: &ClientContext) -> String {
    if let Some(v) = ctx.ktname() {
        return v;
    }
    expand_name(
        ctx.profile
            .default_keytab_name
            .as_deref()
            .unwrap_or(DEFKTNAME),
    )
}

// MIT k5_kt_client_default_name; see docs/parity/b1-client.md
#[must_use]
pub fn kt_client_default_name(ctx: &ClientContext) -> String {
    if let Some(v) = ctx.client_ktname() {
        return v;
    }
    let conf = ctx.profile.default_client_keytab_name.as_deref();
    expand_name(conf.unwrap_or(DEFCKTNAME))
}

fn expand_name(name: &str) -> String {
    krb5_config::expand_ccache_params(name).unwrap_or_else(|_| name.to_owned())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeytabName {
    File(std::path::PathBuf),
    Memory(String),
}

impl KeytabName {
    #[must_use]
    pub fn full_name(&self) -> String {
        match self {
            Self::File(p) => format!("FILE:{}", p.display()),
            Self::Memory(n) => format!("MEMORY:{n}"),
        }
    }
}

// MIT: `krb5_kt_resolve` (ktbase.c:151-209)
pub fn kt_resolve(name: &str) -> Result<KeytabName, Krb5Error> {
    let Some((pfx, resid)) = name.split_once(':') else {
        return Ok(KeytabName::File(name.into()));
    };
    if name.starts_with('/') || (pfx.len() == 1 && pfx.bytes().all(|b| b.is_ascii_alphabetic())) {
        return Ok(KeytabName::File(name.into()));
    }
    match pfx {
        "FILE" | "WRFILE" => Ok(KeytabName::File(resid.into())),
        "MEMORY" => Ok(KeytabName::Memory(resid.to_owned())),
        _ => Err(Krb5Error::of(Code::KtUnknownType)),
    }
}

#[must_use]
pub fn keytab_read_error(e: &std::io::Error, path: &str) -> Krb5Error {
    if e.kind() == std::io::ErrorKind::NotFound {
        Krb5Error::new(Code::Enoent, format!("Key table file '{path}' not found"))
    } else {
        Krb5Error::new(Code::Other, e.to_string())
    }
}

#[derive(Debug)]
pub struct ArmorCcache {
    pub name: String,
    pub spec: CcSpec,
}

#[derive(Clone, Debug, Default)]
pub struct KinitParams<'a> {
    pub service: Option<&'a str>,
    pub in_tkt_service: Option<&'a str>,
    pub want_spake: bool,
    pub armor_ccache: Option<&'a ArmorCcache>,
    pub pkinit_identity: Option<&'a Path>,
    pub pkinit_anchors: &'a [String],
    pub enterprise: bool,
    pub keytab: Option<&'a Path>,
    pub ticket: AsTicketOpts,
    pub in_ccache: Option<InputCcache<'a>>,
    pub anonymous: bool,
    pub canonicalize: bool,
    pub new_password: Option<&'a [u8]>,
    pub prompter: Option<NewPasswordPrompter<'a>>,
    pub key_exp_notice: Option<KeyExpNotice<'a>>,
    pub preauth_prompter: Option<PreauthPrompter<'a>>,
}

#[derive(Clone, Copy)]
pub struct InputCcache<'a>(pub &'a FileCcache);

impl std::fmt::Debug for InputCcache<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InputCcache")
    }
}

fn allowed_preauth_type(
    in_ccache: Option<InputCcache<'_>>,
    server: &krb5_types::PrincipalName,
    realm: &str,
) -> Option<i32> {
    let value = in_ccache?
        .0
        .get_config(Some(&server.unparse_with_realm(realm)), "pa_type")?;
    let text = String::from_utf8_lossy(value);
    let t = text.trim_start_matches(|c: char| c.is_ascii_whitespace() || c == '\u{000b}');
    let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n = t.parse::<i64>().ok()?;
    i32::try_from(n).ok().filter(|&n| n != 0)
}

// MIT read_cc_config_in_data; see docs/parity/b1-client-preauth.md
fn pa_config_in(
    in_ccache: Option<InputCcache<'_>>,
    server: &krb5_types::PrincipalName,
    realm: &str,
) -> Option<Vec<u8>> {
    let value = in_ccache?
        .0
        .get_config(Some(&server.unparse_with_realm(realm)), "pa_config_data")?;
    Some(value.to_vec())
}

#[derive(Clone, Copy)]
pub struct NewPasswordPrompter<'a>(pub &'a (dyn Fn(&str) -> PromptReply + 'a));

// MIT doprompt; see docs/parity/a3-preauth.md
pub type PreauthPromptFn<'a> =
    dyn Fn(&PreauthPrompt<'_>) -> Result<Zeroizing<Vec<u8>>, krb5_cli::PromptError> + 'a;

#[derive(Clone, Copy)]
pub struct PreauthPrompter<'a>(pub &'a PreauthPromptFn<'a>);

impl std::fmt::Debug for PreauthPrompter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreauthPrompter")
    }
}

pub type PromptReply = Result<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>), String>;

impl std::fmt::Debug for NewPasswordPrompter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NewPasswordPrompter")
    }
}

#[derive(Clone, Copy)]
pub struct KeyExpNotice<'a>(pub &'a (dyn Fn(&str) + 'a));

impl std::fmt::Debug for KeyExpNotice<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyExpNotice")
    }
}

pub struct KinitResult {
    pub as_out: AsOutcome,
    pub tgs_out: Option<TgsOutcome>,
}

pub fn kinit(
    ctx: &ClientContext,
    kdc: &KdcAddr,
    principal: &str,
    password: &mut [u8],
    ccache_path: impl AsRef<Path>,
    service: Option<&str>,
) -> Result<KinitResult, Box<dyn std::error::Error + Send + Sync>> {
    kinit_ex(
        ctx,
        kdc,
        principal,
        password,
        ccache_path,
        &InitCredsOpt {
            service,
            want_spake: false,
            armor_ccache: None,
            pkinit_identity: None,
            pkinit_anchors: &[],
            enterprise: false,
        },
    )
}

// MIT: `krb5_get_init_creds_opt` (include/krb5/krb5.hin:6839-6851)
// the public option block.
#[derive(Clone, Copy)]
pub struct InitCredsOpt<'a> {
    pub service: Option<&'a str>,
    pub want_spake: bool,
    pub armor_ccache: Option<&'a ArmorCcache>,
    pub pkinit_identity: Option<&'a Path>,
    pub pkinit_anchors: &'a [String],
    pub enterprise: bool,
}

pub fn kinit_ex(
    ctx: &ClientContext,
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
    kinit_with(ctx, kdc, principal, password, &spec, params)
}

pub fn kinit_to_spec(
    ctx: &ClientContext,
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
        ctx,
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

// MIT write_out_ccache; see docs/parity/b1-client-preauth.md
pub fn kinit_with(
    ctx: &ClientContext,
    kdc: &KdcAddr,
    principal: &str,
    password: &mut [u8],
    spec: &CcSpec,
    params: KinitParams<'_>,
) -> Result<KinitResult, Box<dyn std::error::Error + Send + Sync>> {
    let mut lazy = LazyPassword {
        given: password,
        prompt: None,
        read: None,
        failed: None,
        otp: params.preauth_prompter,
    };
    let built = kinit_inner(ctx, kdc, principal, &mut lazy, params);
    let result = match built {
        Ok((r, cc)) => write_out_ccache(ctx, spec, cc).map(|()| r),
        Err(e) => Err(e),
    };
    // The kinit password buffer and the two new-password replies are wiped.
    password.zeroize();
    result
}

fn write_out_ccache(
    ctx: &ClientContext,
    spec: &CcSpec,
    cc: FileCcache,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if krb5_protocol::trace::enabled() {
        krb5_protocol::trace::write_out_ccache(&trace::ccname(ctx, spec), &cc);
    }
    store_ccache_keep_default(ctx, spec, cc).map_err(|e| {
        let e = store_error(e.as_ref());
        Krb5Error::new(
            e.code,
            format!("Failed to store credentials: {}", e.message),
        )
        .into()
    })
}

#[must_use]
pub fn store_error(e: &(dyn std::error::Error + Send + Sync + 'static)) -> Krb5Error {
    match e.downcast_ref::<std::io::Error>() {
        Some(io) => Krb5Error::from_cache_write(io),
        None => Krb5Error::new(Code::Other, e.to_string()),
    }
}

// MIT: `change_set_password` (changepw.c:258-266)
// MIT: `k5_sendto` (sendto_kdc.c:1602-1604)
// That code has no message of its own, so it prints its table text, not "Cannot contact any KDC".
fn chpw_error(e: ProtocolError, realm: &str) -> Box<dyn std::error::Error + Send + Sync> {
    match &e {
        ProtocolError::Io { .. } => Box::new(Krb5Error::of(Code::KdcUnreach)),
        ProtocolError::KrbError { .. } => Box::new(Krb5Error::from_protocol(&e, realm)),
        ProtocolError::RealmUnknown => Box::new(Krb5Error::new(
            Code::RealmUnknown,
            format!("Cannot find KDC for realm \"{realm}\""),
        )),
        _ => Box::new(e),
    }
}

pub fn kinit_prompted(
    ctx: &ClientContext,
    kdc: &KdcAddr,
    principal: &str,
    prompt: &mut dyn FnMut() -> Result<Zeroizing<Vec<u8>>, Krb5Error>,
    spec: &CcSpec,
    params: KinitParams<'_>,
) -> Result<KinitResult, Box<dyn std::error::Error + Send + Sync>> {
    let mut lazy = LazyPassword {
        given: b"",
        prompt: Some(prompt),
        read: None,
        failed: None,
        otp: params.preauth_prompter,
    };
    match kinit_inner(ctx, kdc, principal, &mut lazy, params) {
        Ok((r, cc)) => write_out_ccache(ctx, spec, cc).map(|()| r),
        Err(e) => Err(e),
    }
}

struct LazyPassword<'p> {
    given: &'p [u8],
    prompt: Option<&'p mut dyn FnMut() -> Result<Zeroizing<Vec<u8>>, Krb5Error>>,
    read: Option<Zeroizing<Vec<u8>>>,
    failed: Option<Krb5Error>,
    otp: Option<PreauthPrompter<'p>>,
}

struct KinitPrompt<'a, 'p>(&'a mut LazyPassword<'p>);

impl AsPrompt for KinitPrompt<'_, '_> {
    fn password(&mut self) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        self.0.get()
    }

    fn preauth(&mut self, p: &PreauthPrompt<'_>) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        let Some(otp) = self.0.otp else {
            return Err(ProtocolError::File(std::io::Error::other(
                "Cannot read password",
            )));
        };
        (otp.0)(p).map_err(|e| {
            let kind = if e == krb5_cli::PromptError::Interrupted {
                std::io::ErrorKind::Interrupted
            } else {
                std::io::ErrorKind::Other
            };
            self.0.note_failed(
                Krb5Error::new(Code::Other, e.to_string()),
                kind == std::io::ErrorKind::Interrupted,
            );
            ProtocolError::File(std::io::Error::new(kind, e.to_string()))
        })
    }
}

impl LazyPassword<'_> {
    fn note_failed(&mut self, e: Krb5Error, interrupted: bool) {
        if interrupted {
            self.failed = Some(e);
        } else {
            self.failed.get_or_insert(e);
        }
    }

    fn get(&mut self) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        if let Some(p) = &self.read {
            return Ok(p.clone());
        }
        let Some(prompt) = self.prompt.as_mut() else {
            return Ok(Zeroizing::new(self.given.to_vec()));
        };
        match prompt() {
            Ok(p) => {
                self.read = Some(p.clone());
                Ok(p)
            }
            Err(e) => {
                let kind = if e.code == Code::PwdInterrupted {
                    std::io::ErrorKind::Interrupted
                } else {
                    std::io::ErrorKind::Other
                };
                let io = std::io::Error::new(kind, e.to_string());
                self.note_failed(e, kind == std::io::ErrorKind::Interrupted);
                Err(ProtocolError::File(io))
            }
        }
    }

    fn as_exchange(
        &mut self,
        req: &AsRequest<'_>,
    ) -> Result<Result<AsOutcome, ProtocolError>, Krb5Error> {
        let out = as_exchange_interactive(req, &mut KinitPrompt(self), false);
        self.finish(out)
    }

    fn as_exchange_defer(
        &mut self,
        req: &AsRequest<'_>,
    ) -> Result<Result<AsOutcome, ProtocolError>, Krb5Error> {
        let out = as_exchange_interactive(req, &mut KinitPrompt(self), true);
        self.finish(out)
    }

    fn finish(
        &mut self,
        out: Result<AsOutcome, ProtocolError>,
    ) -> Result<Result<AsOutcome, ProtocolError>, Krb5Error> {
        match (self.failed.take(), out) {
            (Some(e), Err(ProtocolError::File(_))) => Err(e),
            (_, out) => Ok(out),
        }
    }
}

#[must_use]
pub fn mit_error_code(e: &(dyn std::error::Error + Send + Sync + 'static)) -> Option<i32> {
    match e.downcast_ref::<krb5_protocol::Error>() {
        Some(krb5_protocol::Error::KrbError { code, .. }) => Some(*code),
        Some(krb5_protocol::Error::ReplyIntegrity) => Some(krb5_types::err::BAD_INTEGRITY),
        _ => None,
    }
}

pub fn load_ccache(
    ctx: &ClientContext,
    spec: &CcSpec,
) -> Result<FileCcache, Box<dyn std::error::Error + Send + Sync>> {
    match spec {
        CcSpec::File(p) => Ok(FileCcache::parse(&krb5_protocol::read_cache_file(p)?)?),
        CcSpec::Memory(n) => memory_retrieve(n).ok_or_else(|| "No credentials cache found".into()),
        CcSpec::Dir(r) => {
            let p = dir_read_path(r)?;
            Ok(FileCcache::parse(&krb5_protocol::read_cache_file(&p)?)?)
        }
        CcSpec::Kcm(n) => kcm_load(&ctx.profile, n).map_err(Into::into),
    }
}

pub fn store_ccache(
    ctx: &ClientContext,
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
        CcSpec::Kcm(n) => kcm_store(&ctx.profile, n, &cc).map_err(Into::into),
    }
}

pub fn store_ccache_keep_default(
    ctx: &ClientContext,
    spec: &CcSpec,
    cc: FileCcache,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match spec {
        CcSpec::Kcm(n) => kcm_store_keep_default(&ctx.profile, n, &cc).map_err(Into::into),
        _ => store_ccache(ctx, spec, cc),
    }
}

pub fn destroy_ccache(
    ctx: &ClientContext,
    spec: &CcSpec,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
            let p = dir_read_path(r)?;
            krb5_protocol::destroy_secret_file(&p).map_err(Into::into)
        }
        CcSpec::Kcm(n) => kcm_destroy(&ctx.profile, n).map_err(Into::into),
    }
}

// MIT: `fast_armor_ap_request` (lib/krb5/krb/fast.c:52-108)
// the armor cache's TGT is read when the request is armored.
fn load_fast_armor(
    ctx: &ClientContext,
    spec: &CcSpec,
) -> Result<FastArmor, Box<dyn std::error::Error + Send + Sync>> {
    let cc = load_ccache(ctx, spec).map_err(|e| cache_read_error(ctx, spec, e.as_ref()))?;
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

fn conf_default_realm(ctx: &ClientContext) -> Option<String> {
    ctx.profile.default_realm.clone()
}

pub enum ClientPkinit {
    Ready(PkinitClient),
    Failed(PkinitFailure),
}

impl ClientPkinit {
    #[must_use]
    pub fn arg(&self) -> Pkinit<'_> {
        match self {
            Self::Ready(c) => Pkinit::Client(c),
            Self::Failed(f) => Pkinit::Failed(f),
        }
    }
}

// MIT: `pkinit_identity_initialize` (plugins/preauth/pkinit/pkinit_identity.c:509-562)
// `X509_user_identity`, else each `pkinit_identities` value until one loads; none is "No user identity options specified".
// MIT pkinit_client_process; see docs/parity/b1-client-preauth.md
// MIT pkinit_identity_prompt; see docs/parity/a3-preauth.md
fn load_pkinit(
    identities: &[String],
    anchors: &[String],
    pool: &[String],
    rules: &[String],
    opts: PkinitOpts,
) -> Result<ClientPkinit, Box<dyn std::error::Error + Send + Sync>> {
    let mut found = Err(IdentityError {
        code: 22,
        text: "Invalid argument".into(),
    });
    for value in identities {
        found = krb5_types::pkinit::load_identities(value);
        if found.is_ok() {
            break;
        }
    }
    let no_identity = found.is_err();
    let fail = |code, text, prompted| {
        Ok(ClientPkinit::Failed(PkinitFailure {
            code,
            text,
            no_identity,
            prompted,
        }))
    };
    let base = krb5_protocol::trace::ERROR_TABLE_BASE_KRB5;
    if anchors.is_empty() {
        return fail(base + 210, "No pkinit_anchors supplied".into(), false);
    }
    let creds = match found {
        Ok(c) => c,
        Err(e) => return fail(e.code, e.text, true),
    };
    let certs: Vec<&[u8]> = creds.iter().map(|c| c.cert.as_slice()).collect();
    let pick = match krb5_types::pkinit::select_cert(
        rules,
        &certs,
        &mut krb5_protocol::trace::pkinit_match,
    ) {
        Ok(i) => i,
        Err(e @ CertMatchError::Code(c)) => return fail(i64::from(c), e.to_string(), true),
        Err(e) => return fail(base + 24, e.to_string(), true),
    };
    let chosen = creds.get(pick).ok_or("pkinit identity")?;
    let (anchors, pool) = match (ca_certs(anchors), ca_certs(pool)) {
        (Ok(anchors), Ok(pool)) => (anchors, pool),
        (Err(text), _) | (_, Err(text)) => return fail(base + 24, text, true),
    };
    if anchors.is_empty() {
        return fail(base + 24, NO_TRUSTED_CA.into(), false);
    }
    Ok(ClientPkinit::Ready(PkinitClient {
        cert: chosen.cert.clone(),
        key: chosen.key().clone(),
        anchors,
        pool,
        dh_min_bits: opts.dh_min_bits,
        kdc_hostnames: opts.kdc_hostnames,
        eku_checking: opts.eku_checking,
    }))
}

// MIT: `create_krb5_trustedCertifiers` (pkinit_crypto_openssl.c:5396-5397)
// with no anchor loaded no request is made.
// MIT pa_pkinit_gen_req; see docs/parity/b1-client-preauth.md
const NO_TRUSTED_CA: &str = "Preauthentication failed";

// MIT load_cas_and_crls; see docs/parity/b1-client-preauth.md
fn ca_certs(values: &[String]) -> Result<Vec<Vec<u8>>, String> {
    let mut certs = Vec::new();
    for value in values {
        for cert in krb5_types::pkinit::load_ca_certs(value)? {
            if !certs.contains(&cert) {
                certs.push(cert);
            }
        }
    }
    Ok(certs)
}

fn load_pkinit_anchors(
    anchors: &[String],
    pool: &[String],
    opts: PkinitOpts,
) -> Result<PkinitClient, Box<dyn std::error::Error + Send + Sync>> {
    Ok(PkinitClient {
        cert: Vec::new(),
        key: krb5_types::pkinit::IdentityKey::P256(Zeroizing::new([0u8; 32])),
        anchors: ca_certs(anchors)?,
        pool: ca_certs(pool)?,
        dh_min_bits: opts.dh_min_bits,
        kdc_hostnames: opts.kdc_hostnames,
        eku_checking: opts.eku_checking,
    })
}

struct PkinitConf {
    identities: Vec<String>,
    anchors: Vec<String>,
    pool: Vec<String>,
    rules: Vec<String>,
    opts: PkinitOpts,
}

struct PkinitOpts {
    dh_min_bits: Option<String>,
    kdc_hostnames: Vec<String>,
    eku_checking: Option<String>,
}

// MIT pkinit_client_profile; see docs/parity/b1-client-preauth.md
fn pkinit_from_conf(conf: &Krb5Conf, realm: &str) -> PkinitConf {
    let strings = |option| conf.pkinit_libdefault_strings(realm, option);
    PkinitConf {
        identities: strings("pkinit_identities"),
        anchors: strings("pkinit_anchors"),
        pool: strings("pkinit_pool"),
        rules: strings("pkinit_cert_match"),
        opts: PkinitOpts {
            dh_min_bits: strings("pkinit_dh_min_bits").into_iter().next(),
            kdc_hostnames: strings("pkinit_kdc_hostname"),
            eku_checking: strings("pkinit_eku_checking").into_iter().next(),
        },
    }
}

pub fn profile_pkinit(
    conf: &Krb5Conf,
    realm: &str,
) -> Result<ClientPkinit, Box<dyn std::error::Error + Send + Sync>> {
    let pk = pkinit_from_conf(conf, realm);
    load_pkinit(&pk.identities, &pk.anchors, &pk.pool, &pk.rules, pk.opts)
}

// MIT krb5int_fast_as_armor; see docs/parity/b1-client-preauth.md
fn armor_build_error(err: &(dyn std::error::Error + Send + Sync + 'static)) -> Krb5Error {
    if let Some(k) = err.downcast_ref::<Krb5Error>() {
        return Krb5Error::new(
            k.code,
            format!("Error constructing AP-REQ armor: {}", k.message),
        );
    }
    Krb5Error::new(
        Code::Other,
        format!("Error constructing AP-REQ armor: {err}"),
    )
}

fn cache_has_fast_avail(cc: &FileCcache, realm: &str) -> bool {
    let tgs = krb5_types::PrincipalName::krbtgt(realm).unparse_with_realm(realm);
    cc.creds.iter().any(|c| {
        c.is_config()
            && c.server.1.name_string.len() == 3
            && c.server.1.name_string[1].as_bytes() == b"fast_avail"
            && c.server.1.name_string[2].as_bytes() == tgs.as_bytes()
    })
}

fn initial_armor(
    ctx: &ClientContext,
    cc: Option<&ArmorCcache>,
    realm: &str,
    service: bool,
) -> Result<Option<FastArmor>, Box<dyn std::error::Error + Send + Sync>> {
    let Some(cc) = cc else {
        return Ok(None);
    };
    if !load_ccache(ctx, &cc.spec).is_ok_and(|cache| cache_has_fast_avail(&cache, realm)) {
        for _ in 0..=u8::from(service) {
            trace::fast_armor(ctx, cc, realm, None);
        }
        return Ok(None);
    }
    let armor = load_fast_armor(ctx, &cc.spec).map_err(
        |e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(armor_build_error(e.as_ref())) },
    )?;
    if service {
        trace::fast_armor(ctx, cc, realm, Some(&armor));
        krb5_protocol::set_service_restart(&armor).map_err(
            |e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(armor_build_error(&e)) },
        )?;
    }
    trace::fast_armor(ctx, cc, realm, Some(&armor));
    Ok(Some(armor))
}

#[derive(Clone, Copy)]
enum KeytabArg<'a> {
    Keys(&'a [krb5_crypto::ProtocolKey], &'a Path),
    // MIT krb5_init_creds_set_keytab; see docs/parity/b1-client-keytab.md
    Unreadable(&'a KeytabFailure, &'a Path),
}

fn dispatch_as(
    password: &mut LazyPassword<'_>,
    keytab: Option<KeytabArg<'_>>,
    req: &AsRequest<'_>,
    defer_fast: bool,
) -> Result<Result<AsOutcome, ProtocolError>, Box<dyn std::error::Error + Send + Sync>> {
    match keytab {
        Some(KeytabArg::Keys(keys, path)) => {
            return Ok(krb5_protocol::trace::with_gak_keytab(
                || format!("FILE:{}", path.display()),
                || {
                    if defer_fast {
                        as_exchange_with_keys_defer_fast(req, keys)
                    } else {
                        as_exchange_with_keys(req, keys)
                    }
                },
            ));
        }
        Some(KeytabArg::Unreadable(failure, path)) => {
            return Ok(krb5_protocol::trace::with_gak_keytab(
                || format!("FILE:{}", path.display()),
                || {
                    if defer_fast {
                        as_exchange_with_unreadable_keytab_defer_fast(req, failure)
                    } else {
                        as_exchange_with_unreadable_keytab(req, failure)
                    }
                },
            ));
        }
        None => {}
    }
    let got = if defer_fast {
        password.as_exchange_defer(req)
    } else {
        password.as_exchange(req)
    };
    got.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
}

struct AsShape<'a> {
    cname: krb5_types::PrincipalName,
    realm: &'a str,
    kdc: &'a KdcAddr,
    profile: &'a Krb5Conf,
    want_spake: bool,
    pkinit: Option<Pkinit<'a>>,
    canonicalize: bool,
    sname: Option<&'a krb5_types::PrincipalName>,
    etypes: &'a [i32],
    ticket: AsTicketOpts,
}

impl AsShape<'_> {
    fn request<'b>(&'b self, armor: Option<&'b FastArmor>, password: &'b [u8]) -> AsRequest<'b> {
        AsRequest {
            cname: self.cname.clone(),
            realm: self.realm,
            password,
            kdc: self.kdc,
            profile: self.profile,
            want_spake: self.want_spake,
            fast_armor: armor,
            pkinit: self.pkinit,
            canonicalize: self.canonicalize,
            sname: self.sname,
            etypes: Some(self.etypes),
            ticket: self.ticket.clone(),
        }
    }
}

fn load_armor_for_upgrade(
    ctx: &ClientContext,
    armor: &mut Option<FastArmor>,
    cc: Option<&ArmorCcache>,
    realm: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Some(cc) = cc else {
        return Err(ProtocolError::FastUpgrade.into());
    };
    let loaded = load_fast_armor(ctx, &cc.spec).map_err(
        |e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(armor_build_error(e.as_ref())) },
    )?;
    trace::fast_armor(ctx, cc, realm, Some(&loaded));
    *armor = Some(loaded);
    Ok(())
}

pub fn as_with_fast_ccache(
    ctx: &ClientContext,
    cc: Option<&ArmorCcache>,
    realm: &str,
    service: bool,
    mut exchange: impl FnMut(Option<&FastArmor>, bool) -> Result<AsOutcome, ProtocolError>,
) -> Result<Result<AsOutcome, ProtocolError>, Box<dyn std::error::Error + Send + Sync>> {
    let mut armor = initial_armor(ctx, cc, realm, service)?;
    let first = exchange(armor.as_ref(), cc.is_some() && armor.is_none());
    if !matches!(first, Err(ProtocolError::FastUpgrade)) {
        return Ok(first);
    }
    load_armor_for_upgrade(ctx, &mut armor, cc, realm)?;
    Ok(exchange(armor.as_ref(), false))
}

// MIT: `restart_init_creds_loop` (lib/krb5/krb/get_in_tkt.c:800-801)
// the upgrade sets FAST for the restarted request.
fn exchange_shape(
    ctx: &ClientContext,
    password: &mut LazyPassword<'_>,
    keytab: Option<KeytabArg<'_>>,
    armor: &mut Option<FastArmor>,
    cc: Option<&ArmorCcache>,
    shape: &AsShape<'_>,
) -> Result<Result<AsOutcome, ProtocolError>, Box<dyn std::error::Error + Send + Sync>> {
    let defer = cc.is_some() && armor.is_none();
    let first = {
        let req = shape.request(armor.as_ref(), b"");
        dispatch_as(password, keytab, &req, defer)?
    };
    if !matches!(first, Err(ProtocolError::FastUpgrade)) {
        return Ok(first);
    }
    load_armor_for_upgrade(ctx, armor, cc, shape.realm)?;
    let req = shape.request(armor.as_ref(), b"");
    dispatch_as(password, keytab, &req, false)
}

fn exchange_shape_direct(
    ctx: &ClientContext,
    armor: &mut Option<FastArmor>,
    cc: Option<&ArmorCcache>,
    shape: &AsShape<'_>,
    password: &[u8],
) -> Result<AsOutcome, Box<dyn std::error::Error + Send + Sync>> {
    let defer = cc.is_some() && armor.is_none();
    let first = {
        let req = shape.request(armor.as_ref(), password);
        if defer {
            as_exchange_defer_fast(&req)
        } else {
            as_exchange(&req)
        }
    };
    match first {
        Err(ProtocolError::FastUpgrade) => {
            load_armor_for_upgrade(ctx, armor, cc, shape.realm)?;
            let req = shape.request(armor.as_ref(), password);
            as_exchange(&req).map_err(Into::into)
        }
        other => other.map_err(Into::into),
    }
}

fn kinit_inner(
    ctx: &ClientContext,
    kdc: &KdcAddr,
    principal: &str,
    password: &mut LazyPassword<'_>,
    params: KinitParams<'_>,
) -> Result<(KinitResult, FileCcache), Box<dyn std::error::Error + Send + Sync>> {
    let (cname, mut realm_s) = parse_principal_ex(principal, params.enterprise)?;
    if realm_s.is_empty() {
        realm_s = conf_default_realm(ctx).ok_or("Cannot find KDC for requested realm")?;
    }
    trace::init_creds(&cname, &realm_s, params.in_tkt_service);
    let resolved = resolve_kdc(&ctx.profile, &realm_s, kdc)?;
    let mut armor = initial_armor(
        ctx,
        params.armor_ccache,
        &realm_s,
        params.in_tkt_service.is_some(),
    )?;
    let PkinitConf {
        identities: conf_ids,
        anchors: conf_an,
        pool,
        rules,
        opts,
    } = pkinit_from_conf(&ctx.profile, &realm_s);
    let identities = match params.pkinit_identity {
        _ if params.anonymous => Vec::new(),
        Some(p) => vec![p.to_string_lossy().into_owned()],
        None => conf_ids,
    };
    let anchors = if params.pkinit_anchors.is_empty() {
        conf_an.as_slice()
    } else {
        params.pkinit_anchors
    };
    let pkinit = match (anchors.is_empty(), params.anonymous) {
        (false, true) => match load_pkinit_anchors(anchors, &pool, opts)? {
            pk if pk.anchors.is_empty() => ClientPkinit::Failed(PkinitFailure {
                code: krb5_protocol::trace::ERROR_TABLE_BASE_KRB5 + 24,
                text: NO_TRUSTED_CA.into(),
                no_identity: false,
                prompted: false,
            }),
            pk => ClientPkinit::Ready(pk),
        },
        (true, true) => return Err("anonymous PKINIT requires pkinit_anchors".into()),
        (_, false) => load_pkinit(&identities, anchors, &pool, &rules, opts)?,
    };
    let mut etypes = krb5_protocol::conf_etypes(&ctx.profile, false);
    let mut ticket = params.ticket;
    ticket.anonymous |= params.anonymous;
    let mut keytab_failure: Option<KeytabFailure> = None;
    let keytab_keys = if let Some(ktpath) = params.keytab {
        match read_keytab_file(ktpath) {
            Err(failure) => {
                krb5_protocol::trace::init_creds_keytab_lookup_failed(
                    failure.code,
                    Some(&failure.text),
                );
                keytab_failure = Some(failure);
                None
            }
            Ok(bytes) => {
                let kt = Keytab::parse(&bytes)?;
                let (keys, kt_etypes) = krb5_protocol::keytab_init_creds_keys(
                    &kt, &cname, &realm_s,
                )
                .ok_or_else(|| {
                    Krb5Error::new(
                        Code::Other,
                        format!(
                            "Keytab contains no suitable keys for {}",
                            cname.unparse_with_realm(&realm_s)
                        ),
                    )
                })?;
                krb5_protocol::trace::init_creds_keytab_lookup(
                    krb5_protocol::trace::Princ::new(&cname, realm_s.as_bytes()),
                    &kt_etypes,
                );
                krb5_protocol::sort_etypes_keytab_first(&mut etypes, &kt_etypes);
                Some(keys)
            }
        }
    } else {
        None
    };
    // MIT: `build_in_tkt_name` (get_in_tkt.c:473-512)
    // An initial-ticket service takes the client's realm, whatever realm its name gives.
    let in_tkt_sname = match params.in_tkt_service {
        Some(s) => Some(
            krb5_types::principal_from_unparsed(s, &realm_s)
                .map_err(|_| Krb5Error::of(Code::ParseMalformed))?
                .0,
        ),
        None => None,
    };
    let pa_server = in_tkt_sname
        .clone()
        .unwrap_or_else(|| krb5_types::PrincipalName::krbtgt(&realm_s));
    ticket.allowed_preauth_type = allowed_preauth_type(params.in_ccache, &pa_server, &realm_s);
    ticket.pa_config_in = pa_config_in(params.in_ccache, &pa_server, &realm_s);
    let pac_request = ticket.pac_request;
    let keytab = match (
        keytab_keys.as_deref(),
        keytab_failure.as_ref(),
        params.keytab,
    ) {
        (Some(keys), _, Some(path)) => Some(KeytabArg::Keys(keys, path)),
        (None, Some(failure), Some(path)) => Some(KeytabArg::Unreadable(failure, path)),
        _ => None,
    };
    let shape = AsShape {
        cname: cname.clone(),
        realm: &realm_s,
        kdc: &resolved,
        profile: &ctx.profile,
        want_spake: params.want_spake,
        pkinit: Some(pkinit.arg()),
        canonicalize: params.canonicalize || params.enterprise,
        sname: in_tkt_sname.as_ref(),
        etypes: &etypes,
        ticket,
    };
    let as_out = match exchange_shape(
        ctx,
        password,
        keytab,
        &mut armor,
        params.armor_ccache,
        &shape,
    )? {
        Ok(o) => o,
        Err(e)
            if krb5_protocol::key_exp_should_changepw(
                &e,
                params.new_password.is_some() || params.prompter.is_some(),
                params.keytab.is_some(),
            ) =>
        {
            // MIT: `k5_infer_principal_type` (lib/krb5/krb/bld_princ.c:31-43)
            // `kadmin/changepw` is NT-PRINCIPAL.
            let changepw = krb5_types::PrincipalName::new(
                krb5_types::PrincipalName::NT_PRINCIPAL,
                ["kadmin", "changepw"],
            );
            krb5_protocol::trace::gic_pwd_expired();
            trace::init_creds(&cname, &realm_s, Some("kadmin/changepw"));
            let chpw_ticket = AsTicketOpts {
                lifetime: Some(5 * 60),
                rlife: None,
                forwardable: false,
                proxiable: false,
                // MIT: `make_chpw_options` (lib/krb5/krb/gic_pwd.c:163-163)
                // this request drops the address list the caller set.
                addresses: krb5_protocol::init_creds_addresses(
                    ctx.profile.noaddresses_for(&realm_s),
                )
                .map_err(|e| Krb5Error::from_local_addresses(&e))?,
                anonymous: false,
                starttime: None,
                pac_request,
                allowed_preauth_type: allowed_preauth_type(params.in_ccache, &changepw, &realm_s),
                pa_config_in: pa_config_in(params.in_ccache, &changepw, &realm_s),
            };
            let chpw_shape = AsShape {
                cname: cname.clone(),
                realm: &realm_s,
                kdc: &resolved,
                profile: &ctx.profile,
                want_spake: false,
                pkinit: Some(pkinit.arg()),
                canonicalize: params.canonicalize || params.enterprise,
                sname: Some(&changepw),
                etypes: &etypes,
                ticket: chpw_ticket,
            };
            let chpw_as = exchange_shape(
                ctx,
                password,
                None,
                &mut initial_armor(ctx, params.armor_ccache, &realm_s, true)?,
                params.armor_ccache,
                &chpw_shape,
            )??;
            let new_pw = match (params.new_password, params.prompter) {
                (Some(p), _) => {
                    krb5_protocol::trace::gic_pwd_changepw(3);
                    if let Some(n) = params.key_exp_notice {
                        (n.0)(KEY_EXP_BANNER);
                    }
                    krb5_protocol::change_password(
                        &ctx.profile
                            .locate_kpasswd_traced(&realm_s, &mut crate::trace::dns_srv)?,
                        &chpw_as,
                        p,
                        ctx.profile.request_timeout,
                        Some(&ctx.profile),
                    )
                    .map_err(|e| chpw_error(e, &realm_s))?;
                    Zeroizing::new(p.to_vec())
                }
                (None, Some(prompter)) => prompt_and_change(
                    &ctx.profile
                        .locate_kpasswd_traced(&realm_s, &mut crate::trace::dns_srv)?,
                    &chpw_as,
                    prompter,
                    &realm_s,
                    ctx.profile.request_timeout,
                    &ctx.profile,
                )?,
                (None, None) => return Err(e.into()),
            };
            krb5_protocol::trace::gic_pwd_changed();
            trace::init_creds(&cname, &realm_s, params.in_tkt_service);
            let mut armor = initial_armor(
                ctx,
                params.armor_ccache,
                &realm_s,
                params.in_tkt_service.is_some(),
            )?;
            exchange_shape_direct(ctx, &mut armor, params.armor_ccache, &shape, &new_pw)?
        }
        Err(e) => return Err(e.into()),
    };
    if params.prompter.is_some() || params.preauth_prompter.is_some() {
        krb5_protocol::warn_deprecated_enctype(&as_out);
    }
    if ctx.profile.kdc_timesync {
        ctx.note_kdc_offset(as_out.time_offset);
    }
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
        match tgs_exchange_path(
            &ctx.profile,
            &resolved,
            &as_out,
            sname,
            &svc_realm,
            &krb5_protocol::TgsCredsOptions::default(),
        ) {
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
    let mut cache = FileCcache::new((as_out.crealm.clone(), as_out.cname.clone()), Vec::new());
    // MIT: `marshal_header` (lib/krb5/ccache/cc_file.c:454-462)
    if let Some(off) = ctx.kdc_offset() {
        cache.set_deltatime(off);
    }
    let tgt_realm = String::from_utf8_lossy(as_out.ticket.realm.as_bytes()).into_owned();
    let tgt_server = as_out.ticket.sname.unparse_with_realm(&tgt_realm);
    record_preauth_config(
        &mut cache,
        &tgt_server,
        as_out.fast_avail,
        as_out.pa_type,
        as_out.pa_config.as_deref(),
    );
    cache.creds.extend(creds);
    if let Some(e) = tgs_err {
        tracing::error!(
            event = krb5_log::events::CLIENT_TGS,
            component = "krb5-client",
            outcome = "error",
            error = e.as_str(),
        );
        return Err(e.into());
    }
    Ok((KinitResult { as_out, tgs_out }, cache))
}

fn record_preauth_config(
    cache: &mut FileCcache,
    tgt_server: &str,
    fast_avail: bool,
    pa_type: Option<i32>,
    pa_config: Option<&[u8]>,
) {
    if fast_avail {
        cache.set_config(Some(tgt_server), "fast_avail", b"yes");
    }
    if let Some(t) = pa_type {
        cache.set_config(Some(tgt_server), "pa_type", t.to_string().as_bytes());
    }
    if let Some(c) = pa_config {
        cache.set_config(Some(tgt_server), "pa_config_data", c);
    }
}

const KEY_EXP_BANNER: &str = "Password expired.  You must change it now.";

fn prompt_and_change(
    servers: &[krb5_config::Endpoint],
    chpw_as: &krb5_protocol::AsOutcome,
    prompter: NewPasswordPrompter<'_>,
    realm: &str,
    timeout: Option<std::time::Duration>,
    profile: &krb5_config::Krb5Conf,
) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
    let mut banner = KEY_EXP_BANNER.to_owned();
    let mut ret = "Password change failed";
    for tries in (1..=3).rev() {
        krb5_protocol::trace::gic_pwd_changepw(tries);
        let (pw0, pw1) = (prompter.0)(&banner)?;
        if pw0 != pw1 {
            ret = "Password mismatch";
            banner = format!("{ret}.  Please try again.");
        } else if pw0.is_empty() {
            ret = "New password cannot be zero length";
            banner = format!("{ret}.  Please try again.");
        } else {
            let (code, data) = krb5_protocol::change_password_result(
                servers,
                chpw_as,
                &pw0,
                timeout,
                Some(profile),
            )
            .map_err(|e| chpw_error(e, realm))?;
            if code == krb5_protocol::KPASSWD_SUCCESS {
                return Ok(pw0);
            }
            ret = "Password change failed";
            if code != krb5_protocol::KPASSWD_SOFTERROR {
                return Err(ret.into());
            }
            banner = format!(
                "{}.  Please try again.\n",
                krb5_protocol::format_chpw_failure(code, &data)
            );
        }
    }
    Err(ret.into())
}

fn resolve_kdc(profile: &Krb5Conf, realm: &str, argv: &KdcAddr) -> Result<KdcAddr, Krb5Error> {
    if krb5_config::handed_matches(realm, &argv.host, argv.port) {
        return Ok(argv.clone());
    }
    let found = match profile.kdcs_for_traced(realm, &mut crate::trace::dns_srv) {
        Ok(list) => list,
        Err(krb5_config::Error::InvalidArgument) => return Err(Krb5Error::of(Code::Einval)),
        Err(_) => Vec::new(),
    };
    let Some(ep) = found.first() else {
        krb5_config::clear_handed();
        return Ok(argv.clone());
    };
    let addr = KdcAddr {
        host: ep.host.clone(),
        port: ep.port,
    };
    krb5_config::hand_kdcs(realm, found);
    Ok(addr)
}

#[cfg(all(test, feature = "test-hooks"))]
mod armor_flow;
