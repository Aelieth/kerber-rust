//! `kadmin`'s network handle: MIT's `kadm5_init_*` for a client, and the calls over it.

use krb5_client::creds::{kdc_for_realm, outcome_from_cred};
use krb5_client::errmsg::{Code, Krb5Error};
use krb5_client::{
    KinitParams, kinit_prompted_princ, kinit_with_princ, kt_default_name, kt_resolve,
    mit_error_code,
};
use krb5_config::{CcSpec, ClientContext, Krb5Conf};
use krb5_kdc::{AdminEnt, Error, KeyEntry, NamedPolicy, TL_DB_ARGS, TL_LAST_ADMIN_UNLOCK};
use krb5_protocol::AsOutcome;
use krb5_types::PrincipalName;
use zeroize::Zeroizing;

use super::backend::{Kadm5Api, ModPrincipal, NewPrincipal, PrincRec, mask};
use super::stdio::Io;
use super::texts;
use crate::PolicyArgs;
use crate::kadm5::{
    AdminTicket, AuthFlavours, KADM5_BAD_PASSWORD, KADM5_MISSING_KRB5_CONF_PARAMS,
    KADM5_SECURE_PRINC_MISSING, KADM5_UNK_PRINC, Kadm5Client, PrincView, TlView, kadm5_error_text,
};

/// `KADM5_PRINCIPAL_NORMAL_MASK | KADM5_KEY_DATA`
const GET_MASK: u32 = 0x0043_ffff;
const NORMAL_MASK: u32 = 0x0041_ffff;
const ADMIN_SERVICE: &str = "kadmin/admin";
const KDC_S_PRINCIPAL_UNKNOWN: i32 = krb5_types::err::S_PRINCIPAL_UNKNOWN;

pub(super) enum Auth<'a> {
    Password(Option<&'a str>),
    Keytab(Option<&'a str>),
    Anonymous,
    Creds(&'a CcSpec),
}

pub(super) struct Connect<'a> {
    pub(super) realm: &'a str,
    pub(super) princstr: &'a str,
    pub(super) auth: Auth<'a>,
    pub(super) admin_server: Option<&'a str>,
    pub(super) flavours: AuthFlavours,
}

#[derive(PartialEq)]
enum Kind {
    PrincipalUnknown,
    CcNotFound,
    BadIntegrity,
    Other,
}

struct Fail {
    kind: Kind,
    text: String,
}

impl Fail {
    fn other(text: impl Into<String>) -> Self {
        Self {
            kind: Kind::Other,
            text: text.into(),
        }
    }

    fn of_krb5(e: &Krb5Error) -> Self {
        let kind = if e.code == Code::CcNotfound {
            Kind::CcNotFound
        } else {
            Kind::Other
        };
        Self {
            kind,
            text: e.message.clone(),
        }
    }

    fn of_kinit(
        e: &(dyn std::error::Error + Send + Sync + 'static),
        name: &str,
        realm: &str,
    ) -> Self {
        let kind = match mit_error_code(e) {
            Some(KDC_S_PRINCIPAL_UNKNOWN) => Kind::PrincipalUnknown,
            Some(krb5_types::err::BAD_INTEGRITY) => Kind::BadIntegrity,
            _ => Kind::Other,
        };
        let text = if let Some(k) = e.downcast_ref::<Krb5Error>() {
            k.message.clone()
        } else if let Some(p) = e.downcast_ref::<krb5_protocol::Error>() {
            Krb5Error::from_as(p, name, realm).message
        } else {
            e.to_string()
        };
        Self { kind, text }
    }
}

// MIT: `get_init_creds` (lib/kadm5/clnt/client_init.c:363-434)
fn get_init_creds(
    io: &mut Io,
    c: &Connect<'_>,
    conf: &Krb5Conf,
    host: &str,
) -> Result<AdminTicket, String> {
    let ctx = ClientContext::new(conf.clone());
    let first = acquire(io, c, &ctx, ADMIN_SERVICE);
    let result = match first {
        Err(f)
            if matches!(f.kind, Kind::PrincipalUnknown | Kind::CcNotFound)
                && !c.flavours.old_auth_gssapi =>
        {
            let svc = format!("kadmin/{}", krb5_config::expand_hostname_conf(host, conf));
            acquire(io, c, &ctx, &svc)
        }
        other => other,
    };
    result.map_err(|f| match f.kind {
        Kind::BadIntegrity => kadm5_error_text(KADM5_BAD_PASSWORD),
        Kind::PrincipalUnknown => kadm5_error_text(KADM5_SECURE_PRINC_MISSING),
        _ => f.text,
    })
}

// MIT: `gic_iter` (lib/kadm5/clnt/client_init.c:442-506)
fn acquire(
    io: &mut Io,
    c: &Connect<'_>,
    ctx: &ClientContext,
    svc: &str,
) -> Result<AdminTicket, Fail> {
    let (cname, crealm) = krb5_types::principal_from_unparsed(c.princstr, c.realm)
        .map_err(|_| Fail::other(texts::MALFORMED))?;
    let out = match &c.auth {
        Auth::Creds(spec) => from_cache(ctx, spec, (&cname, &crealm), svc)?,
        auth => from_kdc(io, ctx, auth, (&cname, &crealm), svc)?,
    };
    Ok(AdminTicket {
        times: (&out.enc_part).into(),
        ticket: out.ticket,
        session: out.session_key,
        crealm: out.crealm,
        cname: out.cname,
    })
}

// MIT: `fcc_retrieve` (lib/krb5/ccache/cc_file.c:977-984)
fn not_found(spec: &CcSpec) -> Fail {
    let mut e = Krb5Error::of(Code::CcNotfound);
    if let Some(path) = krb5_client::cache_file_path(spec) {
        e.message = format!("{} (filename: {})", e.message, path.display());
    }
    Fail::of_krb5(&e)
}

fn from_cache(
    ctx: &ClientContext,
    spec: &CcSpec,
    (cname, crealm): (&PrincipalName, &str),
    svc: &str,
) -> Result<AsOutcome, Fail> {
    let (sname, srealm) = krb5_types::principal_from_unparsed(svc, crealm)
        .map_err(|_| Fail::other(texts::MALFORMED))?;
    let cache = krb5_client::load_ccache(ctx, spec)
        .map_err(|e| Fail::of_krb5(&krb5_client::cache_read_error(ctx, spec, e.as_ref())))?;
    let same = |p: &(krb5_types::Realm, PrincipalName), n: &PrincipalName, r: &str| {
        p.0.as_bytes() == r.as_bytes() && p.1.name_string == n.name_string
    };
    cache
        .creds
        .iter()
        .find(|cr| {
            !cr.is_config() && same(&cr.client, cname, crealm) && same(&cr.server, &sname, &srealm)
        })
        .map_or_else(
            || Err(not_found(spec)),
            |cr| outcome_from_cred(cr).map_err(|e| Fail::of_krb5(&e)),
        )
}

fn from_kdc(
    io: &mut Io,
    ctx: &ClientContext,
    auth: &Auth<'_>,
    (cname, crealm): (&PrincipalName, &str),
    svc: &str,
) -> Result<AsOutcome, Fail> {
    let name = cname.unparse_with_realm_lossy(crealm);
    let mut me = (
        krb5_types::try_ascii(crealm).map_err(|_| Fail::other(texts::MALFORMED))?,
        cname.clone(),
    );
    // MIT: `init_any` (lib/kadm5/clnt/client_init.c:218-222)
    if crealm.is_empty() && matches!(auth, Auth::Keytab(_)) {
        me.1.name_type = PrincipalName::NT_SRV_HST;
    }
    let keytab = match auth {
        Auth::Keytab(name) => {
            let path = name.map_or_else(|| kt_default_name(ctx), str::to_owned);
            match kt_resolve(&path) {
                Ok(krb5_client::KeytabName::File(p)) => Some(p),
                Ok(krb5_client::KeytabName::Memory(_)) => None,
                Err(e) => return Err(Fail::other(e.to_string())),
            }
        }
        _ => None,
    };
    if let Some(path) = &keytab {
        me = keytab_client(path, &ctx.profile, &me, &name)?;
    }
    let realm = String::from_utf8_lossy(me.0.as_bytes()).into_owned();
    let kdc = kdc_for_realm(&ctx.profile, &realm).map_err(|e| Fail::of_krb5(&e))?;
    let params = KinitParams {
        in_tkt_service: Some(svc),
        keytab: keytab.as_deref(),
        anonymous: matches!(auth, Auth::Anonymous),
        ..KinitParams::default()
    };
    let spec = CcSpec::Memory("kadm5_0".to_owned());
    let result = match auth {
        Auth::Password(Some(pw)) => {
            kinit_with_princ(ctx, &kdc, &me, &mut pw.as_bytes().to_vec(), &spec, &params)
        }
        Auth::Password(None) => {
            let mut read = |client: &str| -> Result<Zeroizing<Vec<u8>>, Krb5Error> {
                io.read_password(&format!("Password for {client}"), None)
                    .map_err(|e| {
                        let code = if e == krb5_cli::PromptError::Interrupted {
                            Code::PwdInterrupted
                        } else {
                            Code::Other
                        };
                        Krb5Error::new(code, e.to_string())
                    })
            };
            kinit_prompted_princ(ctx, &kdc, &me, &mut read, &spec, &params)
        }
        _ => kinit_with_princ(ctx, &kdc, &me, &mut [], &spec, &params),
    };
    let _ = krb5_client::destroy_ccache(ctx, &spec);
    result
        .map(|r| r.as_out)
        .map_err(|e| Fail::of_kinit(e.as_ref(), &name, &realm))
}

// MIT: `krb5_init_creds_set_keytab` (lib/krb5/krb/gic_keytab.c:191-224)
fn keytab_client(
    path: &std::path::Path,
    conf: &Krb5Conf,
    me: &(krb5_types::Realm, PrincipalName),
    name: &str,
) -> Result<(krb5_types::Realm, PrincipalName), Fail> {
    let parsed = krb5_protocol::read_keytab_file(path)
        .ok()
        .and_then(|bytes| krb5_protocol::Keytab::parse(&bytes).ok());
    let Some(kt) = parsed else {
        return Ok(me.clone());
    };
    match krb5_protocol::keytab_init_creds_client(&kt, conf, me) {
        Ok(Some((found, _, _))) => Ok(found),
        Ok(None) => Err(Fail::other(format!(
            "Keytab contains no suitable keys for {name}"
        ))),
        Err(_) => Ok(me.clone()),
    }
}

/// `host`, and the port: `-s host[:port]`, else the realm's `admin_server` and `kadmind_port`.
// MIT: `kadm5_get_config_params` (lib/kadm5/alt_prof.c:496-531)
fn server_of(c: &Connect<'_>, conf: &Krb5Conf) -> Option<(String, i32)> {
    let listen = krb5_config::KadmindListen::for_realm(Some(conf), c.realm, None);
    let given = c.admin_server.map(str::to_owned).or_else(|| {
        conf.admin_servers
            .get(c.realm)
            .and_then(|v| v.last())
            .map(|e| e.host.clone())
    })?;
    let host = krb5_config::listen::admin_server_host(&given).to_owned();
    let port = krb5_config::listen::admin_server_port(&given).unwrap_or(listen.kadmind_port);
    Some((host, port))
}

pub(super) struct RemoteBackend {
    client: Kadm5Client,
}

impl RemoteBackend {
    // MIT: `init_any` (lib/kadm5/clnt/client_init.c:172-345)
    pub(super) fn connect(io: &mut Io, c: &Connect<'_>, conf: &Krb5Conf) -> Result<Self, String> {
        let Some((host, port)) = server_of(c, conf) else {
            return Err(kadm5_error_text(KADM5_MISSING_KRB5_CONF_PARAMS));
        };
        let ticket = get_init_creds(io, c, conf, &host)?;
        let port =
            u16::try_from(port).map_err(|_| kadm5_error_text(crate::kadm5::KADM5_RPC_ERROR))?;
        Kadm5Client::open(&host, port, &ticket, c.flavours)
            .map(|client| Self { client })
            .map_err(kadm5_error_text)
    }
}

fn wire(code: u32) -> Error {
    Error::Protocol {
        code: code.cast_signed(),
        text: Some(kadm5_error_text(code)),
        e_data: None,
        detail: None,
    }
}

fn wire_key(code: u32) -> Error {
    if code == KADM5_UNK_PRINC {
        Error::NotFound
    } else {
        wire(code)
    }
}

fn keysalt_pairs(ks: &[krb5_crypto::KeySalt]) -> Vec<(i32, i32)> {
    ks.iter().map(|k| (k.etype.to_iana(), k.salt)).collect()
}

fn key_entry(enctype: i32, key: &[u8], kvno: u32) -> Result<KeyEntry, Error> {
    let crypto = |e: krb5_crypto::Error| Error::Crypto(e.to_string());
    let etype = krb5_crypto::EncryptionType::known(enctype).map_err(crypto)?;
    let key = krb5_crypto::ProtocolKey::from_bytes(etype, key).map_err(crypto)?;
    Ok(KeyEntry::new(etype, key, kvno))
}

fn princ_rec(name: &str, ent: &AdminEnt, db_args: &[String], unlock: bool) -> PrincView {
    let mut tl_data = Vec::new();
    if ent.mask & mask::TL_DATA != 0 {
        for arg in db_args {
            let mut contents = arg.as_bytes().to_vec();
            contents.push(0);
            tl_data.push(TlView {
                ty: TL_DB_ARGS,
                contents,
            });
        }
        if unlock {
            let now = krb5_types::KerberosTime::now().unix_seconds();
            tl_data.push(TlView {
                ty: TL_LAST_ADMIN_UNLOCK,
                contents: now.to_le_bytes().to_vec(),
            });
        }
    }
    PrincView {
        principal: name.to_owned(),
        princ_expire_time: ent.princ_expire_time,
        pw_expiration: ent.pw_expiration,
        max_life: ent.max_life,
        attributes: ent.attributes,
        kvno: ent.kvno,
        policy: if ent.mask & mask::POLICY != 0 {
            ent.policy.clone()
        } else {
            None
        },
        max_renewable_life: ent.max_renewable_life,
        tl_data,
        ..PrincView::default()
    }
}

fn full_name(name: &PrincipalName, realm: &str) -> String {
    name.unparse_with_realm_lossy(realm)
}

impl Kadm5Api for RemoteBackend {
    fn refresh(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn get_principal(&mut self, name: &PrincipalName, realm: &str) -> Result<PrincRec, Error> {
        self.client
            .get_principal(&full_name(name, realm), GET_MASK)
            .map(PrincRec::Wire)
            .map_err(wire)
    }

    fn merge_lockout(&self, _: &mut PrincRec) {}

    fn list_principals(&mut self, expr: Option<&str>) -> Result<Vec<String>, Error> {
        self.client.get_principals(expr).map_err(wire)
    }

    fn match_principals(&mut self, pattern: &str) -> Result<Vec<String>, Error> {
        self.client.get_principals(Some(pattern)).map_err(wire)
    }

    fn create_principal(&mut self, r: &NewPrincipal<'_>) -> Result<(), Error> {
        let rec = princ_rec(&full_name(r.name, r.realm), &r.ent, r.db_args, r.unlock);
        self.client
            .create_principal(&rec, r.ent.mask, &keysalt_pairs(r.keysalts), r.pass)
            .map_err(wire)
    }

    fn modify_principal(&mut self, r: &ModPrincipal<'_>) -> Result<(), Error> {
        let rec = princ_rec(&full_name(r.name, r.realm), &r.ent, r.db_args, r.unlock);
        self.client.modify_principal(&rec, r.ent.mask).map_err(wire)
    }

    fn delete_principal(&mut self, name: &PrincipalName, realm: &str) -> Result<(), Error> {
        self.client
            .delete_principal(&full_name(name, realm))
            .map_err(wire)
    }

    fn rename_principal(
        &mut self,
        old: &PrincipalName,
        old_realm: &str,
        new: &PrincipalName,
        new_realm: &str,
    ) -> Result<(), Error> {
        self.client
            .rename_principal(&full_name(old, old_realm), &full_name(new, new_realm))
            .map_err(wire)
    }

    fn create_alias(
        &mut self,
        alias: &PrincipalName,
        alias_realm: &str,
        target: &PrincipalName,
        target_realm: &str,
    ) -> Result<(), Error> {
        self.client
            .create_alias(
                &full_name(alias, alias_realm),
                &full_name(target, target_realm),
            )
            .map_err(wire)
    }

    fn change_password(
        &mut self,
        name: &PrincipalName,
        realm: &str,
        pw: &[u8],
        keepold: u32,
        keysalts: &[krb5_crypto::KeySalt],
    ) -> Result<(), Error> {
        self.client
            .chpass(
                &full_name(name, realm),
                pw,
                keepold != 0,
                &keysalt_pairs(keysalts),
            )
            .map_err(wire)
    }

    fn randomize_key(
        &mut self,
        name: &PrincipalName,
        realm: &str,
        keysalts: &[krb5_crypto::KeySalt],
        keepold: u32,
    ) -> Result<(), Error> {
        self.client
            .randkey(
                &full_name(name, realm),
                keepold != 0,
                &keysalt_pairs(keysalts),
            )
            .map(|_| ())
            .map_err(wire)
    }

    // MIT: `fetch_new_keys` (kadmin/cli/keytab.c:248-296)
    fn fetch_new_keys(
        &mut self,
        name: &PrincipalName,
        realm: &str,
        keysalts: &[krb5_crypto::KeySalt],
    ) -> Result<Vec<KeyEntry>, Error> {
        let full = full_name(name, realm);
        let keys = self
            .client
            .randkey(&full, false, &keysalt_pairs(keysalts))
            .map_err(wire_key)?;
        let kvno = self
            .client
            .get_principal(&full, NORMAL_MASK)
            .map_err(wire_key)?
            .kvno;
        keys.iter()
            .map(|k| key_entry(k.enctype, &k.key, kvno))
            .collect()
    }

    // MIT: `kadm5_get_principal_keys` (lib/kadm5/clnt/client_principal.c:504-528)
    fn get_principal_keys(
        &mut self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Vec<KeyEntry>, Error> {
        let keys = self
            .client
            .extract_keys(&full_name(name, realm))
            .map_err(wire_key)?;
        keys.iter()
            .map(|k| key_entry(k.enctype, &k.key, k.kvno))
            .collect()
    }

    fn purge_keys(
        &mut self,
        name: &PrincipalName,
        realm: &str,
        keepkvno: i32,
    ) -> Result<(), Error> {
        self.client
            .purge_keys(&full_name(name, realm), keepkvno)
            .map_err(wire)
    }

    fn get_strings(
        &mut self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Vec<(String, String)>, Error> {
        self.client
            .get_strings(&full_name(name, realm))
            .map_err(wire)
    }

    fn set_string(
        &mut self,
        name: &PrincipalName,
        realm: &str,
        key: &str,
        value: Option<&str>,
    ) -> Result<(), Error> {
        self.client
            .set_string(&full_name(name, realm), key, value)
            .map_err(wire)
    }

    fn policy_exists(&mut self, name: &str) -> bool {
        self.client.get_policy(name).is_ok()
    }

    fn has_policy(&mut self, name: &str) -> bool {
        self.policy_exists(name)
    }

    fn get_policy(&mut self, name: &str) -> Result<NamedPolicy, Error> {
        let v = self.client.get_policy(name).map_err(wire)?;
        Ok(NamedPolicy {
            name: v.name,
            min_length: v.pw_min_length,
            min_classes: v.pw_min_classes,
            history: v.pw_history_num,
            max_fail: v.pw_max_fail,
            pw_failcnt_interval: v.pw_failcnt_interval,
            pw_lockout_duration: v.pw_lockout_duration,
            pw_min_life: v.pw_min_life,
            pw_max_life: v.pw_max_life,
            allowed_keysalts: v.allowed_keysalts,
        })
    }

    fn list_policies(&mut self, expr: Option<&str>) -> Result<Vec<String>, Error> {
        self.client.get_policies(expr).map_err(wire)
    }

    fn create_policy(&mut self, args: &PolicyArgs) -> Result<(), Error> {
        self.client.create_policy(args, false).map_err(wire)
    }

    fn modify_policy(&mut self, args: &PolicyArgs, clear_keysalts: bool) -> Result<(), Error> {
        self.client
            .modify_policy(args, clear_keysalts)
            .map_err(wire)
    }

    fn delete_policy(&mut self, name: &str) -> Result<(), Error> {
        self.client.delete_policy(name).map_err(wire)
    }

    fn map_update_log(&mut self, _: &std::path::Path, _: u32) -> Result<(), String> {
        Ok(())
    }

    // MIT: `kadm5_lock` (lib/kadm5/clnt/client_init.c:692-695)
    fn lock(&mut self) -> Result<(), Error> {
        Err(Error::InvalidArgument("Invalid argument".to_owned()))
    }

    fn unlock(&mut self) -> Result<(), Error> {
        self.lock()
    }

    fn get_privs(&mut self) -> Result<u32, Error> {
        self.client.get_privs().map_err(wire)
    }
}
