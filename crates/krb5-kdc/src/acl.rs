//! kadm5.acl-style allow/deny for admin operations.

use crate::error::Error;
use crate::store::{
    KDB_DISALLOW_ALL_TIX, KDB_DISALLOW_DUP_SKEY, KDB_DISALLOW_FORWARDABLE, KDB_DISALLOW_POSTDATED,
    KDB_DISALLOW_PROXIABLE, KDB_DISALLOW_RENEWABLE, KDB_DISALLOW_SVR, KDB_DISALLOW_TGT_BASED,
    KDB_LOCKDOWN_KEYS, KDB_NEW_PRINC, KDB_NO_AUTH_DATA_REQUIRED, KDB_OK_AS_DELEGATE,
    KDB_OK_TO_AUTH_AS_DELEGATE, KDB_PWCHANGE_SERVICE, KDB_REQUIRES_HW_AUTH, KDB_REQUIRES_PRE_AUTH,
    KDB_REQUIRES_PWCHANGE, KDB_SUPPORT_DESMD5,
};

/// Mutating admin operations gated by the ACL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminOp {
    /// Add a principal.
    Create,
    /// Delete a principal.
    Delete,
    /// Export a keytab (`ktadd`).
    Ktadd,
    /// Change a password (`kpasswd` / kadm5 `c`).
    ChangePassword,
    /// Inquire (`getprinc` / `listprincs` / kadm5 `i`).
    Inquire,
    /// Extract keys (`ktadd -norandkey` / kadm5 `e`). Not implied by `*`/`x`.
    Extract,
    /// Modify attributes (`modprinc` / kadm5 `m`).
    Modify,
    /// Set keys explicitly (`setkey` / kadm5 `s`). Implied by `*`/`x`.
    SetKey,
    /// List principals/policies (kadm5 `l`).
    List,
    /// Incremental/full dump propagation (kadm5 `p`).
    Propagate,
}

/// kadm5.acl restrictions (`auth_acl.c` `parse_restrictions`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Restrictions {
    /// `-clearpolicy`.
    pub clear_policy: bool,
    /// `-policy <name>`.
    pub policy: Option<String>,
    /// `-maxlife` seconds.
    pub max_life: Option<u64>,
    /// `-maxrenewlife` seconds.
    pub max_renewable_life: Option<u64>,
    /// `-expire` delta seconds.
    pub expire: Option<u64>,
    /// `-pwexpire` delta seconds.
    pub pwexpire: Option<u64>,
    /// Bits forced on (`+flag` / inverted `-allow_*`).
    pub require_attrs: u32,
    /// Bits allowed to stay (`~0` with `-flag` bits cleared).
    pub forbid_attrs: u32,
}

impl Default for Restrictions {
    fn default() -> Self {
        Self {
            clear_policy: false,
            policy: None,
            max_life: None,
            max_renewable_life: None,
            expire: None,
            pwexpire: None,
            require_attrs: 0,
            forbid_attrs: !0,
        }
    }
}

impl Restrictions {
    /// MIT `impose_restrictions` (`auth.c:211-272`).
    pub fn apply_to(&self, p: &mut crate::store::Principal, now: u32) {
        p.attributes |= self.require_attrs;
        p.attributes &= self.forbid_attrs;
        if self.clear_policy {
            p.pw_policy = None;
        } else if let Some(ref pol) = self.policy {
            p.pw_policy = Some(pol.clone());
        }
        if let Some(d) = self.max_life
            && (p.max_life == 0 || p.max_life > d)
        {
            p.max_life = d;
        }
        if let Some(d) = self.max_renewable_life
            && (p.max_renewable_life == 0 || p.max_renewable_life > d)
        {
            p.max_renewable_life = d;
        }
        if let Some(d) = self.expire {
            let cap = now.saturating_add(u32::try_from(d).unwrap_or(u32::MAX));
            if p.expiration == 0 || p.expiration > cap {
                p.expiration = cap;
            }
        }
        if let Some(d) = self.pwexpire {
            let cap = now.saturating_add(u32::try_from(d).unwrap_or(u32::MAX));
            if p.pw_expire == 0 || p.pw_expire > cap {
                p.pw_expire = cap;
            }
        }
        p.requires_preauth = p.attributes & crate::store::KDB_REQUIRES_PRE_AUTH != 0;
        p.locked = p.attributes & crate::store::KDB_DISALLOW_ALL_TIX != 0;
    }
}

/// One ACL line: a principal pattern and permission flags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AclEntry {
    /// Exact `name@REALM` (or glob) as written.
    pub principal: String,
    /// `a` / `*`
    pub add: bool,
    /// `d` / `*`
    pub delete: bool,
    /// `i` (inquire) / `*`
    pub inquire: bool,
    /// `e` (extract keys). MIT does not include this in `*`/`x`.
    pub extract: bool,
    /// `c` (changepw) / `*`
    pub changepw: bool,
    /// `m` (modify) / `*`
    pub modify: bool,
    /// `s` (setkey) / `*`
    pub setkey: bool,
    /// `l` (list) / `*`
    pub list: bool,
    /// `p` (propagate) / `*`
    pub propagate: bool,
    /// Parsed client; `None` is MIT `*` (any).
    client: Option<PrincPat>,
    /// Parsed target; `None` is missing or `*` (any).
    target: Option<PrincPat>,
    /// Optional restrictions imposed on create/modify.
    pub restrictions: Option<Restrictions>,
}

/// Ordered ACL; first matching principal wins. Unlisted principals are denied.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Acl {
    entries: Vec<AclEntry>,
}

impl Acl {
    /// Empty deny-all ACL.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse kadm5.acl text (`auth_acl.c` `load_acl_file`).
    ///
    /// # Errors
    ///
    /// [`Error::AclParse`] on syntax, unknown op letter, or restriction errors.
    pub fn parse(text: &str) -> Result<Self, Error> {
        Self::parse_with_realm(text, "")
    }

    /// Like [`Self::parse`] with MIT `krb5_parse_name` default realm.
    ///
    /// # Errors
    ///
    /// [`Error::AclParse`] on syntax, unknown op letter, or restriction errors.
    pub fn parse_with_realm(text: &str, default_realm: &str) -> Result<Self, Error> {
        let mut entries = Vec::new();
        for line in logical_lines(text) {
            entries.push(parse_line(&line, default_realm)?);
        }
        Ok(Self { entries })
    }

    /// Allow `admin@REALM` every mutating op.
    ///
    /// # Errors
    ///
    /// [`Error::AclParse`] when `admin` is not a principal name.
    pub fn allow_admin(admin: impl Into<String>) -> Result<Self, Error> {
        let principal = admin.into();
        let client = Some(parse_princ_pat(&principal)?);
        Ok(Self {
            entries: vec![AclEntry {
                principal,
                add: true,
                delete: true,
                inquire: true,
                extract: true,
                changepw: true,
                modify: true,
                setkey: true,
                list: true,
                propagate: true,
                client,
                target: None,
                restrictions: None,
            }],
        })
    }

    /// Check whether `actor` may perform `op` on `target` (`auth_acl.c` `acl_check`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::AclDenied`] when no matching line grants the op.
    pub fn check(&self, actor: &str, op: AdminOp, target: Option<&str>) -> Result<(), Error> {
        let Some(e) = self.find(actor, target) else {
            return deny(actor, op);
        };
        let ok = match op {
            AdminOp::Create => e.add,
            AdminOp::Delete => e.delete,
            AdminOp::Inquire => e.inquire,
            AdminOp::Ktadd | AdminOp::Extract => e.extract,
            AdminOp::ChangePassword => e.changepw,
            AdminOp::Modify => e.modify,
            AdminOp::SetKey => e.setkey,
            AdminOp::List => e.list,
            AdminOp::Propagate => e.propagate,
        };
        if ok {
            tracing::info!(
                event = krb5_log::events::KDC_ACL,
                component = "krb5-kdc",
                outcome = "ok",
                actor,
                op = op_name(op),
            );
            return Ok(());
        }
        deny(actor, op)
    }

    /// Rename: delete on `src` and add on `dest` with no restrictions
    /// (`auth_acl.c:638-648` `acl_renprinc`).
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`].
    pub fn check_rename(&self, actor: &str, src: &str, dest: &str) -> Result<(), Error> {
        self.check(actor, AdminOp::Delete, Some(src))?;
        self.check(actor, AdminOp::Create, Some(dest))?;
        if self
            .find(actor, Some(dest))
            .is_some_and(|e| e.restrictions.is_some())
        {
            return deny(actor, AdminOp::Create);
        }
        Ok(())
    }

    /// Restrictions on the matching entry, if any.
    #[must_use]
    pub fn restrictions(&self, actor: &str, target: Option<&str>) -> Option<&Restrictions> {
        self.find(actor, target)
            .and_then(|e| e.restrictions.as_ref())
    }

    /// MIT `kadm5_get_privs` mask for `actor` (`KADM5_PRIV_*`, 0 if none).
    #[must_use]
    pub fn privs(&self, actor: &str) -> u32 {
        for e in &self.entries {
            if !client_matches(e, actor) {
                continue;
            }
            let mut bits = 0u32;
            if e.inquire {
                bits |= 0x01;
            }
            if e.add {
                bits |= 0x02;
            }
            if e.modify {
                bits |= 0x04;
            }
            if e.delete {
                bits |= 0x08;
            }
            if e.list {
                bits |= 0x10;
            }
            if e.changepw {
                bits |= 0x20;
            }
            if e.extract {
                bits |= 0x40;
            }
            return bits;
        }
        0
    }

    /// kadm5.acl principal glob (`*/admin@REALM`, `host/*@REALM`).
    #[must_use]
    pub fn name_matches(pattern: &str, actor: &str) -> bool {
        principal_matches(pattern, actor)
    }

    fn find(&self, actor: &str, target: Option<&str>) -> Option<&AclEntry> {
        let actor_pat = parse_princ_pat(actor).ok()?;
        let target_pat = target.and_then(|t| parse_princ_pat(t).ok());
        for e in &self.entries {
            let mut ws = WildState::default();
            if let Some(ref client) = e.client
                && !match_princ(client, &actor_pat, false, Some(&mut ws))
            {
                continue;
            }
            if let Some(ref tpat) = e.target {
                let Some(ref actual) = target_pat else {
                    continue;
                };
                if !match_princ(tpat, actual, true, Some(&mut ws)) {
                    continue;
                }
            }
            return Some(e);
        }
        None
    }
}

fn deny(actor: &str, op: AdminOp) -> Result<(), Error> {
    tracing::error!(
        event = krb5_log::events::KDC_ACL,
        component = "krb5-kdc",
        outcome = "error",
        actor,
        op = op_name(op),
        error = "ACL denied",
    );
    Err(Error::AclDenied)
}

fn op_name(op: AdminOp) -> &'static str {
    match op {
        AdminOp::Create => "create",
        AdminOp::Delete => "delete",
        AdminOp::Ktadd => "ktadd",
        AdminOp::ChangePassword => "cpw",
        AdminOp::Inquire => "inquire",
        AdminOp::Extract => "extract",
        AdminOp::Modify => "modify",
        AdminOp::SetKey => "setkey",
        AdminOp::List => "list",
        AdminOp::Propagate => "propagate",
    }
}

const ACL_WS: [char; 7] = [' ', '\t', '\n', '\u{000c}', '\u{000b}', '\r', ','];

#[derive(Clone, Debug, PartialEq, Eq)]
struct PrincPat {
    components: Vec<String>,
    realm: String,
}

#[derive(Default)]
struct WildState {
    backref: Vec<String>,
}

/// MIT `auth_acl.c:102-153` `get_line`: `\` continuation; `#` only at column 0.
fn logical_lines(text: &str) -> Vec<String> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut continuing = false;
    for raw in text.split_inclusive('\n') {
        let mut chunk = raw.strip_suffix('\n').unwrap_or(raw);
        chunk = chunk.strip_suffix('\r').unwrap_or(chunk);
        if continuing {
            if let Some(stripped) = chunk.strip_suffix('\\') {
                buf.push_str(stripped);
                continue;
            }
            buf.push_str(chunk);
            continuing = false;
            if !buf.is_empty() && !buf.starts_with('#') {
                out.push(std::mem::take(&mut buf));
            } else {
                buf.clear();
            }
            continue;
        }
        if let Some(stripped) = chunk.strip_suffix('\\') {
            buf = stripped.to_string();
            continuing = true;
            continue;
        }
        if chunk.is_empty() || chunk.starts_with('#') {
            continue;
        }
        out.push(chunk.to_owned());
    }
    if continuing && !buf.is_empty() && !buf.starts_with('#') {
        out.push(buf);
    }
    out
}

fn parse_line(line: &str, default_realm: &str) -> Result<AclEntry, Error> {
    let (client_s, ops, target_s, rs_s) = split_fields(line);
    if client_s.is_empty() || ops.is_empty() {
        return Err(Error::AclParse(format!("syntax error: {line}")));
    }
    let mut add = false;
    let mut delete = false;
    let mut inquire = false;
    let mut extract = false;
    let mut changepw = false;
    let mut modify = false;
    let mut setkey = false;
    let mut list = false;
    let mut propagate = false;
    for ch in ops.chars() {
        let rop = ch.to_ascii_lowercase();
        let grant = rop == ch;
        match rop {
            'a' => add = grant,
            'd' => delete = grant,
            'i' => inquire = grant,
            'e' => extract = grant,
            'c' => changepw = grant,
            'm' => modify = grant,
            's' => setkey = grant,
            'l' => list = grant,
            'p' => propagate = grant,
            '*' | 'x' => {
                add = grant;
                delete = grant;
                inquire = grant;
                changepw = grant;
                modify = grant;
                setkey = grant;
                list = grant;
                propagate = grant;
            }
            _ => {
                return Err(Error::AclParse(format!(
                    "Unrecognized ACL operation '{ch}'"
                )));
            }
        }
    }
    let client = if client_s == "*" {
        None
    } else {
        Some(parse_princ_pat_in(&client_s, default_realm)?)
    };
    let target = match target_s.as_deref() {
        None | Some("*") => None,
        Some(t) => Some(parse_princ_pat_in(t, default_realm)?),
    };
    let restrictions = match rs_s.as_deref() {
        None => None,
        Some(rs) => Some(parse_restrictions(rs)?),
    };
    Ok(AclEntry {
        principal: client_s,
        add,
        delete,
        inquire,
        extract,
        changepw,
        modify,
        setkey,
        list,
        propagate,
        client,
        target,
        restrictions,
    })
}

fn split_fields(line: &str) -> (String, String, Option<String>, Option<String>) {
    let line = line.trim_end_matches([' ', '\t', '\n', '\u{000c}', '\u{000b}', '\r']);
    let mut rest = line;
    let mut take = || {
        rest = rest.trim_start_matches(ACL_WS.as_slice());
        if rest.is_empty() {
            return None;
        }
        let end = rest.find(ACL_WS.as_slice()).unwrap_or(rest.len());
        let field = rest[..end].to_owned();
        rest = &rest[end..];
        Some(field)
    };
    let client = take().unwrap_or_default();
    let ops = take().unwrap_or_default();
    let target = take();
    rest = rest.trim_start_matches(ACL_WS.as_slice());
    let rs = if rest.is_empty() {
        None
    } else {
        Some(rest.to_owned())
    };
    (client, ops, target, rs)
}

fn parse_princ_pat(s: &str) -> Result<PrincPat, Error> {
    parse_princ_pat_in(s, "")
}

fn parse_princ_pat_in(s: &str, default_realm: &str) -> Result<PrincPat, Error> {
    let (name, realm) = match s.rsplit_once('@') {
        Some((n, r)) => (n, r.to_owned()),
        None => (s, default_realm.to_owned()),
    };
    if name.is_empty() {
        return Err(Error::AclParse(format!("Cannot parse principal '{s}'")));
    }
    let components: Vec<String> = name.split('/').map(str::to_owned).collect();
    if components.iter().any(String::is_empty) {
        return Err(Error::AclParse(format!("Cannot parse principal '{s}'")));
    }
    Ok(PrincPat { components, realm })
}

fn parse_restrictions(str: &str) -> Result<Restrictions, Error> {
    let mut rs = Restrictions::default();
    let tokens: Vec<&str> = str
        .split(ACL_WS.as_slice())
        .filter(|t| !t.is_empty())
        .collect();
    let mut i = 0;
    while i < tokens.len() {
        let token = tokens[i];
        if flagspec_to_mask(token, &mut rs.require_attrs, &mut rs.forbid_attrs) {
            i += 1;
            continue;
        }
        if token == "-clearpolicy" {
            rs.clear_policy = true;
            i += 1;
            continue;
        }
        let arg = tokens.get(i + 1).copied();
        let Some(arg) = arg else {
            return Err(Error::AclParse(format!("invalid restrictions: {str}")));
        };
        if token == "-policy" {
            if rs.policy.is_some() {
                return Err(Error::AclParse(format!("invalid restrictions: {str}")));
            }
            rs.policy = Some(arg.to_owned());
            i += 2;
            continue;
        }
        let Some(delta) = parse_deltat(arg) else {
            return Err(Error::AclParse(format!("invalid restrictions: {str}")));
        };
        match token {
            "-expire" => rs.expire = Some(delta),
            "-pwexpire" => rs.pwexpire = Some(delta),
            "-maxlife" => rs.max_life = Some(delta),
            "-maxrenewlife" => rs.max_renewable_life = Some(delta),
            _ => return Err(Error::AclParse(format!("invalid restrictions: {str}"))),
        }
        i += 2;
    }
    Ok(rs)
}

/// MIT `str_conv.c:50-95`.
const FLAG_TABLE: &[(&str, u32, bool)] = &[
    ("allow_postdated", KDB_DISALLOW_POSTDATED, true),
    ("postdateable", KDB_DISALLOW_POSTDATED, true),
    ("disallow_postdated", KDB_DISALLOW_POSTDATED, false),
    ("allow_forwardable", KDB_DISALLOW_FORWARDABLE, true),
    ("forwardable", KDB_DISALLOW_FORWARDABLE, true),
    ("disallow_forwardable", KDB_DISALLOW_FORWARDABLE, false),
    ("allow_tgs_req", KDB_DISALLOW_TGT_BASED, true),
    ("tgt_based", KDB_DISALLOW_TGT_BASED, true),
    ("disallow_tgt_based", KDB_DISALLOW_TGT_BASED, false),
    ("allow_renewable", KDB_DISALLOW_RENEWABLE, true),
    ("renewable", KDB_DISALLOW_RENEWABLE, true),
    ("disallow_renewable", KDB_DISALLOW_RENEWABLE, false),
    ("allow_proxiable", KDB_DISALLOW_PROXIABLE, true),
    ("proxiable", KDB_DISALLOW_PROXIABLE, true),
    ("disallow_proxiable", KDB_DISALLOW_PROXIABLE, false),
    ("allow_dup_skey", KDB_DISALLOW_DUP_SKEY, true),
    ("dup_skey", KDB_DISALLOW_DUP_SKEY, true),
    ("disallow_dup_skey", KDB_DISALLOW_DUP_SKEY, false),
    ("allow_tickets", KDB_DISALLOW_ALL_TIX, true),
    ("allow_tix", KDB_DISALLOW_ALL_TIX, true),
    ("disallow_all_tix", KDB_DISALLOW_ALL_TIX, false),
    ("preauth", KDB_REQUIRES_PRE_AUTH, false),
    ("requires_pre_auth", KDB_REQUIRES_PRE_AUTH, false),
    ("requires_preauth", KDB_REQUIRES_PRE_AUTH, false),
    ("hwauth", KDB_REQUIRES_HW_AUTH, false),
    ("requires_hw_auth", KDB_REQUIRES_HW_AUTH, false),
    ("requires_hwauth", KDB_REQUIRES_HW_AUTH, false),
    ("needchange", KDB_REQUIRES_PWCHANGE, false),
    ("pwchange", KDB_REQUIRES_PWCHANGE, false),
    ("requires_pwchange", KDB_REQUIRES_PWCHANGE, false),
    ("allow_svr", KDB_DISALLOW_SVR, true),
    ("service", KDB_DISALLOW_SVR, true),
    ("disallow_svr", KDB_DISALLOW_SVR, false),
    ("password_changing_service", KDB_PWCHANGE_SERVICE, false),
    ("pwchange_service", KDB_PWCHANGE_SERVICE, false),
    ("pwservice", KDB_PWCHANGE_SERVICE, false),
    ("md5", KDB_SUPPORT_DESMD5, false),
    ("support_desmd5", KDB_SUPPORT_DESMD5, false),
    ("new_princ", KDB_NEW_PRINC, false),
    ("ok_as_delegate", KDB_OK_AS_DELEGATE, false),
    ("ok_to_auth_as_delegate", KDB_OK_TO_AUTH_AS_DELEGATE, false),
    ("no_auth_data_required", KDB_NO_AUTH_DATA_REQUIRED, false),
    ("lockdown_keys", KDB_LOCKDOWN_KEYS, false),
];

/// MIT `krb5_flagspec_to_mask` (`str_conv.c:170-198`).
fn flagspec_to_mask(spec: &str, toset: &mut u32, toclear: &mut u32) -> bool {
    let (req_neg, body) = if let Some(rest) = spec.strip_prefix('-') {
        (true, rest)
    } else if let Some(rest) = spec.strip_prefix('+') {
        (false, rest)
    } else {
        (false, spec)
    };
    let s: String = body
        .chars()
        .map(|c| {
            let c = if c == '-' { '_' } else { c };
            c.to_ascii_lowercase()
        })
        .collect();
    let (flag, mut invert) =
        if let Some((_, flag, invert)) = FLAG_TABLE.iter().copied().find(|(n, _, _)| *n == s) {
            (flag, invert)
        } else if let Some(hex) = s.strip_prefix("0x") {
            let digits: String = hex.chars().take_while(char::is_ascii_hexdigit).collect();
            let flag = u32::from_str_radix(&digits, 16).unwrap_or(0);
            (flag, false)
        } else {
            return false;
        };
    if req_neg {
        invert = !invert;
    }
    if invert {
        *toclear &= !flag;
    } else {
        *toset |= flag;
    }
    true
}

fn parse_deltat(s: &str) -> Option<u64> {
    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }
    let mut total = 0u64;
    let mut num = 0u64;
    let mut seen = false;
    let mut have_unit = false;
    for c in s.chars() {
        if c.is_ascii_digit() {
            num = num
                .saturating_mul(10)
                .saturating_add(u64::from(c as u8 - b'0'));
            seen = true;
            have_unit = false;
        } else {
            let mul = match c {
                's' | 'S' => 1,
                'm' | 'M' => 60,
                'h' | 'H' => 3600,
                'd' | 'D' => 86400,
                'w' | 'W' => 7 * 86400,
                _ => return None,
            };
            total = total.saturating_add(num.saturating_mul(mul));
            num = 0;
            have_unit = true;
        }
    }
    if !seen {
        return None;
    }
    if !have_unit && num != 0 {
        total = total.saturating_add(num);
    } else if !have_unit {
        return None;
    }
    Some(total)
}

fn match_data(pat: &str, actual: &str, targetflag: bool, ws: Option<&mut WildState>) -> bool {
    if pat == "*" {
        if let Some(ws) = ws
            && !targetflag
            && ws.backref.len() < 9
        {
            ws.backref.push(actual.to_owned());
        }
        return true;
    }
    if targetflag && let Some(ws) = ws {
        let b = pat.as_bytes();
        if b.len() == 2 && b[0] == b'*' && (b'1'..=b'9').contains(&b[1]) {
            let n = usize::from(b[1] - b'1');
            return ws.backref.get(n).is_some_and(|s| s == actual);
        }
    }
    pat == actual
}

fn match_princ(
    pat: &PrincPat,
    actual: &PrincPat,
    targetflag: bool,
    mut ws: Option<&mut WildState>,
) -> bool {
    if pat.components.len() != actual.components.len() {
        return false;
    }
    if !match_data(&pat.realm, &actual.realm, targetflag, None) {
        return false;
    }
    for (p, a) in pat.components.iter().zip(actual.components.iter()) {
        if !match_data(p, a, targetflag, ws.as_deref_mut()) {
            return false;
        }
    }
    true
}

fn client_matches(e: &AclEntry, actor: &str) -> bool {
    let Ok(actor_pat) = parse_princ_pat(actor) else {
        return false;
    };
    match e.client {
        None => true,
        Some(ref c) => match_princ(c, &actor_pat, false, None),
    }
}

fn principal_matches(pattern: &str, actor: &str) -> bool {
    if pattern == actor {
        return true;
    }
    let (Ok(p), Ok(a)) = (parse_princ_pat(pattern), parse_princ_pat(actor)) else {
        return false;
    };
    match_princ(&p, &a, false, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acl_uppercase_letter_revokes() {
        let acl = Acl::parse("admin@KERBER.TEST *D\n").unwrap();
        assert!(
            acl.check("admin@KERBER.TEST", AdminOp::Create, None)
                .is_ok()
        );
        assert_eq!(
            acl.check("admin@KERBER.TEST", AdminOp::Delete, None)
                .unwrap_err(),
            Error::AclDenied
        );
        assert!(
            acl.check("admin@KERBER.TEST", AdminOp::Inquire, None)
                .is_ok()
        );
    }

    #[test]
    fn acl_unknown_op_letter_is_load_error() {
        let err = Acl::parse("bad@KERBER.TEST aZ\n").unwrap_err();
        assert!(
            err.to_string().contains("Unrecognized ACL operation 'Z'"),
            "{err}"
        );
    }

    #[test]
    fn acl_flag_aliases_parse() {
        let acl = Acl::parse(
            "admin@KERBER.TEST a *@KERBER.TEST -preauth +disallow_svr +0x80 -Allow-Tix\n",
        )
        .unwrap();
        let rs = acl
            .restrictions("admin@KERBER.TEST", Some("user@KERBER.TEST"))
            .expect("rs");
        assert_ne!(rs.require_attrs & KDB_DISALLOW_SVR, 0);
        assert_ne!(rs.require_attrs & KDB_DISALLOW_ALL_TIX, 0);
        assert_ne!(rs.require_attrs & KDB_REQUIRES_PRE_AUTH, 0);
        assert_eq!(rs.forbid_attrs & KDB_REQUIRES_PRE_AUTH, 0);
    }

    #[test]
    fn acl_comment_only_at_column_zero() {
        let acl = Acl::parse("# full line\nadmin@KERBER.TEST a\n").unwrap();
        assert!(
            acl.check("admin@KERBER.TEST", AdminOp::Create, None)
                .is_ok()
        );
        assert!(Acl::parse("   # not a comment\n").is_err());
        assert!(Acl::parse("   \n").is_err());
    }

    #[test]
    fn acl_backslash_continuation() {
        let acl = Acl::parse("admin@KERBER.TEST \\\n a\n").unwrap();
        assert!(
            acl.check("admin@KERBER.TEST", AdminOp::Create, None)
                .is_ok()
        );
    }

    #[test]
    fn acl_allow_admin_rejects_unparseable() {
        assert!(Acl::allow_admin("").is_err());
        assert!(Acl::allow_admin("@KERBER.TEST").is_err());
        assert!(Acl::allow_admin("a//b@KERBER.TEST").is_err());
    }

    #[test]
    fn acl_unknown_restriction_is_load_error() {
        assert!(Acl::parse("admin@KERBER.TEST * *@KERBER.TEST -notatoken\n").is_err());
    }

    #[test]
    fn acl_restriction_clearpolicy_is_imposed() {
        let acl = Acl::parse("restricted@KERBER.TEST a *@KERBER.TEST -clearpolicy\n").unwrap();
        let rs = acl
            .restrictions("restricted@KERBER.TEST", Some("user9@KERBER.TEST"))
            .expect("rs");
        assert!(rs.clear_policy);
    }

    #[test]
    fn acl_target_star_is_any_check() {
        let acl = Acl::parse("admin@KERBER.TEST a *\n").unwrap();
        assert!(
            acl.check(
                "admin@KERBER.TEST",
                AdminOp::Create,
                Some("svc/x@KERBER.TEST")
            )
            .is_ok()
        );
    }
}
