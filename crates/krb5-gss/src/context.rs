//! Context establishment (`init_sec_context.c`, `accept_sec_context.c`,
//! `inq_context.c`, `context_time.c`, `get_tkt_flags.c`,
//! `generic/util_seqstate.c`, `util_cksum.c`): AP-REQ/AP-REP, channel
//! bindings, and the sequence window.

use std::sync::atomic::{AtomicBool, Ordering};

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt};
use krb5_protocol::{
    AUTH_CONTEXT_DO_SEQUENCE, AUTH_CONTEXT_USE_SUBKEY, AcceptorAuthContext, ReplayCache,
    build_ap_req_from_authenticator, permitted_enctypes, permitted_enctypes_kdc,
};
use krb5_types::{
    ApOptions, ApRep, Authenticator, AuthorizationData, AuthorizationDataValue, Checksum,
    EncApRepPart, EncryptionKey, KerberosTime, Microseconds, PrincipalName, Realm, Ticket, ku, pa,
};

use super::deleg::{DelegCred, extract_delegated, krb_cred_for_deleg};
use super::oid::{
    GSS_C_CHANNEL_BOUND, GSS_C_CONF, GSS_C_DCE, GSS_C_DELEG, GSS_C_EXTENDED_ERROR, GSS_C_IDENTIFY,
    GSS_C_INTEG, GSS_C_MUTUAL, GSS_C_PROT_READY, GSS_C_REPLAY, GSS_C_SEQUENCE, GSS_C_TRANS,
    GSS_CHECKSUM_TYPE, gss_unwrap_app, gss_wrap_app,
};
use super::{Error, GssContext};

pub(super) const TOK_AP_REQ: [u8; 2] = [0x01, 0x00];

pub(super) const TOK_AP_REP: [u8; 2] = [0x02, 0x00];

pub(super) const FLAG_ACCEPTOR_SUBKEY: u8 = 0x04;

/// Whether this process accepts on the KDC profile ([`use_kdc_context`]).
static KDC_CONTEXT: AtomicBool = AtomicBool::new(false);

/// From now on, accept every context with the KDC profile's enctype policy, kdc.conf's
/// `[libdefaults]` before krb5.conf's, as kadmind does.
/// MIT `krb5int_gss_use_kdc_context` (`lib/gssapi/krb5/init_sec_context.c:1018-1036`): the switch is process-wide, and every krb5 context made after it reads the KDC profile.
pub fn use_kdc_context() {
    KDC_CONTEXT.store(true, Ordering::Relaxed);
}

const INITIATOR_FLAGS: u32 = GSS_C_INTEG
    | GSS_C_CONF
    | GSS_C_MUTUAL
    | GSS_C_REPLAY
    | GSS_C_SEQUENCE
    | GSS_C_DCE
    | GSS_C_IDENTIFY
    | GSS_C_EXTENDED_ERROR;

pub(super) const KRB5_GSS_FOR_CREDS: u16 = 1;

const GSS_EXTS_FINISHED: u32 = 2;

/// RFC 2744 channel bindings (hashed into the AP-REQ 0x8003 checksum).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChannelBindings {
    /// Initiator address type.
    pub initiator_addrtype: u32,
    /// Initiator address octets.
    pub initiator_address: Vec<u8>,
    /// Acceptor address type.
    pub acceptor_addrtype: u32,
    /// Acceptor address octets.
    pub acceptor_address: Vec<u8>,
    /// Application data (TLS unique, …).
    pub application_data: Vec<u8>,
}

impl ChannelBindings {
    /// MD5 of the RFC 2744 encoding, or 16 zero octets when `None`.
    #[must_use]
    pub fn bnd_hash(cb: Option<&Self>) -> [u8; 16] {
        let Some(cb) = cb else {
            return [0u8; 16];
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(&cb.initiator_addrtype.to_le_bytes());
        buf.extend_from_slice(
            &u32::try_from(cb.initiator_address.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        buf.extend_from_slice(&cb.initiator_address);
        buf.extend_from_slice(&cb.acceptor_addrtype.to_le_bytes());
        buf.extend_from_slice(
            &u32::try_from(cb.acceptor_address.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        buf.extend_from_slice(&cb.acceptor_address);
        buf.extend_from_slice(
            &u32::try_from(cb.application_data.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        buf.extend_from_slice(&cb.application_data);
        md5_16(&buf)
    }
}

/// Result of [`GssContext::inquire_context`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InquireOk {
    /// True if this context is the initiator.
    pub initiator: bool,
    /// Established GSS flags (`GSS_C_*`), including `GSS_C_TRANS`.
    pub flags: u32,
    /// Remaining ticket lifetime in seconds (`0` if unknown or expired).
    pub lifetime: u32,
    /// Authenticated client `name@REALM`.
    pub client: Option<String>,
}

/// Per-message sequence window (RFC 4121 replay detection).
const SEQ_WINDOW: u64 = 32;

/// MIT `krb5_generate_subkey_extended` (`lib/krb5/krb/gen_subkey.c:29-52`): a random key of the session key's enctype.
pub(super) fn random_subkey(session: &ProtocolKey) -> Result<ProtocolKey, Error> {
    Ok(ProtocolKey::random(session.etype())?)
}

/// MIT `kg_setup_keys` (`lib/gssapi/krb5/util_crypt.c:99-125`): DES3 and RC4 keys use the pre-CFX tokens, every other enctype CFX (`proto` 1).
const fn pre_cfx(etype: i32) -> bool {
    matches!(etype, 16 | 23 | 24)
}

pub(super) fn authenticator_checksum(
    cb: Option<&ChannelBindings>,
    flags: u32,
    deleg_der: Option<&[u8]>,
) -> Vec<u8> {
    let extra = deleg_der.map_or(0, |d| 4 + d.len());
    let mut v = Vec::with_capacity(24 + extra);
    v.extend_from_slice(&16u32.to_le_bytes());
    v.extend_from_slice(&ChannelBindings::bnd_hash(cb));
    v.extend_from_slice(&flags.to_le_bytes());
    if let Some(der) = deleg_der {
        v.extend_from_slice(&KRB5_GSS_FOR_CREDS.to_le_bytes());
        let n = u16::try_from(der.len()).unwrap_or(u16::MAX);
        v.extend_from_slice(&n.to_le_bytes());
        v.extend_from_slice(der);
    }
    v
}

/// MIT `kg_process_extension` (`accept_sec_context.c:381-383`): a finished extension is
/// rejected unless this is an IAKERB acceptor.
/// A short extension header is an error, not a skipped option.
fn process_checksum(
    cksum: Option<&Checksum>,
    ap_mutual: bool,
    acceptor_cb: Option<&ChannelBindings>,
    ticket_session: &ProtocolKey,
    subkey: Option<&ProtocolKey>,
    replay: &ReplayCache,
    authdata: Option<&AuthorizationData>,
) -> Result<(u32, Option<String>), Error> {
    let mut flags_out = 0u32;
    let mut delegated = None;
    let mut cb_match = false;
    match cksum {
        None => {}
        Some(ck) if ck.cksumtype != GSS_CHECKSUM_TYPE => {
            flags_out = GSS_C_REPLAY | GSS_C_SEQUENCE;
            if ap_mutual {
                flags_out |= GSS_C_MUTUAL;
            }
        }
        Some(ck) => {
            let raw = ck.checksum.as_ref();
            if raw.len() < 24 {
                return Err(Error::ChannelBindings);
            }
            let cb_len = u32::from_le_bytes(raw[0..4].try_into().map_err(|_| Error::Truncated)?);
            if cb_len != 16 {
                return Err(Error::Inner("gss failure".into()));
            }
            let token_cb = &raw[4..20];
            if let Some(local) = acceptor_cb {
                let expect = ChannelBindings::bnd_hash(Some(local));
                let token_cb_present = token_cb.iter().any(|&b| b != 0);
                cb_match = token_cb == expect.as_slice();
                if token_cb_present && !cb_match {
                    return Err(Error::ChannelBindings);
                }
            }
            let token_flags =
                u32::from_le_bytes(raw[20..24].try_into().map_err(|_| Error::Truncated)?);
            flags_out = token_flags & INITIATOR_FLAGS;
            if cb_match {
                flags_out |= GSS_C_CHANNEL_BOUND;
            }
            let mut rest = &raw[24..];
            if rest.len() >= 4 && token_flags & GSS_C_DELEG != 0 {
                let option_id =
                    u16::from_le_bytes(rest[..2].try_into().map_err(|_| Error::Truncated)?);
                let option_len = usize::from(u16::from_le_bytes(
                    rest[2..4].try_into().map_err(|_| Error::Truncated)?,
                ));
                rest = &rest[4..];
                if rest.len() < option_len {
                    return Err(Error::Inner("gss failure".into()));
                }
                if option_id != KRB5_GSS_FOR_CREDS {
                    return Err(Error::Inner("gss failure".into()));
                }
                delegated = extract_delegated(raw, token_flags, subkey, ticket_session, replay)?;
                if delegated.is_some() {
                    flags_out |= GSS_C_DELEG;
                }
                rest = &rest[option_len..];
            }
            while !rest.is_empty() {
                if rest.len() < 8 {
                    return Err(Error::Inner("gss failure".into()));
                }
                let ext_type =
                    u32::from_be_bytes(rest[0..4].try_into().map_err(|_| Error::Truncated)?);
                // MIT `kg_process_extension` (`accept_sec_context.c:380-384`): GSS_EXTS_FINISHED
                // is IAKERB-only; a plain krb5 acceptor fails it.
                if ext_type == GSS_EXTS_FINISHED {
                    return Err(Error::Inner("gss failure".into()));
                }
                let option_len = usize::try_from(u32::from_be_bytes(
                    rest[4..8].try_into().map_err(|_| Error::Truncated)?,
                ))
                .map_err(|_| Error::Truncated)?;
                rest = &rest[8..];
                if rest.len() < option_len {
                    return Err(Error::Inner("gss failure".into()));
                }
                rest = &rest[option_len..];
            }
        }
    }
    let client_cbt = authenticator_cbt(authdata)?;
    if client_cbt && acceptor_cb.is_some() && !cb_match {
        return Err(Error::ChannelBindings);
    }
    Ok((flags_out, delegated))
}

fn authenticator_cbt(authdata: Option<&AuthorizationData>) -> Result<bool, Error> {
    const AD_AP_OPTIONS: i32 = 143;
    const KERB_AP_OPTIONS_CBT: u32 = 0x4000;
    fn find(els: &[AuthorizationDataValue]) -> Result<Option<[u8; 4]>, Error> {
        let mut hit = None;
        for el in els {
            if el.ad_type == pa::AD_IF_RELEVANT {
                let inner: AuthorizationData = decode(el.ad_data.as_ref())?;
                if let Some(d) = find(&inner)? {
                    return Ok(Some(d));
                }
            } else if el.ad_type == AD_AP_OPTIONS {
                if hit.is_some() {
                    return Err(Error::Inner("gss failure".into()));
                }
                if el.ad_data.len() != 4 {
                    return Err(Error::Inner("gss failure".into()));
                }
                let mut b = [0u8; 4];
                b.copy_from_slice(el.ad_data.as_ref());
                hit = Some(b);
            }
        }
        Ok(hit)
    }
    let Some(data) = find(authdata.map_or(&[][..], |a| a.as_slice()))? else {
        return Ok(false);
    };
    let v = u32::from_le_bytes(data);
    Ok(v & KERB_AP_OPTIONS_CBT != 0)
}

fn ap_req_token(token: &[u8]) -> Result<Vec<u8>, Error> {
    if token.first() == Some(&0x60) {
        return gss_unwrap_app(token);
    }
    let mut inner = Vec::with_capacity(2 + token.len());
    inner.extend_from_slice(&TOK_AP_REQ);
    inner.extend_from_slice(token);
    Ok(inner)
}

fn md5_16(data: &[u8]) -> [u8; 16] {
    use md5::{Digest, Md5};
    let out = Md5::digest(data);
    let mut a = [0u8; 16];
    a.copy_from_slice(&out);
    a
}

impl GssContext {
    /// Acceptor identity for kadm5 name/realm gates (no usable session).
    ///
    /// # Errors
    ///
    /// None: the fixed all-zero 32-byte AES-256 key always builds, so this is always `Ok`.
    pub fn for_kadm5_acceptor(
        acceptor: PrincipalName,
        ticket_realm: impl Into<String>,
    ) -> Result<Self, Error> {
        Ok(Self {
            session: ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0u8; 32])?,
            acceptor_subkey: None,
            send_seq: 0,
            recv_seq: 0,
            recv_seen: false,
            recv_window: std::collections::HashSet::new(),
            initiator: false,
            rpcsec_init_window: false,
            replay: ReplayCache::new(),
            client: None,
            delegated: None,
            spnego_mech_list: None,
            lifetime_end: 0,
            gss_flags: 0,
            ticket_initial: false,
            acceptor: Some(acceptor),
            ticket_realm: Some(ticket_realm.into()),
            ap_rep_key: None,
            dce_style: false,
            ap_req_time: None,
        })
    }

    /// Initiator: wrap a service ticket as a GSS initial token (AP-REQ).
    ///
    /// # Errors
    ///
    /// [`Error::Inner`] when the OS random source fails (for the subkey or a confounder), or the
    /// delegated KRB-CRED or the AP-REQ does not encode.
    pub fn init_sec_context(
        ticket: Ticket,
        session: &ProtocolKey,
        crealm: &Realm,
        cname: &PrincipalName,
        mutual: bool,
        channel_bindings: Option<&ChannelBindings>,
        deleg: Option<&DelegCred>,
    ) -> Result<(Self, Vec<u8>), Error> {
        let opts = if mutual {
            ApOptions::mutual_required()
        } else {
            ApOptions::none()
        };
        let mut flags = GSS_C_INTEG | GSS_C_CONF | GSS_C_REPLAY | GSS_C_SEQUENCE;
        if mutual {
            flags |= GSS_C_MUTUAL;
        }
        let deleg_der = if let Some(d) = deleg {
            flags |= GSS_C_DELEG;
            Some(krb_cred_for_deleg(session, d)?)
        } else {
            None
        };
        let cksum = Checksum {
            cksumtype: GSS_CHECKSUM_TYPE,
            checksum: authenticator_checksum(channel_bindings, flags, deleg_der.as_deref()).into(),
        };
        let sub = random_subkey(session)?;
        let enc_sub = EncryptionKey {
            keytype: sub.etype().to_iana(),
            keyvalue: sub.as_bytes().to_vec().into(),
        };
        let now = KerberosTime::now();
        let authenticator = Authenticator {
            authenticator_vno: Authenticator::VNO,
            crealm: crealm.clone(),
            cname: cname.clone(),
            cksum: Some(cksum),
            cusec: Microseconds::from_subsec_micros(now.0.timestamp_subsec_micros()),
            ctime: now,
            subkey: Some(enc_sub),
            seq_number: Some(0),
            authorization_data: None,
        };
        let ap = build_ap_req_from_authenticator(ticket, session, opts, &authenticator)?;
        let der = encode(&ap)?;
        let token = gss_wrap_app(TOK_AP_REQ, &der);
        Ok((
            Self {
                session: sub,
                acceptor_subkey: None,
                send_seq: 0,
                recv_seq: 0,
                recv_seen: false,
                recv_window: std::collections::HashSet::new(),
                initiator: true,
                rpcsec_init_window: false,
                replay: ReplayCache::new(),
                client: Some(cname.unparse_with_realm(&String::from_utf8_lossy(crealm.as_bytes()))),
                delegated: None,
                spnego_mech_list: None,
                lifetime_end: 0,
                gss_flags: flags,
                ticket_initial: false,
                acceptor: None,
                ticket_realm: Some(String::from_utf8_lossy(crealm.as_bytes()).into_owned()),
                ap_rep_key: None,
                dce_style: false,
                ap_req_time: Some((authenticator.ctime, authenticator.cusec)),
            },
            token,
        ))
    }

    /// Acceptor: verify the initial token with the service key.
    ///
    /// `expected_server` / `expected_realm` bind the ticket sname. Passing
    /// `None` accepts any principal the key decrypts; production acceptors
    /// must pass the keytab principal.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] when `service_keys` is empty, the GSS framing is bad or lacks the
    /// AP-REQ token ID, or a delegated KRB-CRED lacks its credential fields; [`Error::Integrity`]
    /// when the ticket or authenticator fails its integrity check; [`Error::ChannelBindings`] when
    /// the 0x8003 checksum is under 24 bytes or its bindings (sent or demanded) do not match;
    /// [`Error::Inner`] for every other refusal of the AP-REQ (a session key or subkey enctype
    /// outside `permitted_enctypes`, the KDC profile's after [`use_kdc_context`], among them),
    /// its subkey, 0x8003 checksum, authorization data, or delegated KRB-CRED, and when the
    /// AP-REP cannot be built.
    pub fn accept_sec_context(
        token: &[u8],
        service_keys: &[ProtocolKey],
        channel_bindings: Option<&ChannelBindings>,
        expected_server: Option<&PrincipalName>,
        expected_realm: Option<&str>,
        rcache: &ReplayCache,
    ) -> Result<(Self, Option<Vec<u8>>), Error> {
        Self::accept_sec_context_kt(
            token,
            service_keys,
            None,
            channel_bindings,
            expected_server,
            expected_realm,
            rcache,
        )
    }

    /// [`accept_sec_context`](Self::accept_sec_context) with a per-key kvno
    /// slice (parallel to `service_keys`, as read from a keytab).
    /// MIT `try_one_princ` (`rd_req_dec.c:325-347`): fetches the keytab entry by the exact
    /// ticket kvno when the server principal is fully specified; a wildcard name
    /// (`is_matching`) iterates instead. We mirror that: the kvnos pin the ticket kvno only
    /// when `expected_server` is `Some`.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] when `service_keys` is empty, the GSS framing is bad or lacks the
    /// AP-REQ token ID, or a delegated KRB-CRED lacks its credential fields; [`Error::Integrity`]
    /// when the ticket or authenticator fails its integrity check; [`Error::ChannelBindings`] when
    /// the 0x8003 checksum is under 24 bytes or its bindings (sent or demanded) do not match;
    /// [`Error::Inner`] for every other refusal of the AP-REQ (a session key or subkey enctype
    /// outside `permitted_enctypes`, the KDC profile's after [`use_kdc_context`], among them),
    /// its subkey, 0x8003 checksum, authorization data, or delegated KRB-CRED, and when the
    /// AP-REP cannot be built.
    pub fn accept_sec_context_kt(
        token: &[u8],
        service_keys: &[ProtocolKey],
        service_kvnos: Option<&[u32]>,
        channel_bindings: Option<&ChannelBindings>,
        expected_server: Option<&PrincipalName>,
        expected_realm: Option<&str>,
        rcache: &ReplayCache,
    ) -> Result<(Self, Option<Vec<u8>>), Error> {
        let first = service_keys.first().ok_or(Error::Truncated)?;
        let dce_style = token.first() != Some(&0x60);
        let inner = ap_req_token(token)?;
        if inner.len() < 2 || inner[..2] != TOK_AP_REQ {
            return Err(Error::Truncated);
        }
        let ctx = Self {
            session: first.clone(),
            acceptor_subkey: None,
            send_seq: 0,
            recv_seq: 0,
            recv_seen: false,
            recv_window: std::collections::HashSet::new(),
            initiator: false,
            rpcsec_init_window: false,
            replay: ReplayCache::new(),
            client: None,
            delegated: None,
            spnego_mech_list: None,
            lifetime_end: 0,
            gss_flags: 0,
            ticket_initial: false,
            acceptor: None,
            ticket_realm: None,
            ap_rep_key: None,
            dce_style,
            ap_req_time: None,
        };
        let params = krb5_protocol::ApVerifyParams {
            expected_server,
            expected_realm,
            keys: service_keys,
            // MIT pins the ticket kvno only on the fully specified (explicit
            // server) path; a wildcard acceptor name iterates every key.
            key_kvnos: expected_server.and(service_kvnos),
            kvno: None,
            skew: krb5_protocol::DEFAULT_SKEW,
            addresses: None,
            now: None,
        };
        let ok = match krb5_protocol::verify_ap_req_ex(&inner[2..], &params, rcache, Some(b"")) {
            Ok(v) => v,
            Err(krb5_protocol::Error::Crypto(s)) if s.contains("integrity") => {
                return Err(Error::Integrity);
            }
            Err(e) => return Err(e.into()),
        };
        // MIT `krb5_gss_init_context` (`init_sec_context.c:995-1016`): a process that asked for the KDC context accepts on the KDC profile.
        let permitted = if KDC_CONTEXT.load(Ordering::Relaxed) {
            permitted_enctypes_kdc()
        } else {
            permitted_enctypes()
        };
        // MIT `kg_accept_krb5` (`accept_sec_context.c:829-837`): `krb5_rd_req_decoded` negotiates the enctypes before the context exists, then the auth context takes `DO_SEQUENCE`.
        let mut ac = permitted.and_then(|p| AcceptorAuthContext::from_ap_req(&ok, &p))?;
        ac.set_flags(AUTH_CONTEXT_DO_SEQUENCE);
        let crealm = String::from_utf8_lossy(ok.ticket_part.crealm.as_bytes()).into_owned();
        let client = ok.authenticator.cname.unparse_with_realm(&crealm);
        let srealm = String::from_utf8_lossy(ok.srealm.as_bytes()).into_owned();
        let ticket_session = ProtocolKey::from_bytes(
            EncryptionType::from_iana(ok.ticket_part.key.keytype)
                .or_else(|_| EncryptionType::known(ok.ticket_part.key.keytype))?,
            ok.ticket_part.key.keyvalue.as_ref(),
        )?;
        let subkey = if let Some(sk) = &ok.authenticator.subkey {
            Some(ProtocolKey::from_bytes(
                EncryptionType::from_iana(sk.keytype)
                    .or_else(|_| EncryptionType::known(sk.keytype))?,
                sk.keyvalue.as_ref(),
            )?)
        } else {
            None
        };
        let (mut gss_flags, delegated) = process_checksum(
            ok.authenticator.cksum.as_ref(),
            ok.mutual_required,
            channel_bindings,
            &ticket_session,
            subkey.as_ref(),
            &ctx.replay,
            ok.authenticator.authorization_data.as_ref(),
        )?;
        if dce_style {
            gss_flags |= GSS_C_MUTUAL | GSS_C_DCE;
        }
        // MIT `kg_accept_krb5` (`accept_sec_context.c:1089-1089`): sets GSS_C_PROT_READY_FLAG on
        // the established single-leg context.
        gss_flags |= GSS_C_PROT_READY;
        let want_mutual = gss_flags & GSS_C_MUTUAL != 0;
        let sess = subkey.unwrap_or_else(|| ticket_session.clone());
        let base = ok.authenticator.seq_number.unwrap_or(0);
        // MIT `kg_accept_krb5` (`accept_sec_context.c:1107-1113`): without mutual authentication this side's sequence numbers start at the initiator's.
        let mut send_seq = u64::from(base);
        let mut acceptor_subkey = None;
        let mut ap_rep_tok = None;
        if want_mutual {
            // MIT `kg_accept_krb5` (`accept_sec_context.c:998-1037`): a CFX or DCE context, or a negotiated enctype other than the session key's that is not DES3 or RC4, gets an acceptor subkey.
            let mut use_subkey = ac.ap_req_use_subkey();
            let cfx = !pre_cfx(sess.etype().to_iana());
            if !cfx && !dce_style && use_subkey && pre_cfx(ac.negotiated_etype().to_iana()) {
                use_subkey = false;
            }
            let generate_subkey = cfx || dce_style || use_subkey;
            if generate_subkey {
                ac.set_flags(ac.flags() | AUTH_CONTEXT_USE_SUBKEY);
            }
            // MIT `kg_accept_krb5` (`accept_sec_context.c:1039-1064`): the AP-REP's random seq is the first this side sends, and its subkey keys every token after it.
            let ap_rep = ac.mk_rep()?;
            send_seq = u64::from(ac.local_seq());
            if generate_subkey {
                acceptor_subkey = ac.send_subkey().cloned();
            }
            let der = encode(&ap_rep)?;
            ap_rep_tok = Some(if dce_style {
                der
            } else {
                gss_wrap_app(TOK_AP_REP, &der)
            });
        }
        let out = Self {
            session: sess,
            acceptor_subkey,
            send_seq,
            recv_seq: u64::from(base),
            recv_seen: false,
            recv_window: std::collections::HashSet::new(),
            initiator: false,
            rpcsec_init_window: false,
            replay: ctx.replay,
            client: Some(client),
            delegated,
            spnego_mech_list: None,
            lifetime_end: ok.ticket_part.endtime.unix_seconds(),
            gss_flags,
            ticket_initial: ok.ticket_part.flags.initial(),
            acceptor: Some(ok.sname.clone()),
            ticket_realm: Some(srealm),
            ap_rep_key: if dce_style {
                Some(ticket_session.clone())
            } else {
                None
            },
            dce_style,
            ap_req_time: None,
        };
        Ok((out, ap_rep_tok))
    }

    /// MIT `kg_accept_dce` / `krb5_rd_rep_dce`.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] when the context is not DCE-style or its AP-REP key is already spent;
    /// [`Error::Inner`] when the AP-REP or its enc-part does not decode or does not decrypt under
    /// the ticket session key; [`Error::Integrity`] when the enc-part carries a subkey or a
    /// sequence number other than this context's send sequence.
    pub fn accept_dce(&mut self, token: &[u8]) -> Result<(), Error> {
        if !self.dce_style {
            return Err(Error::Truncated);
        }
        let key = self.ap_rep_key.as_ref().ok_or(Error::Truncated)?;
        let ap: ApRep = decode(token)?;
        let usage = KeyUsage::new(ku::AP_REP_ENC_PART)?;
        let plain = decrypt(key, usage, ap.enc_part.cipher.as_ref())?;
        let part: EncApRepPart = decode(&plain)?;
        if part.subkey.is_some() {
            return Err(Error::Integrity);
        }
        let seq = part.seq_number.unwrap_or(0);
        if u64::from(seq) != self.send_seq {
            return Err(Error::Integrity);
        }
        self.ap_rep_key = None;
        Ok(())
    }

    /// True when the initial token was a raw DCE AP-REQ.
    #[must_use]
    pub fn is_dce_style(&self) -> bool {
        self.dce_style
    }

    /// Consume the acceptor's AP-REP token: its sequence number and its subkey.
    ///
    /// MIT `krb5_mk_rep` encrypts EncAPRepPart with the **ticket session**
    /// (`auth_context->key`), not the authenticator subkey.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] when the GSS framing is bad or lacks the AP-REP token ID;
    /// [`Error::Inner`] when the AP-REP or its enc-part does not decode, the enc-part decrypts
    /// under neither `ticket_session` nor the context key, it does not echo this context's
    /// authenticator time, or the acceptor subkey has an unknown etype or a wrong length.
    pub fn process_ap_rep(
        &mut self,
        token: &[u8],
        ticket_session: &ProtocolKey,
    ) -> Result<(), Error> {
        let inner = gss_unwrap_app(token)?;
        if inner.len() < 2 || inner[..2] != TOK_AP_REP {
            return Err(Error::Truncated);
        }
        let ap: ApRep = decode(&inner[2..])?;
        let usage = KeyUsage::new(ku::AP_REP_ENC_PART)?;
        let cipher = ap.enc_part.cipher.as_ref();
        // MIT `mutual_auth` (`init_sec_context.c:785-794`): ticket session, then subkey.
        let plain = decrypt(ticket_session, usage, cipher)
            .or_else(|_| decrypt(&self.session, usage, cipher))?;
        let part: EncApRepPart = decode(&plain)?;
        // MIT `krb5_rd_rep` (`rd_rep.c:106-111`): an AP-REP that does not echo the authenticator's time is not mutual authentication.
        if let Some((ctime, cusec)) = &self.ap_req_time
            && (part.ctime != *ctime || part.cusec.get() != cusec.get())
        {
            return Err(Error::Inner("Mutual authentication failed".into()));
        }
        // MIT `mutual_auth` (`init_sec_context.c:797-806`): the acceptor's sequence numbers start at the AP-REP's.
        self.recv_seq = u64::from(part.seq_number.unwrap_or(0));
        self.recv_seen = false;
        self.recv_window.clear();
        // MIT `mutual_auth` (`init_sec_context.c:808-825`): the acceptor's subkey is kept for a CFX or DCE context, or when its enctype is not the initiator subkey's.
        if let Some(sk) = part.subkey {
            let et = EncryptionType::from_iana(sk.keytype)
                .or_else(|_| EncryptionType::known(sk.keytype))?;
            let own = self.session.etype().to_iana();
            if !pre_cfx(own) || self.dce_style || sk.keytype != own {
                self.acceptor_subkey = Some(ProtocolKey::from_bytes(et, sk.keyvalue.as_ref())?);
            }
        }
        Ok(())
    }

    /// Session key established by the context (for tests and the acceptor binary).
    #[must_use]
    pub fn session_key(&self) -> &ProtocolKey {
        &self.session
    }

    /// MIT `gss_krb5_get_tkt_flags` INITIAL bit.
    #[must_use]
    pub fn ticket_is_initial(&self) -> bool {
        self.ticket_initial
    }

    /// Remaining lifetime, GSS flags, and names.
    #[must_use]
    pub fn inquire_context(&self) -> InquireOk {
        InquireOk {
            initiator: self.initiator,
            flags: self.gss_flags | GSS_C_TRANS,
            lifetime: self.lifetime(),
            client: self.client.clone(),
        }
    }

    /// Remaining ticket lifetime in seconds (`0` if unknown or expired).
    #[must_use]
    pub fn lifetime(&self) -> u32 {
        if self.lifetime_end == 0 {
            return 0;
        }
        let now = KerberosTime::now().unix_seconds();
        self.lifetime_end.saturating_sub(now)
    }

    /// Established GSS flags, including `GSS_C_TRANS`.
    #[must_use]
    pub fn gss_flags(&self) -> u32 {
        self.gss_flags | GSS_C_TRANS
    }

    /// MIT libgssrpc INIT verifier may skip GSS seq 0 (discarded window MIC).
    ///
    /// Only the iprop RPCSEC client sets this. Default wrap/MIC stays strict.
    pub fn allow_rpcsec_init_window(&mut self) {
        self.rpcsec_init_window = true;
    }

    pub(super) fn accept_seq(&mut self, seq: u64) -> Result<(), Error> {
        if self.recv_window.contains(&seq) {
            return Err(Error::Sequence);
        }
        if !self.recv_seen {
            if seq != self.recv_seq && !self.rpcsec_init_window {
                return Err(Error::Sequence);
            }
            self.recv_seen = true;
            self.recv_window.insert(seq);
            self.recv_seq = seq.wrapping_add(1);
            return Ok(());
        }
        let next = self.recv_seq;
        let too_old = seq.wrapping_add(SEQ_WINDOW) < next;
        let too_new = seq >= next.wrapping_add(SEQ_WINDOW);
        if too_old || too_new {
            return Err(Error::Sequence);
        }
        self.recv_window.insert(seq);
        if seq >= next {
            self.recv_seq = seq.wrapping_add(1);
        }
        Ok(())
    }
}
