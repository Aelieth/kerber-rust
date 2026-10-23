use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt_enc_data};
use krb5_protocol::{
    AUTH_CONTEXT_DO_SEQUENCE, AUTH_CONTEXT_USE_SUBKEY, AcceptorAuthContext, AcceptorConfig,
    ApAuthenticator, KeytabGetEntry, ReplayCache, build_ap_req_from_authenticator,
    generate_ap_authenticator, generate_seq_number,
};
use krb5_types::{
    ApOptions, ApRep, AuthorizationData, AuthorizationDataValue, Checksum, EncApRepPart,
    EncryptionKey, HostAddress, KerberosTime, PrincipalName, Realm, Ticket, ku, pa,
};

use super::deleg::{DelegCred, extract_delegated, krb_cred_for_deleg};
use super::oid::{
    GSS_C_CHANNEL_BOUND, GSS_C_CONF, GSS_C_DCE, GSS_C_DELEG, GSS_C_EXTENDED_ERROR, GSS_C_IDENTIFY,
    GSS_C_INTEG, GSS_C_MUTUAL, GSS_C_PROT_READY, GSS_C_REPLAY, GSS_C_SEQUENCE, GSS_C_TRANS,
    GSS_CHECKSUM_TYPE, gss_unwrap_app, gss_wrap_app,
};
use super::seqstate::{SeqState, SeqStatus};
use super::{Error, GssContext};

pub(super) const TOK_AP_REQ: [u8; 2] = [0x01, 0x00];

pub(super) const TOK_AP_REP: [u8; 2] = [0x02, 0x00];

pub(super) const FLAG_ACCEPTOR_SUBKEY: u8 = 0x04;

#[derive(Clone, Copy)]
struct AcceptKeys<'a> {
    keys: &'a [ProtocolKey],
    kvnos: Option<&'a [u32]>,
    get_entry: Option<KeytabGetEntry<'a>>,
}

const INITIATOR_FLAGS: u32 = GSS_C_INTEG
    | GSS_C_CONF
    | GSS_C_MUTUAL
    | GSS_C_REPLAY
    | GSS_C_SEQUENCE
    | GSS_C_DCE
    | GSS_C_IDENTIFY
    | GSS_C_EXTENDED_ERROR
    | GSS_C_CHANNEL_BOUND;

pub(super) const KRB5_GSS_FOR_CREDS: u16 = 1;

const GSS_EXTS_FINISHED: u32 = 2;

/// Channel bindings are hashed into the AP-REQ's 0x8003 checksum (RFC 2744).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChannelBindings {
    pub initiator_addrtype: u32,
    pub initiator_address: Vec<u8>,
    pub acceptor_addrtype: u32,
    pub acceptor_address: Vec<u8>,
    pub application_data: Vec<u8>,
}

impl ChannelBindings {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InquireOk {
    pub initiator: bool,
    pub flags: u32,
    pub lifetime: u32,
    pub client: Option<String>,
}

// MIT: `krb5_generate_subkey_extended` (lib/krb5/krb/gen_subkey.c:29-52)
// a random key of the session key's enctype.
pub(super) fn random_subkey(session: &ProtocolKey) -> Result<ProtocolKey, Error> {
    Ok(ProtocolKey::random(session.etype())?)
}

const FIELD_TOOLONG: &str = "Field is too long for this implementation";

// MIT: `kg_setup_keys` (lib/gssapi/krb5/util_crypt.c:99-125)
// DES3 and RC4 keys use the pre-CFX tokens, every other enctype CFX (`proto` 1).
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

// MIT: `kg_process_extension` (accept_sec_context.c:381-383)
// a finished extension is
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
    pub fn for_kadm5_acceptor(
        acceptor: PrincipalName,
        ticket_realm: impl Into<String>,
    ) -> Result<Self, Error> {
        Ok(Self {
            session: ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0u8; 32])?,
            acceptor_subkey: None,
            send_seq: 0,
            recv: SeqState::new(0, 0, true),
            initiator: false,
            client: None,
            delegated: None,
            spnego_mech_list: None,
            lifetime_end: 0,
            acceptor_skew: 0,
            gss_flags: 0,
            ticket_initial: false,
            acceptor: Some(acceptor),
            ticket_realm: Some(ticket_realm.into()),
            ap_rep_key: None,
            dce_style: false,
            ap_req_time: None,
        })
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the initiator's ticket, flags, and profile"
    )]
    pub fn init_sec_context(
        ticket: Ticket,
        session: &ProtocolKey,
        crealm: &Realm,
        cname: &PrincipalName,
        req_flags: u32,
        channel_bindings: Option<&ChannelBindings>,
        deleg: Option<&DelegCred>,
        profile: Option<&krb5_config::Krb5Conf>,
        time_offset: i64,
    ) -> Result<(Self, Vec<u8>), Error> {
        // MIT kg_new_connection; see docs/parity/b1-gss.md
        // MIT: `kg_new_connection` (lib/gssapi/krb5/init_sec_context.c:486)
        let cbt = req_flags & GSS_C_CHANNEL_BOUND != 0;
        // MIT: `kg_new_connection` (lib/gssapi/krb5/init_sec_context.c:544-550)
        let mut flags = req_flags & (INITIATOR_FLAGS & !GSS_C_DCE & !GSS_C_CHANNEL_BOUND)
            | GSS_C_TRANS
            | GSS_C_CONF
            | GSS_C_INTEG;
        let opts = if flags & GSS_C_MUTUAL != 0 {
            ApOptions::mutual_required()
        } else {
            ApOptions::none()
        };
        let deleg_der = if let Some(d) = deleg {
            flags |= GSS_C_DELEG;
            let der = krb_cred_for_deleg(session, d)?;
            // MIT make_gss_checksum; see docs/parity/b1-gss.md
            if der.len() + 28 > 65_535 {
                return Err(Error::Inner(FIELD_TOOLONG.into()));
            }
            Some(der)
        } else {
            None
        };
        let cksum = Checksum {
            cksumtype: GSS_CHECKSUM_TYPE,
            checksum: authenticator_checksum(channel_bindings, flags, deleg_der.as_deref()).into(),
        };
        let sub = random_subkey(session)?;
        let sub_etype = sub.etype().to_iana();
        let enc_sub = EncryptionKey {
            keytype: sub.etype().to_iana(),
            keyvalue: sub.as_bytes().to_vec().into(),
        };
        // MIT: `krb5_mk_req_extended` (lib/krb5/krb/mk_req_ext.c:136-143)
        // MIT: `krb5_mk_req_extended` (lib/krb5/krb/mk_req_ext.c:187-194)
        let seq = generate_seq_number()?;
        let desired = if flags & GSS_C_MUTUAL != 0 {
            match profile {
                Some(conf) => krb5_protocol::conf_etypes(conf, true),
                None => krb5_crypto::EncryptionType::preferred()
                    .iter()
                    .map(|etype| etype.to_iana())
                    .collect(),
            }
        } else {
            Vec::new()
        };
        let authenticator = generate_ap_authenticator(ApAuthenticator {
            crealm,
            cname,
            cksum: Some(cksum),
            subkey: Some(enc_sub),
            sequence: Some(seq),
            time_offset,
            cbt,
            desired_etypes: &desired,
            ticket_etype: session.etype().to_iana(),
            profile,
        })?;
        let ap = build_ap_req_from_authenticator(ticket, session, opts, &authenticator)?;
        let der = encode(&ap)?;
        let token = gss_wrap_app(TOK_AP_REQ, &der);
        Ok((
            Self {
                session: sub,
                acceptor_subkey: None,
                send_seq: u64::from(seq),
                // MIT: `kg_new_connection` (lib/gssapi/krb5/init_sec_context.c:632-634)
                recv: SeqState::new(
                    if flags & GSS_C_MUTUAL == 0 {
                        u64::from(seq)
                    } else {
                        0
                    },
                    flags,
                    !pre_cfx(sub_etype),
                ),
                initiator: true,
                client: Some(cname.unparse_with_realm(&String::from_utf8_lossy(crealm.as_bytes()))),
                delegated: None,
                spnego_mech_list: None,
                lifetime_end: 0,
                acceptor_skew: 0,
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

    pub fn accept_sec_context(
        token: &[u8],
        service_keys: &[ProtocolKey],
        channel_bindings: Option<&ChannelBindings>,
        expected_server: Option<&PrincipalName>,
        expected_realm: Option<&str>,
        rcache: &ReplayCache,
        conf: &AcceptorConfig,
    ) -> Result<(Self, Option<Vec<u8>>), Error> {
        Self::accept_sec_context_kt(
            token,
            service_keys,
            None,
            channel_bindings,
            expected_server,
            expected_realm,
            rcache,
            conf,
        )
    }

    // MIT try_one_princ; see docs/parity/b1-client.md
    #[expect(
        clippy::too_many_arguments,
        reason = "gss_accept_sec_context's inputs and the acceptor's profile"
    )]
    pub fn accept_sec_context_kt(
        token: &[u8],
        service_keys: &[ProtocolKey],
        service_kvnos: Option<&[u32]>,
        channel_bindings: Option<&ChannelBindings>,
        expected_server: Option<&PrincipalName>,
        expected_realm: Option<&str>,
        rcache: &ReplayCache,
        conf: &AcceptorConfig,
    ) -> Result<(Self, Option<Vec<u8>>), Error> {
        if service_keys.is_empty() {
            return Err(Error::Truncated);
        }
        Self::accept_inner(
            token,
            AcceptKeys {
                keys: service_keys,
                kvnos: expected_server.and(service_kvnos),
                get_entry: None,
            },
            channel_bindings,
            expected_server,
            expected_realm,
            rcache,
            conf,
        )
    }

    // MIT: `kg_accept_krb5` (accept_sec_context.c:829-831)
    // `krb5_rd_req_decoded` with the credential's `acceptor_mprinc` (NULL for `GSS_C_NO_NAME`) and its keytab.
    // MIT decrypt_try_server; see docs/parity/b1-client.md
    pub fn accept_sec_context_kdb(
        token: &[u8],
        acceptor: Option<&PrincipalName>,
        realm: &str,
        get_entry: KeytabGetEntry<'_>,
        channel_bindings: Option<&ChannelBindings>,
        rcache: &ReplayCache,
        conf: &AcceptorConfig,
    ) -> Result<(Self, Option<Vec<u8>>), Error> {
        Self::accept_inner(
            token,
            AcceptKeys {
                keys: &[],
                kvnos: None,
                get_entry: Some(get_entry),
            },
            channel_bindings,
            acceptor,
            Some(realm),
            rcache,
            conf,
        )
    }

    fn accept_inner(
        token: &[u8],
        keys: AcceptKeys<'_>,
        channel_bindings: Option<&ChannelBindings>,
        expected_server: Option<&PrincipalName>,
        expected_realm: Option<&str>,
        rcache: &ReplayCache,
        conf: &AcceptorConfig,
    ) -> Result<(Self, Option<Vec<u8>>), Error> {
        let dce_style = token.first() != Some(&0x60);
        let inner = ap_req_token(token)?;
        if inner.len() < 2 || inner[..2] != TOK_AP_REQ {
            return Err(Error::Truncated);
        }
        let replay = ReplayCache::new();
        let sender = channel_bindings
            .filter(|cb| cb.initiator_addrtype == crate::oid::GSS_C_AF_INET)
            .map(|cb| HostAddress {
                addr_type: HostAddress::ADDRTYPE_INET,
                address: cb.initiator_address.clone().into(),
            });
        let params = krb5_protocol::ApVerifyParams {
            expected_server,
            expected_realm,
            keys: keys.keys,
            key_kvnos: keys.kvnos,
            key_principals: None,
            kvno: None,
            get_entry: keys.get_entry,
            // MIT rd_req_decoded_opt; see docs/parity/b1-client.md
            skew: i64::from(conf.clockskew),
            ignore_acceptor_hostname: conf.ignore_acceptor_hostname,
            capaths: &conf.capaths,
            remote_addr: sender.as_ref(),
            now: None,
        };
        let ok = match krb5_protocol::verify_ap_req_ex(&inner[2..], &params, rcache, Some(b"")) {
            Ok(v) => v,
            Err(krb5_protocol::Error::Crypto(s)) if s.contains("integrity") => {
                return Err(Error::Integrity);
            }
            Err(e) => return Err(e.into()),
        };
        let mut ac = AcceptorAuthContext::from_ap_req(&ok, conf)?;
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
            &replay,
            ok.authenticator.authorization_data.as_ref(),
        )?;
        if dce_style {
            gss_flags |= GSS_C_MUTUAL | GSS_C_DCE;
        }
        gss_flags |= GSS_C_PROT_READY;
        let want_mutual = gss_flags & GSS_C_MUTUAL != 0;
        let sess = subkey.unwrap_or_else(|| ticket_session.clone());
        let sess_etype = sess.etype().to_iana();
        let base = ok.authenticator.seq_number.unwrap_or(0);
        let mut send_seq = u64::from(base);
        let mut acceptor_subkey = None;
        let mut ap_rep_tok = None;
        if want_mutual {
            let mut use_subkey = ac.ap_req_use_subkey();
            let cfx = !pre_cfx(sess.etype().to_iana());
            if !cfx && !dce_style && use_subkey && pre_cfx(ac.negotiated_etype().to_iana()) {
                use_subkey = false;
            }
            let generate_subkey = cfx || dce_style || use_subkey;
            if generate_subkey {
                ac.set_flags(ac.flags() | AUTH_CONTEXT_USE_SUBKEY);
            }
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
            recv: SeqState::new(u64::from(base), gss_flags, !pre_cfx(sess_etype)),
            initiator: false,
            client: Some(client),
            delegated,
            spnego_mech_list: None,
            lifetime_end: ok.ticket_part.endtime.unix_seconds(),
            acceptor_skew: conf.clockskew,
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

    pub fn accept_dce(&mut self, token: &[u8]) -> Result<(), Error> {
        if !self.dce_style {
            return Err(Error::Truncated);
        }
        let key = self.ap_rep_key.as_ref().ok_or(Error::Truncated)?;
        let ap: ApRep = decode(token)?;
        let usage = KeyUsage::new(ku::AP_REP_ENC_PART)?;
        let plain = decrypt_enc_data(key, usage, ap.enc_part.etype, ap.enc_part.cipher.as_ref())?;
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

    #[must_use]
    pub fn is_dce_style(&self) -> bool {
        self.dce_style
    }

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
        // MIT: `mutual_auth` (init_sec_context.c:785-794)
        // ticket session, then subkey.
        let etype = ap.enc_part.etype;
        let plain = decrypt_enc_data(ticket_session, usage, etype, cipher)
            .or_else(|_| decrypt_enc_data(&self.session, usage, etype, cipher))?;
        let part: EncApRepPart = decode(&plain)?;
        // MIT: `krb5_rd_rep` (rd_rep.c:106-111)
        // an AP-REP that does not echo the authenticator's time is not mutual authentication.
        if let Some((ctime, cusec)) = &self.ap_req_time
            && (part.ctime != *ctime || part.cusec.get() != cusec.get())
        {
            return Err(Error::Inner("Mutual authentication failed".into()));
        }
        self.recv = SeqState::new(
            u64::from(part.seq_number.unwrap_or(0)),
            self.gss_flags,
            !pre_cfx(self.session.etype().to_iana()),
        );
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

    #[must_use]
    pub fn session_key(&self) -> &ProtocolKey {
        &self.session
    }

    #[must_use]
    pub fn send_seq(&self) -> u64 {
        self.send_seq
    }

    #[must_use]
    pub fn ticket_is_initial(&self) -> bool {
        self.ticket_initial
    }

    #[must_use]
    pub fn inquire_context(&self) -> InquireOk {
        InquireOk {
            initiator: self.initiator,
            flags: self.gss_flags | GSS_C_TRANS,
            lifetime: self.lifetime(),
            client: self.client.clone(),
        }
    }

    #[must_use]
    pub fn endtime(&self) -> Option<u32> {
        (self.lifetime_end != 0).then_some(self.lifetime_end)
    }

    // MIT krb5_gss_context_time; see docs/parity/b1-gss.md
    #[must_use]
    pub fn lifetime(&self) -> u32 {
        if self.lifetime_end == 0 {
            return 0;
        }
        let now = i64::from(KerberosTime::now().unix_seconds());
        let start = now - i64::from(self.acceptor_skew);
        u32::try_from((i64::from(self.lifetime_end) - start).max(0)).unwrap_or(u32::MAX)
    }

    #[must_use]
    pub fn gss_flags(&self) -> u32 {
        self.gss_flags | GSS_C_TRANS
    }

    // MIT g_seqstate_check; see docs/parity/b1-gss.md
    pub(super) fn accept_seq(&mut self, seq: u64) -> Result<(), Error> {
        // MIT returns a replayed, old or out-of-window token's message with a supplementary status; we refuse it.
        let past = self.recv.do_replay && self.recv.past_window(seq);
        match self.recv.check(seq) {
            SeqStatus::Duplicate | SeqStatus::Old => Err(Error::Sequence),
            SeqStatus::Unseq if past => Err(Error::Sequence),
            SeqStatus::Complete | SeqStatus::Gap | SeqStatus::Unseq => Ok(()),
        }
    }
}
