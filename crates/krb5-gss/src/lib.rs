//! GSS-API Kerberos V5 mechanism (RFC 4121) and SPNEGO (RFC 4178).
//!
//! Interop with MIT `libgssapi_krb5` is out-of-process only. This crate
//! never links C libraries.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    EncryptionType, KeyUsage, ProtocolKey, checksum, decrypt, decrypt_cts, encrypt,
    encrypt_with_confounder, integrity_mac, verify_checksum,
};
use krb5_protocol::{ReplayCache, build_ap_rep, build_ap_req_with_cksum, unwrap_krb_cred};
use krb5_types::{
    ApOptions, ApRep, Checksum, EncApRepPart, EncKrbCredPart, EncryptedData, EncryptionKey,
    KerberosTime, KrbCred, KrbCredInfo, Microseconds, PrincipalName, Realm, Ticket, ku,
};
use thiserror::Error;

/// ISO OID 1.2.840.113554.1.2.2 (Kerberos V5 GSS).
pub const KRB5_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];
/// SPNEGO OID 1.3.6.1.5.5.2.
pub const SPNEGO_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

/// RFC 4121 checksum type in the AP-REQ authenticator (`0x8003`).
pub const GSS_CHECKSUM_TYPE: i32 = 0x8003;

const TOK_MIC: [u8; 2] = [0x04, 0x04];
const TOK_WRAP: [u8; 2] = [0x05, 0x04];
const TOK_AP_REQ: [u8; 2] = [0x01, 0x00];
const TOK_AP_REP: [u8; 2] = [0x02, 0x00];

const FLAG_SENT_BY_ACCEPTOR: u8 = 0x01;
const FLAG_SEALED: u8 = 0x02;
const FLAG_ACCEPTOR_SUBKEY: u8 = 0x04;

/// RFC 4121 `GSS_C_DELEG_FLAG`.
pub const GSS_C_DELEG: u32 = 1;
/// RFC 2744 `GSS_C_MUTUAL_FLAG`.
pub const GSS_C_MUTUAL: u32 = 2;
/// RFC 2744 `GSS_C_REPLAY_FLAG`.
pub const GSS_C_REPLAY: u32 = 4;
/// RFC 2744 `GSS_C_SEQUENCE_FLAG`.
pub const GSS_C_SEQUENCE: u32 = 8;
/// RFC 2744 `GSS_C_CONF_FLAG`.
pub const GSS_C_CONF: u32 = 16;
/// RFC 2744 `GSS_C_INTEG_FLAG`.
pub const GSS_C_INTEG: u32 = 32;
/// RFC 2744 `GSS_C_TRANS_FLAG` (context is exportable).
pub const GSS_C_TRANS: u32 = 256;
const KRB5_GSS_FOR_CREDS: u16 = 1;
const EXPORT_MAGIC: &[u8; 4] = b"K5G1";
const EXPORT_VERSION: u8 = 1;
const AES_CONFOUNDER: usize = 16;

/// GSS-API error.
#[derive(Debug, Error)]
pub enum Error {
    /// Protocol / crypto.
    #[error("{0}")]
    Inner(String),
    /// Integrity.
    #[error("gss integrity")]
    Integrity,
    /// Token too short.
    #[error("gss truncated")]
    Truncated,
    /// Sequence number replay or gap.
    #[error("gss sequence")]
    Sequence,
    /// Channel bindings mismatch.
    #[error("gss channel bindings")]
    ChannelBindings,
}

impl From<krb5_protocol::Error> for Error {
    fn from(e: krb5_protocol::Error) -> Self {
        Self::Inner(e.to_string())
    }
}

impl From<krb5_crypto::Error> for Error {
    fn from(e: krb5_crypto::Error) -> Self {
        Self::Inner(e.to_string())
    }
}

impl From<krb5_asn1::Error> for Error {
    fn from(e: krb5_asn1::Error) -> Self {
        Self::Inner(e.to_string())
    }
}

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

/// Established GSS context (initiator or acceptor).
pub struct GssContext {
    session: ProtocolKey,
    /// MIT CFX acceptor subkey from AP-REP (`FLAG_ACCEPTOR_SUBKEY`).
    acceptor_subkey: Option<ProtocolKey>,
    send_seq: u64,
    recv_seq: u64,
    recv_seen: bool,
    recv_window: std::collections::HashSet<u64>,
    initiator: bool,
    /// MIT libgssrpc INIT may spend GSS seq 0 on a discarded window MIC.
    rpcsec_init_window: bool,
    replay: ReplayCache,
    /// Authenticated client `name@REALM` (set on accept; initiator from cname).
    pub client: Option<String>,
    /// Delegated client from a 0x8003 KRB-CRED trailer (`GSS_C_DELEG_FLAG`).
    pub delegated: Option<String>,
    spnego_mech_list: Option<Vec<u8>>,
    lifetime_end: u32,
    gss_flags: u32,
}

/// GSS IOV buffer type (MIT `gssapi_ext.h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IovType {
    /// Confidentiality payload (encrypted in place).
    Data,
    /// Token header (GSS 16 + AES confounder ciphertext).
    Header,
    /// E(header) + HMAC.
    Trailer,
    /// Empty for AES-CTS / RFC 8009.
    Padding,
    /// Integrity-only associated data (RPCSEC_GSS header).
    SignOnly,
}

/// One wrap_iov buffer. HEADER/TRAILER/PADDING are resized; DATA is in-place.
pub struct IovBuf<'a> {
    /// Buffer role.
    pub kind: IovType,
    /// Backing storage.
    pub data: &'a mut Vec<u8>,
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

/// Forwarded TGT (or other ticket) to embed in a GSS delegation checksum.
#[derive(Clone, Debug)]
pub struct DelegCred {
    /// Ticket to forward.
    pub ticket: Ticket,
    /// Session key of `ticket` (goes in `KrbCredInfo.key`).
    pub session: ProtocolKey,
    /// Client realm.
    pub crealm: Realm,
    /// Client name.
    pub cname: PrincipalName,
}

/// Per-message sequence window (RFC 4121 replay detection).
const SEQ_WINDOW: u64 = 32;

impl GssContext {
    /// Initiator: wrap a service ticket as a GSS initial token (AP-REQ).
    ///
    /// # Errors
    ///
    /// Crypto / DER failures.
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
        let ap = build_ap_req_with_cksum(
            ticket,
            session,
            crealm,
            cname,
            opts,
            Some(cksum),
            Some(enc_sub),
        )?;
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
                client: Some(format!(
                    "{}@{}",
                    cname.components_joined(),
                    String::from_utf8_lossy(crealm.as_bytes())
                )),
                delegated: None,
                spnego_mech_list: None,
                lifetime_end: 0,
                gss_flags: flags,
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
    /// AP-REQ verify failures or channel-binding mismatch.
    pub fn accept_sec_context(
        token: &[u8],
        service_keys: &[ProtocolKey],
        channel_bindings: Option<&ChannelBindings>,
        expected_server: Option<&PrincipalName>,
        expected_realm: Option<&str>,
    ) -> Result<(Self, Option<Vec<u8>>), Error> {
        let first = service_keys.first().ok_or(Error::Truncated)?;
        let inner = gss_unwrap_app(token)?;
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
        };
        let params = krb5_protocol::ApVerifyParams {
            expected_server,
            expected_realm,
            keys: service_keys,
            kvno: None,
            skew: krb5_protocol::DEFAULT_SKEW,
            addresses: None,
            now: None,
        };
        let ok = krb5_protocol::verify_ap_req_ex(&inner[2..], &params, &ctx.replay, None)?;
        let client = format!(
            "{}@{}",
            ok.authenticator.cname.components_joined(),
            String::from_utf8_lossy(ok.authenticator.crealm.as_bytes())
        );
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
        let mut want_mutual = ok.mutual_required;
        let mut delegated = None;
        let mut gss_flags = GSS_C_INTEG | GSS_C_CONF | GSS_C_REPLAY | GSS_C_SEQUENCE;
        if let Some(ck) = &ok.authenticator.cksum
            && ck.cksumtype == GSS_CHECKSUM_TYPE
        {
            check_channel_bindings(ck.checksum.as_ref(), channel_bindings)?;
            if ck.checksum.as_ref().len() >= 24 {
                let mut f = [0u8; 4];
                f.copy_from_slice(&ck.checksum.as_ref()[20..24]);
                let flags = u32::from_le_bytes(f);
                gss_flags = flags;
                want_mutual |= flags & GSS_C_MUTUAL != 0;
                delegated = extract_delegated(
                    ck.checksum.as_ref(),
                    flags,
                    subkey.as_ref(),
                    &ticket_session,
                )?;
            }
        }
        if want_mutual {
            gss_flags |= GSS_C_MUTUAL;
        }
        let sess = subkey.unwrap_or(ticket_session);
        let base = ok.authenticator.seq_number.unwrap_or(0);
        let out = Self {
            session: sess,
            acceptor_subkey: None,
            send_seq: 0,
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
        };
        let mut ap_rep_tok = None;
        if want_mutual {
            let ap_rep = build_ap_rep(&out.session, &ok.authenticator, None, Some(0))?;
            let der = encode(&ap_rep)?;
            ap_rep_tok = Some(gss_wrap_app(TOK_AP_REP, &der));
        }
        Ok((out, ap_rep_tok))
    }

    /// Consume the MIT CFX AP-REP token (acceptor subkey).
    ///
    /// MIT `krb5_mk_rep` encrypts EncAPRepPart with the **ticket session**
    /// (`auth_context->key`), not the authenticator subkey.
    ///
    /// # Errors
    ///
    /// Truncated token, decrypt, or DER failures.
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
        let plain = decrypt(ticket_session, usage, ap.enc_part.cipher.as_ref())?;
        let part: EncApRepPart = decode(&plain)?;
        if let Some(sk) = part.subkey {
            let et = EncryptionType::from_iana(sk.keytype)
                .or_else(|_| EncryptionType::known(sk.keytype))?;
            self.acceptor_subkey = Some(ProtocolKey::from_bytes(et, sk.keyvalue.as_ref())?);
        }
        Ok(())
    }

    fn recv_key(&self, flags: u8) -> Result<&ProtocolKey, Error> {
        if flags & FLAG_ACCEPTOR_SUBKEY != 0 {
            self.acceptor_subkey
                .as_ref()
                .ok_or_else(|| Error::Inner("gss acceptor subkey".into()))
        } else {
            Ok(&self.session)
        }
    }

    fn send_key(&self) -> (&ProtocolKey, u8) {
        if let Some(k) = &self.acceptor_subkey {
            (k, FLAG_ACCEPTOR_SUBKEY)
        } else {
            (&self.session, 0)
        }
    }

    /// Per-message wrap (confidentiality). RFC 4121 §4.2.6 token.
    ///
    /// # Errors
    ///
    /// Crypto failures.
    pub fn wrap(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        // MIT 1.22.2 libgssapi_krb5 wrap tokens use RRC=0 (observed in
        // gss-gate). wrap_with_rrc(16) remains for SSPI in-place decrypt.
        self.wrap_with_rrc_inner(plaintext, 0)
    }

    /// Unwrap a wrap token. Sequence numbers are checked.
    ///
    /// # Errors
    ///
    /// Integrity, truncated tokens, or sequence mismatch.
    pub fn unwrap(&mut self, token: &[u8]) -> Result<Vec<u8>, Error> {
        let owned = message_token(token)?;
        let inner = owned.as_slice();
        if inner.len() < 16 || inner[..2] != TOK_WRAP {
            return Err(Error::Truncated);
        }
        let mut header = [0u8; 16];
        header.copy_from_slice(&inner[..16]);
        let seq = u64::from_be_bytes(header[8..16].try_into().map_err(|_| Error::Truncated)?);
        self.accept_seq(seq)?;
        let rrc = u16::from_be_bytes(header[6..8].try_into().map_err(|_| Error::Truncated)?);
        let payload = rotate_rrc(&inner[16..], rrc);
        let usage = seal_usage(!self.initiator);
        let key = self.recv_key(header[2])?;
        if header[2] & FLAG_SEALED == 0 {
            // RFC 4121 wrap without confidentiality: header | data | checksum.
            let ec = usize::from(u16::from_be_bytes(
                header[4..6].try_into().map_err(|_| Error::Truncated)?,
            ));
            if payload.len() < ec {
                return Err(Error::Truncated);
            }
            let split = payload.len() - ec;
            let data = &payload[..split];
            let mac = &payload[split..];
            let mut h = header;
            h[4] = 0;
            h[5] = 0;
            h[6] = 0;
            h[7] = 0;
            let mut to_ck = data.to_vec();
            to_ck.extend_from_slice(&h);
            verify_checksum(key, usage, &to_ck, mac).map_err(|_| Error::Integrity)?;
            return Ok(data.to_vec());
        }
        let plain = decrypt(key, usage, &payload)?;
        if plain.len() < 16 {
            return Err(Error::Truncated);
        }
        let (msg, trail) = plain.split_at(plain.len() - 16);
        let mut expected = header;
        expected[6] = 0;
        expected[7] = 0;
        if trail != expected {
            return Err(Error::Integrity);
        }
        Ok(msg.to_vec())
    }

    /// MIC (integrity only). RFC 4121 §4.2.6.1 token.
    ///
    /// # Errors
    ///
    /// Crypto failures.
    pub fn get_mic(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let usage = sign_usage(self.initiator);
        let header = mic_header(self.initiator, self.send_seq);
        let mut buf = data.to_vec();
        buf.extend_from_slice(&header);
        let mic = checksum(&self.session, usage, &buf)?;
        self.send_seq = self.send_seq.wrapping_add(1);
        let mut tok = header.to_vec();
        tok.extend_from_slice(&mic);
        Ok(tok)
    }

    /// Verify a MIC. Sequence numbers are checked.
    ///
    /// # Errors
    ///
    /// Integrity failure or sequence mismatch.
    pub fn verify_mic(&mut self, data: &[u8], token: &[u8]) -> Result<(), Error> {
        let owned = message_token(token)?;
        let inner = owned.as_slice();
        if inner.len() < 16 || inner[..2] != TOK_MIC {
            return Err(Error::Truncated);
        }
        let seq = u64::from_be_bytes(inner[8..16].try_into().map_err(|_| Error::Truncated)?);
        self.accept_seq(seq)?;
        let usage = sign_usage(!self.initiator);
        let key = self.recv_key(inner[2])?;
        let mut buf = data.to_vec();
        buf.extend_from_slice(&inner[..16]);
        verify_checksum(key, usage, &buf, &inner[16..]).map_err(|_| Error::Integrity)?;
        Ok(())
    }

    /// Session key established by the context (for tests and the acceptor binary).
    #[must_use]
    pub fn session_key(&self) -> &ProtocolKey {
        &self.session
    }

    /// Delegated initiator name if `GSS_C_DELEG_FLAG` carried a KRB-CRED.
    #[must_use]
    pub fn delegated(&self) -> Option<&str> {
        self.delegated.as_deref()
    }

    /// Wrap with an explicit RRC (tests pin rotate direction).
    ///
    /// # Errors
    ///
    /// Crypto failures.
    pub fn wrap_with_rrc(&mut self, plaintext: &[u8], rrc: u16) -> Result<Vec<u8>, Error> {
        self.wrap_with_rrc_inner(plaintext, rrc)
    }

    /// Wrap without confidentiality (`gss_seal` conf=0). AUTH_GSSAPI
    /// `signed_isn` / sequence verifiers use this (MIT `auth_gssapi_seal_seq`).
    ///
    /// # Errors
    ///
    /// Crypto failures.
    pub fn wrap_integ(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let usage = seal_usage(self.initiator);
        let mut header = wrap_header(self.initiator, false, self.send_seq);
        let mut to_ck = plaintext.to_vec();
        to_ck.extend_from_slice(&header);
        let mac = checksum(&self.session, usage, &to_ck)?;
        let ec = u16::try_from(mac.len()).map_err(|_| Error::Truncated)?;
        header[4..6].copy_from_slice(&ec.to_be_bytes());
        self.send_seq = self.send_seq.wrapping_add(1);
        let mut tok = header.to_vec();
        tok.extend_from_slice(plaintext);
        tok.extend_from_slice(&mac);
        Ok(tok)
    }

    fn wrap_with_rrc_inner(&mut self, plaintext: &[u8], rrc: u16) -> Result<Vec<u8>, Error> {
        let usage = seal_usage(self.initiator);
        let (key, extra) = self.send_key();
        let mut header = wrap_header(self.initiator, true, self.send_seq);
        header[2] |= extra;
        let mut to_enc = plaintext.to_vec();
        to_enc.extend_from_slice(&header);
        let cipher = encrypt(key, usage, &to_enc)?;
        self.send_seq = self.send_seq.wrapping_add(1);
        let mut tok = header.to_vec();
        tok.extend_from_slice(&cipher);
        apply_send_rrc(&mut tok, rrc)?;
        Ok(tok)
    }

    /// CFX wrap_iov (AES / RFC 8009). `conf` encrypts DATA; `SIGN_ONLY` is MAC-only.
    ///
    /// Layout: HEADER (32) | DATA | PADDING (empty) | TRAILER (E(header)+HMAC), RRC=0.
    ///
    /// # Errors
    ///
    /// Non-AES etype, missing HEADER/DATA/TRAILER, or crypto failures.
    pub fn wrap_iov(&mut self, conf: bool, iov: &mut [IovBuf<'_>]) -> Result<(), Error> {
        if conf {
            self.wrap_iov_sealed(iov)
        } else {
            self.wrap_iov_integ(iov)
        }
    }

    /// Inverse of [`Self::wrap_iov`]. DATA is replaced with plaintext.
    ///
    /// # Errors
    ///
    /// Truncated buffers, integrity, sequence, or non-AES etype.
    pub fn unwrap_iov(&mut self, iov: &mut [IovBuf<'_>]) -> Result<(), Error> {
        let sealed = iov
            .iter()
            .find(|b| b.kind == IovType::Header)
            .and_then(|b| b.data.get(2).copied())
            .ok_or(Error::Truncated)?
            & FLAG_SEALED
            != 0;
        if sealed {
            self.unwrap_iov_sealed(iov)
        } else {
            self.unwrap_iov_integ(iov)
        }
    }

    /// HEADER / PADDING / TRAILER sizes for AES wrap_iov (`conf` = confidentiality).
    ///
    /// # Errors
    ///
    /// Non-AES etype.
    pub fn wrap_iov_length(&self, conf: bool) -> Result<(usize, usize, usize), Error> {
        let (key, _) = self.send_key();
        require_aes(key.etype())?;
        let h = key.etype().hmac_output_len();
        if conf {
            Ok((16 + AES_CONFOUNDER, 0, 16 + h))
        } else {
            Ok((16, 0, h))
        }
    }

    fn wrap_iov_sealed(&mut self, iov: &mut [IovBuf<'_>]) -> Result<(), Error> {
        let (key, extra) = self.send_key();
        let key = key.clone();
        require_aes(key.etype())?;
        let hmac_len = key.etype().hmac_output_len();
        let usage = seal_usage(self.initiator);
        let mut tok_hdr = wrap_header(self.initiator, true, self.send_seq);
        tok_hdr[2] |= extra;
        let has_ad = iov
            .iter()
            .any(|b| b.kind == IovType::SignOnly && !b.data.is_empty());
        if !has_ad {
            let n = iov_data_len(iov)?;
            let mut plain = Vec::with_capacity(n);
            iov_copy_data(iov, &mut plain)?;
            let tok = self.wrap(&plain)?;
            let trailer_len = 16 + hmac_len;
            if tok.len() != 16 + AES_CONFOUNDER + n + trailer_len {
                return Err(Error::Truncated);
            }
            return split_wrap_token(iov, &tok, n, trailer_len);
        }
        let n = iov_data_len(iov)?;
        let mut plain = Vec::with_capacity(n);
        iov_copy_data(iov, &mut plain)?;
        let mut conf = [0u8; AES_CONFOUNDER];
        getrandom::getrandom(&mut conf).map_err(|e| Error::Inner(e.to_string()))?;
        let mut to_enc = plain.clone();
        to_enc.extend_from_slice(&tok_hdr);
        let mut cipher = encrypt_with_confounder(&key, usage, &conf, &to_enc)?;
        let c_len = cipher.len().checked_sub(hmac_len).ok_or(Error::Truncated)?;
        let hmac_in = iov_hmac_input(
            iov,
            key.etype().is_rfc8009(),
            &conf,
            &cipher[..c_len],
            &tok_hdr,
            None,
        )?;
        let mac = integrity_mac(&key, usage, &hmac_in)?;
        if mac.len() != hmac_len {
            return Err(Error::Truncated);
        }
        cipher.truncate(c_len);
        cipher.extend_from_slice(&mac);
        self.send_seq = self.send_seq.wrapping_add(1);
        let trailer_len = 16 + hmac_len;
        let mut tok = tok_hdr.to_vec();
        tok.extend_from_slice(&cipher);
        split_wrap_token(iov, &tok, n, trailer_len)
    }

    fn wrap_iov_integ(&mut self, iov: &mut [IovBuf<'_>]) -> Result<(), Error> {
        let (key, extra) = self.send_key();
        let key = key.clone();
        require_aes(key.etype())?;
        let usage = seal_usage(self.initiator);
        let mut header = wrap_header(self.initiator, false, self.send_seq);
        header[2] |= extra;
        let mut to_ck = Vec::new();
        iov_sign_body(iov, &mut to_ck);
        to_ck.extend_from_slice(&header);
        let mac = checksum(&key, usage, &to_ck)?;
        let ec = u16::try_from(mac.len()).map_err(|_| Error::Truncated)?;
        header[4..6].copy_from_slice(&ec.to_be_bytes());
        self.send_seq = self.send_seq.wrapping_add(1);
        write_iov_one(iov, IovType::Header, &header)?;
        write_iov_one(iov, IovType::Trailer, &mac)?;
        if let Some(p) = iov.iter_mut().find(|b| b.kind == IovType::Padding) {
            p.data.clear();
        }
        Ok(())
    }

    fn unwrap_iov_sealed(&mut self, iov: &mut [IovBuf<'_>]) -> Result<(), Error> {
        let has_ad = iov
            .iter()
            .any(|b| b.kind == IovType::SignOnly && !b.data.is_empty());
        if !has_ad {
            let tok = join_wrap_token(iov)?;
            let plain = self.unwrap(&tok)?;
            write_iov_data(iov, &plain)?;
            return Ok(());
        }
        let header = iov_find(iov, IovType::Header)?.to_vec();
        if header.len() != 16 + AES_CONFOUNDER {
            return Err(Error::Truncated);
        }
        let mut tok_hdr = [0u8; 16];
        tok_hdr.copy_from_slice(&header[..16]);
        if tok_hdr[..2] != TOK_WRAP || tok_hdr[2] & FLAG_SEALED == 0 {
            return Err(Error::Truncated);
        }
        let rrc = u16::from_be_bytes(tok_hdr[6..8].try_into().map_err(|_| Error::Truncated)?);
        if rrc != 0 {
            return Err(Error::Truncated);
        }
        let key = self.recv_key(tok_hdr[2])?.clone();
        require_aes(key.etype())?;
        let hmac_len = key.etype().hmac_output_len();
        let trailer = iov_find(iov, IovType::Trailer)?.to_vec();
        if trailer.len() != 16 + hmac_len {
            return Err(Error::Truncated);
        }
        let n = iov_data_len(iov)?;
        let mut c = Vec::with_capacity(AES_CONFOUNDER + n + 16);
        c.extend_from_slice(&header[16..]);
        iov_copy_data(iov, &mut c)?;
        c.extend_from_slice(&trailer[..16]);
        let mac = &trailer[16..];
        let usage = seal_usage(!self.initiator);
        let rfc8009 = key.etype().is_rfc8009();
        let (conf, plain) = decrypt_cts(&key, usage, &c)?;
        if rfc8009 {
            let hmac_in = iov_hmac_input(iov, true, &[], &c, &tok_hdr, None)?;
            let expect = integrity_mac(&key, usage, &hmac_in)?;
            if !mac_eq(mac, &expect) {
                return Err(Error::Integrity);
            }
        }
        if plain.len() < 16 {
            return Err(Error::Truncated);
        }
        let (msg, trail) = plain.split_at(plain.len() - 16);
        if !rfc8009 {
            let hmac_in = iov_hmac_input(iov, false, &conf, &[], &tok_hdr, Some(msg))?;
            let expect = integrity_mac(&key, usage, &hmac_in)?;
            if !mac_eq(mac, &expect) {
                return Err(Error::Integrity);
            }
        }
        let mut expected = tok_hdr;
        expected[6] = 0;
        expected[7] = 0;
        if trail != expected {
            return Err(Error::Integrity);
        }
        let seq = u64::from_be_bytes(tok_hdr[8..16].try_into().map_err(|_| Error::Truncated)?);
        self.accept_seq(seq)?;
        write_iov_data(iov, msg)
    }

    fn unwrap_iov_integ(&mut self, iov: &mut [IovBuf<'_>]) -> Result<(), Error> {
        let tok = join_wrap_token(iov)?;
        let plain = self.unwrap(&tok)?;
        write_iov_data(iov, &plain)
    }

    /// Serialize context state (private Rust↔Rust format, not MIT `kg_ctx_externalize`).
    ///
    /// # Errors
    ///
    /// Key length overflows `u16`.
    pub fn export_sec_context(&self) -> Result<Vec<u8>, Error> {
        let mut o = Vec::new();
        o.extend_from_slice(EXPORT_MAGIC);
        o.push(EXPORT_VERSION);
        o.push(u8::from(self.initiator));
        o.push(u8::from(self.rpcsec_init_window));
        o.extend_from_slice(&self.gss_flags.to_le_bytes());
        o.extend_from_slice(&self.lifetime_end.to_le_bytes());
        o.extend_from_slice(&self.send_seq.to_be_bytes());
        o.extend_from_slice(&self.recv_seq.to_be_bytes());
        o.push(u8::from(self.recv_seen));
        let mut win: Vec<u64> = self.recv_window.iter().copied().collect();
        win.sort_unstable();
        let nwin = u16::try_from(win.len()).map_err(|_| Error::Truncated)?;
        o.extend_from_slice(&nwin.to_be_bytes());
        for s in win {
            o.extend_from_slice(&s.to_be_bytes());
        }
        write_key(&mut o, &self.session)?;
        match &self.acceptor_subkey {
            Some(k) => {
                o.push(1);
                write_key(&mut o, k)?;
            }
            None => o.push(0),
        }
        write_opt_str(&mut o, self.client.as_deref())?;
        write_opt_str(&mut o, self.delegated.as_deref())?;
        let sp = self.spnego_mech_list.as_deref().unwrap_or(&[]);
        let n = u16::try_from(sp.len()).map_err(|_| Error::Truncated)?;
        o.extend_from_slice(&n.to_be_bytes());
        o.extend_from_slice(sp);
        Ok(o)
    }

    /// Inverse of [`Self::export_sec_context`].
    ///
    /// # Errors
    ///
    /// Truncated or unknown version.
    pub fn import_sec_context(token: &[u8]) -> Result<Self, Error> {
        let mut i = 0usize;
        if token.get(i..i + 4) != Some(EXPORT_MAGIC.as_slice()) {
            return Err(Error::Truncated);
        }
        i += 4;
        let ver = *token.get(i).ok_or(Error::Truncated)?;
        i += 1;
        if ver != EXPORT_VERSION {
            return Err(Error::Truncated);
        }
        let initiator = *token.get(i).ok_or(Error::Truncated)? != 0;
        i += 1;
        let rpcsec_init_window = *token.get(i).ok_or(Error::Truncated)? != 0;
        i += 1;
        let gss_flags = u32::from_le_bytes(take_arr(token, &mut i)?);
        let lifetime_end = u32::from_le_bytes(take_arr(token, &mut i)?);
        let send_seq = u64::from_be_bytes(take_arr(token, &mut i)?);
        let recv_seq = u64::from_be_bytes(take_arr(token, &mut i)?);
        let recv_seen = *token.get(i).ok_or(Error::Truncated)? != 0;
        i += 1;
        let nwin = usize::from(u16::from_be_bytes(take_arr(token, &mut i)?));
        if nwin > 64 {
            return Err(Error::Truncated);
        }
        let mut recv_window = std::collections::HashSet::new();
        for _ in 0..nwin {
            recv_window.insert(u64::from_be_bytes(take_arr(token, &mut i)?));
        }
        let session = read_key(token, &mut i)?;
        let has_sub = *token.get(i).ok_or(Error::Truncated)?;
        i += 1;
        let acceptor_subkey = if has_sub != 0 {
            Some(read_key(token, &mut i)?)
        } else {
            None
        };
        let client = read_opt_str(token, &mut i)?;
        let delegated = read_opt_str(token, &mut i)?;
        let nsp = usize::from(u16::from_be_bytes(take_arr(token, &mut i)?));
        let sp = token.get(i..i + nsp).ok_or(Error::Truncated)?;
        i += nsp;
        if i != token.len() {
            return Err(Error::Truncated);
        }
        Ok(Self {
            session,
            acceptor_subkey,
            send_seq,
            recv_seq,
            recv_seen,
            recv_window,
            initiator,
            rpcsec_init_window,
            replay: ReplayCache::new(),
            client,
            delegated,
            spnego_mech_list: if sp.is_empty() {
                None
            } else {
                Some(sp.to_vec())
            },
            lifetime_end,
            gss_flags,
        })
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

    fn accept_seq(&mut self, seq: u64) -> Result<(), Error> {
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

fn require_aes(et: EncryptionType) -> Result<(), Error> {
    if et.is_aes() {
        Ok(())
    } else {
        Err(Error::Inner("gss wrap_iov aes".into()))
    }
}

fn mac_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn iov_find<'a>(iov: &'a [IovBuf<'_>], kind: IovType) -> Result<&'a [u8], Error> {
    let mut found = None;
    for b in iov {
        if b.kind == kind {
            if found.is_some() {
                return Err(Error::Truncated);
            }
            found = Some(b.data.as_slice());
        }
    }
    found.ok_or(Error::Truncated)
}

fn iov_data_len(iov: &[IovBuf<'_>]) -> Result<usize, Error> {
    let n: usize = iov
        .iter()
        .filter(|b| b.kind == IovType::Data)
        .map(|b| b.data.len())
        .sum();
    if n == 0 && !iov.iter().any(|b| b.kind == IovType::Data) {
        return Err(Error::Truncated);
    }
    Ok(n)
}

fn iov_copy_data(iov: &[IovBuf<'_>], out: &mut Vec<u8>) -> Result<(), Error> {
    let mut any = false;
    for b in iov {
        if b.kind == IovType::Data {
            any = true;
            out.extend_from_slice(b.data);
        }
    }
    if any { Ok(()) } else { Err(Error::Truncated) }
}

fn iov_sign_body(iov: &[IovBuf<'_>], out: &mut Vec<u8>) {
    for b in iov {
        if matches!(b.kind, IovType::Data | IovType::SignOnly) {
            out.extend_from_slice(b.data);
        }
    }
}

fn write_iov_one(iov: &mut [IovBuf<'_>], kind: IovType, bytes: &[u8]) -> Result<(), Error> {
    let mut slot = None;
    for (i, b) in iov.iter().enumerate() {
        if b.kind == kind {
            if slot.is_some() {
                return Err(Error::Truncated);
            }
            slot = Some(i);
        }
    }
    let i = slot.ok_or(Error::Truncated)?;
    iov[i].data.clear();
    iov[i].data.extend_from_slice(bytes);
    Ok(())
}

fn write_iov_data(iov: &mut [IovBuf<'_>], plain: &[u8]) -> Result<(), Error> {
    let mut off = 0usize;
    for b in iov.iter_mut() {
        if b.kind == IovType::Data {
            let n = b.data.len();
            let chunk = plain.get(off..off + n).ok_or(Error::Truncated)?;
            b.data.copy_from_slice(chunk);
            off += n;
        }
    }
    if off == plain.len() {
        Ok(())
    } else {
        Err(Error::Truncated)
    }
}

fn join_wrap_token(iov: &[IovBuf<'_>]) -> Result<Vec<u8>, Error> {
    let mut tok = iov_find(iov, IovType::Header)?.to_vec();
    iov_copy_data(iov, &mut tok)?;
    if let Ok(p) = iov_find(iov, IovType::Padding) {
        tok.extend_from_slice(p);
    }
    tok.extend_from_slice(iov_find(iov, IovType::Trailer)?);
    Ok(tok)
}

fn split_wrap_token(
    iov: &mut [IovBuf<'_>],
    tok: &[u8],
    n: usize,
    trailer_len: usize,
) -> Result<(), Error> {
    let header_len = 16 + AES_CONFOUNDER;
    if tok.len() != header_len + n + trailer_len {
        return Err(Error::Truncated);
    }
    write_iov_one(iov, IovType::Header, &tok[..header_len])?;
    write_iov_data(iov, &tok[header_len..header_len + n])?;
    if let Some(p) = iov.iter_mut().find(|b| b.kind == IovType::Padding) {
        p.data.clear();
    }
    write_iov_one(iov, IovType::Trailer, &tok[header_len + n..])
}

fn iov_hmac_input(
    iov: &[IovBuf<'_>],
    rfc8009: bool,
    conf: &[u8],
    cipher: &[u8],
    tok_hdr: &[u8; 16],
    data_plain: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    if rfc8009 {
        let mut m = vec![0u8; 16];
        m.extend_from_slice(cipher.get(..AES_CONFOUNDER).ok_or(Error::Truncated)?);
        let mut off = AES_CONFOUNDER;
        for b in iov {
            match b.kind {
                IovType::Data => {
                    let n = b.data.len();
                    m.extend_from_slice(cipher.get(off..off + n).ok_or(Error::Truncated)?);
                    off += n;
                }
                IovType::SignOnly => m.extend_from_slice(b.data),
                _ => {}
            }
        }
        m.extend_from_slice(cipher.get(off..off + 16).ok_or(Error::Truncated)?);
        return Ok(m);
    }
    let mut m = conf.to_vec();
    let mut poff = 0usize;
    for b in iov {
        match b.kind {
            IovType::Data => {
                if let Some(p) = data_plain {
                    let n = b.data.len();
                    m.extend_from_slice(p.get(poff..poff + n).ok_or(Error::Truncated)?);
                    poff += n;
                } else {
                    m.extend_from_slice(b.data);
                }
            }
            IovType::SignOnly => m.extend_from_slice(b.data),
            _ => {}
        }
    }
    m.extend_from_slice(tok_hdr);
    Ok(m)
}

fn write_key(out: &mut Vec<u8>, key: &ProtocolKey) -> Result<(), Error> {
    out.extend_from_slice(&key.etype().to_iana().to_be_bytes());
    let n = u16::try_from(key.as_bytes().len()).map_err(|_| Error::Truncated)?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(key.as_bytes());
    Ok(())
}

fn read_key(token: &[u8], i: &mut usize) -> Result<ProtocolKey, Error> {
    let etype_n = i32::from_be_bytes(take_arr(token, i)?);
    let n = usize::from(u16::from_be_bytes(take_arr(token, i)?));
    let bytes = token.get(*i..*i + n).ok_or(Error::Truncated)?;
    *i += n;
    let et = EncryptionType::from_iana(etype_n).or_else(|_| EncryptionType::known(etype_n))?;
    Ok(ProtocolKey::from_bytes(et, bytes)?)
}

fn take_arr<const N: usize>(token: &[u8], i: &mut usize) -> Result<[u8; N], Error> {
    let s = token.get(*i..*i + N).ok_or(Error::Truncated)?;
    *i += N;
    s.try_into().map_err(|_| Error::Truncated)
}

fn write_opt_str(out: &mut Vec<u8>, s: Option<&str>) -> Result<(), Error> {
    let b = s.unwrap_or("").as_bytes();
    let n = u16::try_from(b.len()).map_err(|_| Error::Truncated)?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

fn read_opt_str(token: &[u8], i: &mut usize) -> Result<Option<String>, Error> {
    let n = usize::from(u16::from_be_bytes(take_arr(token, i)?));
    let b = token.get(*i..*i + n).ok_or(Error::Truncated)?;
    *i += n;
    if b.is_empty() {
        return Ok(None);
    }
    Ok(Some(
        String::from_utf8(b.to_vec()).map_err(|_| Error::Truncated)?,
    ))
}

fn random_subkey(session: &ProtocolKey) -> Result<ProtocolKey, Error> {
    let n = session.etype().key_len();
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).map_err(|e| Error::Inner(e.to_string()))?;
    ProtocolKey::from_bytes(session.etype(), &b).map_err(Error::from)
}

fn authenticator_checksum(
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

fn krb_cred_for_deleg(ticket_session: &ProtocolKey, deleg: &DelegCred) -> Result<Vec<u8>, Error> {
    let realm = String::from_utf8_lossy(deleg.crealm.as_bytes());
    let info = KrbCredInfo {
        key: EncryptionKey {
            keytype: deleg.session.etype().to_iana(),
            keyvalue: deleg.session.as_bytes().to_vec().into(),
        },
        prealm: Some(deleg.crealm.clone()),
        pname: Some(deleg.cname.clone()),
        flags: None,
        authtime: None,
        starttime: None,
        endtime: None,
        renew_till: None,
        srealm: Some(deleg.crealm.clone()),
        sname: Some(PrincipalName::krbtgt(realm.as_ref())),
        caddr: None,
    };
    let now = KerberosTime::now();
    let part = EncKrbCredPart {
        ticket_info: vec![info],
        nonce: None,
        timestamp: Some(now.clone()),
        usec: Some(Microseconds::from_subsec_micros(
            now.0.timestamp_subsec_micros(),
        )),
        s_address: None,
        r_address: None,
    };
    let der = encode(&part)?;
    let usage = KeyUsage::new(ku::KRB_CRED_ENC_PART)?;
    let cipher = encrypt(ticket_session, usage, &der)?;
    let cred = KrbCred {
        pvno: KrbCred::PVNO,
        msg_type: KrbCred::MSG_TYPE,
        tickets: vec![deleg.ticket.clone()],
        enc_part: EncryptedData {
            etype: ticket_session.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    };
    Ok(encode(&cred)?)
}

fn extract_delegated(
    cksum: &[u8],
    flags: u32,
    subkey: Option<&ProtocolKey>,
    ticket_session: &ProtocolKey,
) -> Result<Option<String>, Error> {
    if flags & GSS_C_DELEG == 0 {
        return Ok(None);
    }
    if cksum.len() < 28 {
        return Err(Error::Truncated);
    }
    let dlgth = usize::from(u16::from_le_bytes(
        cksum[26..28].try_into().map_err(|_| Error::Truncated)?,
    ));
    if dlgth > cksum.len() - 28 {
        return Err(Error::Truncated);
    }
    let raw = &cksum[28..28 + dlgth];
    let mut part = None;
    if let Some(sk) = subkey {
        part = unwrap_krb_cred(sk, raw, &ReplayCache::new()).ok();
    }
    if part.is_none() {
        part = unwrap_krb_cred(ticket_session, raw, &ReplayCache::new()).ok();
    }
    let part = if let Some(p) = part {
        p
    } else {
        let msg: KrbCred = decode(raw)?;
        let enc: EncKrbCredPart = decode(msg.enc_part.cipher.as_ref())?;
        (msg, enc)
    };
    let info = part.1.ticket_info.first().ok_or(Error::Truncated)?;
    let name = info
        .pname
        .as_ref()
        .map_or(String::new(), PrincipalName::components_joined);
    let realm = info.prealm.as_ref().map_or_else(String::new, |r| {
        String::from_utf8_lossy(r.as_bytes()).into_owned()
    });
    Ok(Some(format!("{name}@{realm}")))
}

fn check_channel_bindings(cksum: &[u8], local: Option<&ChannelBindings>) -> Result<(), Error> {
    // RFC 4121: GSS_C_NO_CHANNEL_BINDINGS on the acceptor ignores the token.
    let Some(local) = local else {
        return Ok(());
    };
    if cksum.len() < 24 {
        return Err(Error::ChannelBindings);
    }
    let lgth = u32::from_le_bytes(cksum[0..4].try_into().map_err(|_| Error::Truncated)?);
    if lgth != 16 {
        return Err(Error::ChannelBindings);
    }
    let mut got = [0u8; 16];
    got.copy_from_slice(&cksum[4..20]);
    let expect = ChannelBindings::bnd_hash(Some(local));
    if got != expect {
        return Err(Error::ChannelBindings);
    }
    Ok(())
}

fn seal_usage(initiator: bool) -> KeyUsage {
    KeyUsage::from_rfc(if initiator {
        ku::GSS_INITIATOR_SEAL
    } else {
        ku::GSS_ACCEPTOR_SEAL
    })
}

fn sign_usage(initiator: bool) -> KeyUsage {
    KeyUsage::from_rfc(if initiator {
        ku::GSS_INITIATOR_SIGN
    } else {
        ku::GSS_ACCEPTOR_SIGN
    })
}

fn rotate_rrc(cipher: &[u8], rrc: u16) -> Vec<u8> {
    let n = usize::from(rrc);
    if n == 0 || n >= cipher.len() {
        return cipher.to_vec();
    }
    let split = cipher.len() - n;
    let mut out = Vec::with_capacity(cipher.len());
    out.extend_from_slice(&cipher[split..]);
    out.extend_from_slice(&cipher[..split]);
    out
}

fn apply_send_rrc(tok: &mut [u8], rrc: u16) -> Result<(), Error> {
    if tok.len() < 16 {
        return Err(Error::Truncated);
    }
    tok[6..8].copy_from_slice(&rrc.to_be_bytes());
    let n = usize::from(rrc);
    if n == 0 || n >= tok.len() - 16 {
        return Ok(());
    }
    let cipher = tok[16..].to_vec();
    // Inverse of [`rotate_rrc`]: left-rotate by `rrc` so recv right-rotates back.
    let mut rotated = Vec::with_capacity(cipher.len());
    rotated.extend_from_slice(&cipher[n..]);
    rotated.extend_from_slice(&cipher[..n]);
    tok[16..].copy_from_slice(&rotated);
    Ok(())
}

fn wrap_header(initiator: bool, sealed: bool, seq: u64) -> [u8; 16] {
    let mut h = [0u8; 16];
    h[0] = TOK_WRAP[0];
    h[1] = TOK_WRAP[1];
    let mut flags = 0u8;
    if !initiator {
        flags |= FLAG_SENT_BY_ACCEPTOR;
    }
    if sealed {
        flags |= FLAG_SEALED;
    }
    h[2] = flags;
    h[3] = 0xff;
    h[4] = 0;
    h[5] = 0;
    h[6] = 0;
    h[7] = 0;
    h[8..16].copy_from_slice(&seq.to_be_bytes());
    h
}

fn mic_header(initiator: bool, seq: u64) -> [u8; 16] {
    let mut h = [0xff; 16];
    h[0] = TOK_MIC[0];
    h[1] = TOK_MIC[1];
    h[2] = if initiator { 0 } else { FLAG_SENT_BY_ACCEPTOR };
    h[8..16].copy_from_slice(&seq.to_be_bytes());
    h
}

/// RFC 4121 per-message tokens are bare (no RFC 2743 APPLICATION 0 wrapper).
fn message_token(token: &[u8]) -> Result<Vec<u8>, Error> {
    if token.first() == Some(&0x60) {
        gss_unwrap_app(token)
    } else {
        Ok(token.to_vec())
    }
}

fn gss_wrap_app(tok_id: [u8; 2], inner: &[u8]) -> Vec<u8> {
    let mut body = der_tlv(0x06, KRB5_OID);
    body.extend_from_slice(&tok_id);
    body.extend_from_slice(inner);
    der_tlv(0x60, &body)
}

fn gss_unwrap_app(token: &[u8]) -> Result<Vec<u8>, Error> {
    if token.len() < 2 || token[0] != 0x60 {
        return Err(Error::Truncated);
    }
    let (hlen, blen) = der_len_decode(&token[1..])?;
    let start = 1 + hlen;
    if start + blen > token.len() {
        return Err(Error::Truncated);
    }
    let body = &token[start..start + blen];
    if body.len() < 2 || body[0] != 0x06 {
        return Err(Error::Truncated);
    }
    let oid_len = usize::from(body[1]);
    let rest = body.get(2 + oid_len..).ok_or(Error::Truncated)?;
    Ok(rest.to_vec())
}

fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    der_len(&mut out, body.len());
    out.extend_from_slice(body);
    out
}

fn der_len(out: &mut Vec<u8>, n: usize) {
    if let Ok(b) = u8::try_from(n) {
        if b < 128 {
            out.push(b);
        } else {
            out.push(0x81);
            out.push(b);
        }
        return;
    }
    out.push(0x82);
    out.extend_from_slice(&(u16::try_from(n).unwrap_or(u16::MAX)).to_be_bytes());
}

fn der_len_decode(b: &[u8]) -> Result<(usize, usize), Error> {
    if b.is_empty() {
        return Err(Error::Truncated);
    }
    if b[0] < 128 {
        return Ok((1, usize::from(b[0])));
    }
    if b[0] == 0x81 && b.len() >= 2 {
        return Ok((2, usize::from(b[1])));
    }
    if b[0] == 0x82 && b.len() >= 3 {
        return Ok((3, usize::from(u16::from_be_bytes([b[1], b[2]]))));
    }
    Err(Error::Truncated)
}

/// SPNEGO `NegTokenInit` wrapping a Kerberos inner token (long-form DER length).
#[must_use]
pub fn spnego_init(krb_token: &[u8]) -> Vec<u8> {
    let oid_krb = der_tlv(0x06, KRB5_OID);
    let mech_seq = der_tlv(0x30, &oid_krb);
    let mech_types = der_tlv(0xa0, &mech_seq);
    let mech_token = der_tlv(0xa2, &der_tlv(0x04, krb_token));
    let mut seq = mech_types;
    seq.extend_from_slice(&mech_token);
    let neg = der_tlv(0xa0, &der_tlv(0x30, &seq));
    let mut app = der_tlv(0x06, SPNEGO_OID);
    app.extend_from_slice(&neg);
    der_tlv(0x60, &app)
}

/// Extract the inner Kerberos GSS token from a SPNEGO or raw krb5 blob.
///
/// # Errors
///
/// Truncated input.
pub fn spnego_inner(token: &[u8]) -> Result<&[u8], Error> {
    if token.len() < 2 || token[0] != 0x60 {
        return Err(Error::Truncated);
    }
    let (hlen, blen) = der_len_decode(&token[1..])?;
    let start = 1 + hlen;
    if start + blen > token.len() {
        return Err(Error::Truncated);
    }
    let body = &token[start..start + blen];
    if body.first() != Some(&0x06) || body.len() < 2 {
        return Err(Error::Truncated);
    }
    let oid_len = usize::from(body[1]);
    let rest = body.get(2 + oid_len..).ok_or(Error::Truncated)?;
    if rest.first() == Some(&0xa0) {
        return find_mech_token(rest);
    }
    // Raw RFC 4121/2743 Kerberos token: keep the APPLICATION 0 wrapper.
    Ok(token)
}

fn find_mech_token(neg: &[u8]) -> Result<&[u8], Error> {
    let (hlen, blen) = der_len_decode(neg.get(1..).ok_or(Error::Truncated)?)?;
    let seq_start = 1 + hlen;
    let seq = neg
        .get(seq_start..seq_start + blen)
        .ok_or(Error::Truncated)?;
    let inner = if seq.first() == Some(&0x30) {
        let (ih, il) = der_len_decode(seq.get(1..).ok_or(Error::Truncated)?)?;
        seq.get(1 + ih..1 + ih + il).ok_or(Error::Truncated)?
    } else {
        seq
    };
    let mut i = 0usize;
    while i + 2 < inner.len() {
        let tag = inner[i];
        let (lh, ln) = der_len_decode(&inner[i + 1..])?;
        let body_at = i + 1 + lh;
        let body = inner.get(body_at..body_at + ln).ok_or(Error::Truncated)?;
        if tag == 0xa2 {
            if body.first() == Some(&0x04) {
                let (oh, ol) = der_len_decode(body.get(1..).ok_or(Error::Truncated)?)?;
                return body.get(1 + oh..1 + oh + ol).ok_or(Error::Truncated);
            }
            return Ok(body);
        }
        i = body_at + ln;
    }
    Err(Error::Truncated)
}

const SPNEGO_ACCEPT_COMPLETED: u8 = 0;

fn der_oid(oid: &[u8]) -> Vec<u8> {
    der_tlv(0x06, oid)
}

fn der_octet(b: &[u8]) -> Vec<u8> {
    der_tlv(0x04, b)
}

fn der_enumerated(v: u8) -> Vec<u8> {
    vec![0x0a, 0x01, v]
}

fn parse_octet(body: &[u8]) -> Result<Vec<u8>, Error> {
    if body.first() != Some(&0x04) {
        return Ok(body.to_vec());
    }
    let (h, n) = der_len_decode(body.get(1..).ok_or(Error::Truncated)?)?;
    body.get(1 + h..1 + h + n)
        .ok_or(Error::Truncated)
        .map(<[u8]>::to_vec)
}

fn gss_oid_body(token: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    if token.len() < 2 || token[0] != 0x60 {
        return Err(Error::Truncated);
    }
    let (hlen, blen) = der_len_decode(&token[1..])?;
    let start = 1 + hlen;
    let body = token.get(start..start + blen).ok_or(Error::Truncated)?;
    if body.first() != Some(&0x06) || body.len() < 2 {
        return Err(Error::Truncated);
    }
    let oid_len = usize::from(body[1]);
    let oid = body.get(2..2 + oid_len).ok_or(Error::Truncated)?;
    let rest = body.get(2 + oid_len..).ok_or(Error::Truncated)?;
    Ok((oid, rest))
}

/// Whether `token` is a GSS-wrapped SPNEGO NegotiationToken.
#[must_use]
pub fn is_spnego(token: &[u8]) -> bool {
    matches!(gss_oid_body(token), Ok((oid, _)) if oid == SPNEGO_OID)
}

struct NegInit {
    mech_list_der: Vec<u8>,
    mech_token: Vec<u8>,
    mic: Option<Vec<u8>>,
}

fn parse_neg_init(token: &[u8]) -> Result<NegInit, Error> {
    let (oid, rest) = gss_oid_body(token)?;
    if oid != SPNEGO_OID {
        return Err(Error::Truncated);
    }
    if rest.first() != Some(&0xa0) {
        return Err(Error::Truncated);
    }
    let (h, n) = der_len_decode(rest.get(1..).ok_or(Error::Truncated)?)?;
    let inner = rest.get(1 + h..1 + h + n).ok_or(Error::Truncated)?;
    let seq = if inner.first() == Some(&0x30) {
        let (sh, sn) = der_len_decode(inner.get(1..).ok_or(Error::Truncated)?)?;
        inner.get(1 + sh..1 + sh + sn).ok_or(Error::Truncated)?
    } else {
        inner
    };
    let mut mech_list_der = None;
    let mut mech_token = None;
    let mut mic = None;
    let mut i = 0usize;
    while i < seq.len() {
        let tag = seq[i];
        let (lh, ln) = der_len_decode(seq.get(i + 1..).ok_or(Error::Truncated)?)?;
        let body = seq
            .get(i + 1 + lh..i + 1 + lh + ln)
            .ok_or(Error::Truncated)?;
        match tag {
            0xa0 => mech_list_der = Some(body.to_vec()),
            0xa2 => mech_token = Some(parse_octet(body)?),
            0xa3 => mic = Some(parse_octet(body)?),
            _ => {}
        }
        i = i.saturating_add(1).saturating_add(lh).saturating_add(ln);
    }
    Ok(NegInit {
        mech_list_der: mech_list_der.ok_or(Error::Truncated)?,
        mech_token: mech_token.ok_or(Error::Truncated)?,
        mic,
    })
}

fn encode_neg_resp(state: u8, mech: &[u8], response: Option<&[u8]>, mic: Option<&[u8]>) -> Vec<u8> {
    let mut seq = der_tlv(0xa0, &der_enumerated(state));
    seq.extend_from_slice(&der_tlv(0xa1, &der_oid(mech)));
    if let Some(r) = response {
        seq.extend_from_slice(&der_tlv(0xa2, &der_octet(r)));
    }
    if let Some(m) = mic {
        seq.extend_from_slice(&der_tlv(0xa3, &der_octet(m)));
    }
    der_tlv(0xa1, &der_tlv(0x30, &seq))
}

fn mech_token_as_gss(mech_token: &[u8]) -> Vec<u8> {
    if mech_token.first() == Some(&0x60) {
        mech_token.to_vec()
    } else {
        gss_wrap_app(TOK_AP_REQ, mech_token)
    }
}

/// SPNEGO acceptor: `NegTokenInit` → krb5 accept → `NegTokenResp` with MIC.
///
/// # Errors
///
/// Truncated SPNEGO, AP-REQ verify, or MIC verify.
pub fn spnego_accept(
    token: &[u8],
    service_keys: &[ProtocolKey],
    channel_bindings: Option<&ChannelBindings>,
    expected_server: Option<&PrincipalName>,
    expected_realm: Option<&str>,
) -> Result<(GssContext, Vec<u8>), Error> {
    let init = parse_neg_init(token)?;
    let mech = mech_token_as_gss(&init.mech_token);
    let (mut ctx, ap_rep) = GssContext::accept_sec_context(
        &mech,
        service_keys,
        channel_bindings,
        expected_server,
        expected_realm,
    )?;
    if let Some(mic) = &init.mic {
        ctx.verify_mic(&init.mech_list_der, mic)?;
    }
    let mic = ctx.get_mic(&init.mech_list_der)?;
    ctx.spnego_mech_list = Some(init.mech_list_der);
    let resp = encode_neg_resp(
        SPNEGO_ACCEPT_COMPLETED,
        KRB5_OID,
        ap_rep.as_deref(),
        Some(&mic),
    );
    Ok((ctx, resp))
}

fn parse_neg_resp_mic(token: &[u8]) -> Result<Vec<u8>, Error> {
    let rest = if token.first() == Some(&0xa1) {
        token
    } else {
        return Err(Error::Truncated);
    };
    let (h, n) = der_len_decode(rest.get(1..).ok_or(Error::Truncated)?)?;
    let inner = rest.get(1 + h..1 + h + n).ok_or(Error::Truncated)?;
    let seq = if inner.first() == Some(&0x30) {
        let (sh, sn) = der_len_decode(inner.get(1..).ok_or(Error::Truncated)?)?;
        inner.get(1 + sh..1 + sh + sn).ok_or(Error::Truncated)?
    } else {
        inner
    };
    let mut i = 0usize;
    while i < seq.len() {
        let tag = seq[i];
        let (lh, ln) = der_len_decode(seq.get(i + 1..).ok_or(Error::Truncated)?)?;
        let body = seq
            .get(i + 1 + lh..i + 1 + lh + ln)
            .ok_or(Error::Truncated)?;
        if tag == 0xa3 {
            return parse_octet(body);
        }
        i = i.saturating_add(1).saturating_add(lh).saturating_add(ln);
    }
    Err(Error::Truncated)
}

impl GssContext {
    /// Verify a follow-up SPNEGO `NegTokenResp` mechListMIC.
    ///
    /// # Errors
    ///
    /// Truncated token or MIC verify.
    pub fn verify_spnego_mic(&mut self, token: &[u8]) -> Result<(), Error> {
        let list = self.spnego_mech_list.clone().ok_or(Error::Truncated)?;
        let mic = parse_neg_resp_mic(token)?;
        self.verify_mic(&list, &mic)
    }
}

fn md5_16(data: &[u8]) -> [u8; 16] {
    use md5::{Digest, Md5};
    let out = Md5::digest(data);
    let mut a = [0u8; 16];
    a.copy_from_slice(&out);
    a
}

/// Build a MIT-shaped wrap token (16-byte RFC 4121 header + `encrypt(plain||header)`).
///
/// Used by tests to prove unwrap accepts the layout MIT `libgssapi_krb5` emits.
///
/// # Errors
///
/// Crypto failures.
pub fn mit_shaped_wrap(
    session: &ProtocolKey,
    initiator: bool,
    seq: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    mit_shaped_wrap_flags(session, initiator, seq, plaintext, 0)
}

fn mit_shaped_wrap_flags(
    session: &ProtocolKey,
    initiator: bool,
    seq: u64,
    plaintext: &[u8],
    extra_flags: u8,
) -> Result<Vec<u8>, Error> {
    let usage = seal_usage(initiator);
    let mut header = wrap_header(initiator, true, seq);
    header[2] |= extra_flags;
    let mut to_enc = plaintext.to_vec();
    to_enc.extend_from_slice(&header);
    let cipher = encrypt(session, usage, &to_enc)?;
    let mut tok = header.to_vec();
    tok.extend_from_slice(&cipher);
    Ok(tok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_crypto::{EncryptionType, string_to_key};
    use krb5_kdc::{
        S2K_ITERS, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, as_req, bootstrap_documented,
        documented_host, pa_enc_timestamp, tgs_req,
    };
    use krb5_types::ascii;

    fn contexts() -> (GssContext, GssContext) {
        let (store, _) = bootstrap_documented().unwrap();
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let key = string_to_key(
            EncryptionType::Aes256CtsHmacSha196,
            TEST_USER_PASSWORD,
            cname.default_salt(TEST_REALM),
            Some(&S2K_ITERS.to_be_bytes()),
        )
        .unwrap();
        let req = as_req(
            cname.clone(),
            TEST_REALM,
            1,
            Some(vec![pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        let as_out = krb5_kdc::issue_as(&store, &req).unwrap();
        let tgs = tgs_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            TEST_REALM,
            &cname,
            documented_host(),
            TEST_REALM,
            2,
        )
        .unwrap();
        let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
        let (init, token) = GssContext::init_sec_context(
            tgs_out.rep.0.ticket.clone(),
            &tgs_out.session_key,
            &ascii(TEST_REALM),
            &cname,
            false,
            None,
            None,
        )
        .unwrap();
        let host = store.get_name(&documented_host()).unwrap();
        let skey = &host.best_key().unwrap().key;
        let (acc, _) = GssContext::accept_sec_context(
            &token,
            std::slice::from_ref(skey),
            None,
            Some(&documented_host()),
            Some(TEST_REALM),
        )
        .unwrap();
        (init, acc)
    }

    #[test]
    fn wrap_unwrap_mic_round_trip() {
        let (mut init, mut acc) = contexts();
        let wrapped = init.wrap(b"hello gss").unwrap();
        assert_eq!(&wrapped[6..8], &[0, 0], "MIT wrap uses RRC=0");
        let plain = acc.unwrap(&wrapped).unwrap();
        assert_eq!(plain, b"hello gss");
        let mic = init.get_mic(b"hello gss").unwrap();
        acc.verify_mic(b"hello gss", &mic).unwrap();
        assert!(acc.unwrap(&wrapped).is_err());
    }

    #[test]
    fn wrap_integ_round_trip_is_unsealed() {
        let (mut init, mut acc) = contexts();
        let tok = init.wrap_integ(&1u32.to_be_bytes()).unwrap();
        assert_eq!(tok[2] & FLAG_SEALED, 0);
        let plain = acc.unwrap(&tok).unwrap();
        assert_eq!(plain, 1u32.to_be_bytes());
    }

    #[test]
    fn mit_shaped_wrap_token_is_accepted() {
        let (init, mut acc) = contexts();
        let tok = mit_shaped_wrap(init.session_key(), true, 0, b"mit-layout").unwrap();
        assert_eq!(&tok[..2], &TOK_WRAP);
        assert_eq!(tok[2] & FLAG_SEALED, FLAG_SEALED);
        let plain = acc.unwrap(&tok).unwrap();
        assert_eq!(plain, b"mit-layout");
    }

    #[test]
    fn channel_bindings_must_match() {
        let (store, _) = bootstrap_documented().unwrap();
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let key = string_to_key(
            EncryptionType::Aes256CtsHmacSha196,
            TEST_USER_PASSWORD,
            cname.default_salt(TEST_REALM),
            Some(&S2K_ITERS.to_be_bytes()),
        )
        .unwrap();
        let req = as_req(
            cname.clone(),
            TEST_REALM,
            7,
            Some(vec![pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        let as_out = krb5_kdc::issue_as(&store, &req).unwrap();
        let tgs = tgs_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            TEST_REALM,
            &cname,
            documented_host(),
            TEST_REALM,
            8,
        )
        .unwrap();
        let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
        let cb = ChannelBindings {
            application_data: b"tls-unique-test".to_vec(),
            ..ChannelBindings::default()
        };
        let (_init, token) = GssContext::init_sec_context(
            tgs_out.rep.0.ticket.clone(),
            &tgs_out.session_key,
            &ascii(TEST_REALM),
            &cname,
            false,
            Some(&cb),
            None,
        )
        .unwrap();
        let host = store.get_name(&documented_host()).unwrap();
        let skey = &host.best_key().unwrap().key;
        GssContext::accept_sec_context(
            &token,
            std::slice::from_ref(skey),
            Some(&cb),
            Some(&documented_host()),
            Some(TEST_REALM),
        )
        .unwrap();
        let other = ChannelBindings {
            application_data: b"other".to_vec(),
            ..ChannelBindings::default()
        };
        match GssContext::accept_sec_context(
            &token,
            std::slice::from_ref(skey),
            Some(&other),
            Some(&documented_host()),
            Some(TEST_REALM),
        ) {
            Err(Error::ChannelBindings) => {}
            Err(e) => panic!("expected channel bindings error, got {e}"),
            Ok(_) => panic!("expected channel bindings error"),
        }
        GssContext::accept_sec_context(
            &token,
            std::slice::from_ref(skey),
            None,
            Some(&documented_host()),
            Some(TEST_REALM),
        )
        .expect("acceptor GSS_C_NO_CHANNEL_BINDINGS ignores token CB");
    }

    #[test]
    fn spnego_long_form_length_round_trips() {
        let krb = vec![0x60; 200];
        let tok = spnego_init(&krb);
        assert_eq!(tok[0], 0x60);
        assert_ne!(
            tok[1], 0x80,
            "indefinite / overflow byte is not a DER length"
        );
        assert!(
            tok[1] >= 0x81,
            "200-byte inner token needs long-form length"
        );
        let inner = spnego_inner(&tok).unwrap();
        assert_eq!(inner, krb.as_slice());
        let raw = der_tlv(0x60, &[der_tlv(0x06, KRB5_OID), vec![0x01, 0x00]].concat());
        assert_eq!(spnego_inner(&raw).unwrap(), raw.as_slice());
    }

    #[test]
    fn spnego_accept_emits_neg_token_resp() {
        let (_as_out, tgs_out, skey, cname) = user_host();
        let (_init, krb) = GssContext::init_sec_context(
            tgs_out.rep.0.ticket.clone(),
            &tgs_out.session_key,
            &ascii(TEST_REALM),
            &cname,
            true,
            None,
            None,
        )
        .unwrap();
        let tok = spnego_init(&krb);
        assert!(is_spnego(&tok));
        let (acc, resp) = spnego_accept(
            &tok,
            std::slice::from_ref(&skey),
            None,
            Some(&documented_host()),
            Some(TEST_REALM),
        )
        .unwrap();
        assert_eq!(
            resp.first().copied(),
            Some(0xa1),
            "MIT wants bare NegTokenResp"
        );
        assert!(acc.client.is_some());
    }

    #[test]
    fn spnego_hostile_length_is_truncated_not_panic() {
        let mut tok = vec![0x60, 0x82, 0xff, 0xff, 0x06, 0x06];
        tok.extend_from_slice(SPNEGO_OID);
        tok.extend_from_slice(&[0xa0, 0x03, 0x30, 0x01, 0x00]);
        let r = std::panic::catch_unwind(|| parse_neg_init(&tok));
        assert!(r.is_ok(), "hostile SPNEGO length must not panic");
        assert!(matches!(r.unwrap(), Err(Error::Truncated)));
        assert!(matches!(
            spnego_accept(&tok, &[], None, None, None),
            Err(Error::Truncated)
        ));
    }

    #[test]
    fn hostile_gss_oid_length_is_truncated_not_panic() {
        // APPLICATION 0 wrapping OID with attacker-controlled length 255.
        let mut tok = vec![0x60, 13, 0x06, 255];
        tok.extend_from_slice(&[0u8; 11]);
        let r = std::panic::catch_unwind(|| gss_unwrap_app(&tok));
        assert!(r.is_ok(), "hostile OID length must not panic");
        assert!(matches!(r.unwrap(), Err(Error::Truncated)));
        assert!(gss_unwrap_app(&[0x60, 2, 0x06, 0xff]).is_err());
    }

    #[test]
    fn acceptor_rejects_wrong_service_name() {
        let (store, _) = bootstrap_documented().unwrap();
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let key = string_to_key(
            EncryptionType::Aes256CtsHmacSha196,
            TEST_USER_PASSWORD,
            cname.default_salt(TEST_REALM),
            Some(&S2K_ITERS.to_be_bytes()),
        )
        .unwrap();
        let req = as_req(
            cname.clone(),
            TEST_REALM,
            9,
            Some(vec![pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        let as_out = krb5_kdc::issue_as(&store, &req).unwrap();
        let tgs = tgs_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            TEST_REALM,
            &cname,
            documented_host(),
            TEST_REALM,
            10,
        )
        .unwrap();
        let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
        let (_init, token) = GssContext::init_sec_context(
            tgs_out.rep.0.ticket.clone(),
            &tgs_out.session_key,
            &ascii(TEST_REALM),
            &cname,
            false,
            None,
            None,
        )
        .unwrap();
        let host = store.get_name(&documented_host()).unwrap();
        let skey = &host.best_key().unwrap().key;
        let wrong = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "other.example"]);
        let Err(err) = GssContext::accept_sec_context(
            &token,
            std::slice::from_ref(skey),
            None,
            Some(&wrong),
            Some(TEST_REALM),
        ) else {
            panic!("wrong service accepted")
        };
        assert!(
            err.to_string().contains("NOT_US")
                || err.to_string().contains("sname")
                || err.to_string().contains("35")
                || err.to_string().contains("does not match"),
            "got {err}"
        );
        assert!(
            GssContext::accept_sec_context(
                &token,
                std::slice::from_ref(skey),
                None,
                Some(&documented_host()),
                Some(TEST_REALM),
            )
            .is_ok(),
            "matching service"
        );
    }

    #[test]
    fn first_seq_must_match_authenticator_base() {
        let (init, mut acc) = contexts();
        let bad = mit_shaped_wrap(init.session_key(), true, 5, b"skip").unwrap();
        assert!(matches!(acc.unwrap(&bad), Err(Error::Sequence)));
        let good = mit_shaped_wrap(init.session_key(), true, 0, b"ok").unwrap();
        assert_eq!(acc.unwrap(&good).unwrap(), b"ok");
    }

    #[test]
    fn rpcsec_init_window_accepts_seq_gap_default_rejects() {
        let (mut strict, acc) = contexts();
        let gap = mit_shaped_wrap(acc.session_key(), false, 1, b"init-win").unwrap();
        assert!(
            matches!(strict.unwrap(&gap), Err(Error::Sequence)),
            "default first-recv must match authenticator base"
        );
        let (mut iprop, acc) = contexts();
        iprop.allow_rpcsec_init_window();
        let gap = mit_shaped_wrap(acc.session_key(), false, 1, b"init-win").unwrap();
        assert_eq!(iprop.unwrap(&gap).unwrap(), b"init-win");
    }

    #[test]
    fn process_ap_rep_acceptor_subkey_unwrap() {
        use krb5_types::{EncApRepPart, EncryptedData, EncryptionKey, KerberosTime, Microseconds};

        let (mut init, _acc) = contexts();
        let et = init.session_key().etype();
        let mut ticket_raw = vec![0u8; et.key_len()];
        getrandom::getrandom(&mut ticket_raw).unwrap();
        let ticket = ProtocolKey::from_bytes(et, &ticket_raw).unwrap();
        let mut raw = vec![0u8; et.key_len()];
        getrandom::getrandom(&mut raw).unwrap();
        let sub = ProtocolKey::from_bytes(et, &raw).unwrap();
        let part = EncApRepPart {
            ctime: KerberosTime::now(),
            cusec: Microseconds::new(0).unwrap(),
            subkey: Some(EncryptionKey {
                keytype: et.to_iana(),
                keyvalue: sub.as_bytes().to_vec().into(),
            }),
            seq_number: Some(0),
        };
        let der = encode(&part).unwrap();
        let usage = KeyUsage::new(ku::AP_REP_ENC_PART).unwrap();
        let cipher = encrypt(&ticket, usage, &der).unwrap();
        let ap = ApRep {
            pvno: ApRep::PVNO,
            msg_type: ApRep::MSG_TYPE,
            enc_part: EncryptedData {
                etype: et.to_iana(),
                kvno: None,
                cipher: cipher.into(),
            },
        };
        let tok = gss_wrap_app(TOK_AP_REP, &encode(&ap).unwrap());
        init.process_ap_rep(&tok, &ticket).unwrap();
        let wrapped =
            mit_shaped_wrap_flags(&sub, false, 0, b"subkey", FLAG_ACCEPTOR_SUBKEY).unwrap();
        assert_eq!(init.unwrap(&wrapped).unwrap(), b"subkey");
    }

    #[test]
    fn wrap_mic_replay_inside_window_is_rejected() {
        let (mut init, mut acc) = contexts();
        let w = init.wrap(b"one").unwrap();
        acc.unwrap(&w).unwrap();
        // Gap inside the window is accepted (seq 0 then seq 2).
        let gap = mit_shaped_wrap(init.session_key(), true, 2, b"gap").unwrap();
        assert_eq!(acc.unwrap(&gap).unwrap(), b"gap");
        assert!(matches!(acc.unwrap(&w), Err(Error::Sequence)));
        let mic = init.get_mic(b"one").unwrap();
        acc.verify_mic(b"one", &mic).unwrap();
        assert!(matches!(acc.verify_mic(b"one", &mic), Err(Error::Sequence)));
    }

    #[test]
    fn rrc_nonzero_round_trip_pins_rotate_direction() {
        let (mut init, mut acc) = contexts();
        let tok = init.wrap_with_rrc(b"rrc-payload", 16).unwrap();
        assert_ne!(&tok[6..8], &[0, 0], "RRC field must be non-zero");
        let plain = acc.unwrap(&tok).unwrap();
        assert_eq!(plain, b"rrc-payload");
    }

    fn user_host() -> (
        krb5_kdc::IssuedAs,
        krb5_kdc::IssuedTgs,
        ProtocolKey,
        PrincipalName,
    ) {
        let (store, _) = bootstrap_documented().unwrap();
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let key = string_to_key(
            EncryptionType::Aes256CtsHmacSha196,
            TEST_USER_PASSWORD,
            cname.default_salt(TEST_REALM),
            Some(&S2K_ITERS.to_be_bytes()),
        )
        .unwrap();
        let req = as_req(
            cname.clone(),
            TEST_REALM,
            41,
            Some(vec![pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        let as_out = krb5_kdc::issue_as(&store, &req).unwrap();
        let tgs = tgs_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            TEST_REALM,
            &cname,
            documented_host(),
            TEST_REALM,
            42,
        )
        .unwrap();
        let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
        let host = store.get_name(&documented_host()).unwrap();
        let skey = host.best_key().unwrap().key.clone();
        (as_out, tgs_out, skey, cname)
    }

    #[test]
    fn deleg_checksum_carries_krb_cred() {
        let (as_out, tgs_out, _skey, cname) = user_host();
        let deleg = DelegCred {
            ticket: as_out.rep.0.ticket.clone(),
            session: as_out.session_key.clone(),
            crealm: ascii(TEST_REALM),
            cname: cname.clone(),
        };
        let (_init, token) = GssContext::init_sec_context(
            tgs_out.rep.0.ticket.clone(),
            &tgs_out.session_key,
            &ascii(TEST_REALM),
            &cname,
            false,
            None,
            Some(&deleg),
        )
        .unwrap();
        let inner = gss_unwrap_app(&token).unwrap();
        let ap: krb5_types::ApReq = decode(&inner[2..]).unwrap();
        let usage = KeyUsage::new(ku::AP_REQ_AUTHENTICATOR).unwrap();
        let plain = decrypt(
            &tgs_out.session_key,
            usage,
            ap.authenticator.cipher.as_ref(),
        )
        .unwrap();
        let auth: krb5_types::Authenticator = decode(&plain).unwrap();
        let ck = auth.cksum.expect("0x8003");
        assert_eq!(ck.cksumtype, GSS_CHECKSUM_TYPE);
        let b = ck.checksum.as_ref();
        assert!(b.len() > 28, "deleg trailer missing: len={}", b.len());
        let flags = u32::from_le_bytes(b[20..24].try_into().unwrap());
        assert_ne!(flags & GSS_C_DELEG, 0);
        assert_eq!(&b[24..26], &KRB5_GSS_FOR_CREDS.to_le_bytes());
    }

    #[test]
    fn accept_hostile_dlgth_is_truncated() {
        let (as_out, tgs_out, skey, cname) = user_host();
        let deleg = DelegCred {
            ticket: as_out.rep.0.ticket.clone(),
            session: as_out.session_key.clone(),
            crealm: ascii(TEST_REALM),
            cname: cname.clone(),
        };
        let der = krb_cred_for_deleg(&tgs_out.session_key, &deleg).unwrap();
        let mut ck = authenticator_checksum(None, GSS_C_DELEG | GSS_C_INTEG, Some(&der));
        ck[26..28].copy_from_slice(&0xFFFFu16.to_le_bytes());
        let cksum = Checksum {
            cksumtype: GSS_CHECKSUM_TYPE,
            checksum: ck.into(),
        };
        let sub = random_subkey(&tgs_out.session_key).unwrap();
        let enc_sub = EncryptionKey {
            keytype: sub.etype().to_iana(),
            keyvalue: sub.as_bytes().to_vec().into(),
        };
        let ap = build_ap_req_with_cksum(
            tgs_out.rep.0.ticket.clone(),
            &tgs_out.session_key,
            &ascii(TEST_REALM),
            &cname,
            ApOptions::none(),
            Some(cksum),
            Some(enc_sub),
        )
        .unwrap();
        let token = gss_wrap_app(TOK_AP_REQ, &encode(&ap).unwrap());
        let Err(err) = GssContext::accept_sec_context(
            &token,
            std::slice::from_ref(&skey),
            None,
            Some(&documented_host()),
            Some(TEST_REALM),
        ) else {
            panic!("hostile Dlgth must not accept")
        };
        assert!(
            matches!(err, Error::Truncated),
            "hostile Dlgth must be Truncated, got {err}"
        );
    }

    #[test]
    fn accept_extracts_delegated_client() {
        let (as_out, tgs_out, skey, cname) = user_host();
        let deleg = DelegCred {
            ticket: as_out.rep.0.ticket.clone(),
            session: as_out.session_key.clone(),
            crealm: ascii(TEST_REALM),
            cname: cname.clone(),
        };
        let (_init, token) = GssContext::init_sec_context(
            tgs_out.rep.0.ticket.clone(),
            &tgs_out.session_key,
            &ascii(TEST_REALM),
            &cname,
            false,
            None,
            Some(&deleg),
        )
        .unwrap();
        let (acc, _) = GssContext::accept_sec_context(
            &token,
            std::slice::from_ref(&skey),
            None,
            Some(&documented_host()),
            Some(TEST_REALM),
        )
        .unwrap();
        let want = format!("{TEST_USER}@{TEST_REALM}");
        assert_eq!(acc.delegated(), Some(want.as_str()));
    }

    struct WrappedIov {
        header: Vec<u8>,
        data: Vec<u8>,
        padding: Vec<u8>,
        trailer: Vec<u8>,
        sign: Vec<u8>,
    }

    fn wrap_iov_once(ctx: &mut GssContext, msg: &[u8], assoc: Option<&[u8]>) -> WrappedIov {
        let mut header = Vec::new();
        let mut data = msg.to_vec();
        let mut padding = vec![0xff];
        let mut trailer = Vec::new();
        let mut sign = assoc.unwrap_or(&[]).to_vec();
        let mut iov = vec![
            IovBuf {
                kind: IovType::Header,
                data: &mut header,
            },
            IovBuf {
                kind: IovType::Data,
                data: &mut data,
            },
            IovBuf {
                kind: IovType::Padding,
                data: &mut padding,
            },
            IovBuf {
                kind: IovType::Trailer,
                data: &mut trailer,
            },
        ];
        if assoc.is_some() {
            iov.insert(
                1,
                IovBuf {
                    kind: IovType::SignOnly,
                    data: &mut sign,
                },
            );
        }
        ctx.wrap_iov(true, &mut iov).unwrap();
        WrappedIov {
            header,
            data,
            padding,
            trailer,
            sign,
        }
    }

    fn unwrap_iov_once(
        ctx: &mut GssContext,
        header: &mut Vec<u8>,
        data: &mut Vec<u8>,
        padding: &mut Vec<u8>,
        trailer: &mut Vec<u8>,
        assoc: Option<&mut Vec<u8>>,
    ) -> Result<(), Error> {
        let mut iov = Vec::new();
        iov.push(IovBuf {
            kind: IovType::Header,
            data: header,
        });
        if let Some(s) = assoc {
            iov.push(IovBuf {
                kind: IovType::SignOnly,
                data: s,
            });
        }
        iov.push(IovBuf {
            kind: IovType::Data,
            data,
        });
        iov.push(IovBuf {
            kind: IovType::Padding,
            data: padding,
        });
        iov.push(IovBuf {
            kind: IovType::Trailer,
            data: trailer,
        });
        ctx.unwrap_iov(&mut iov)
    }

    #[test]
    fn wrap_iov_slices_match_wrap_token() {
        let (mut init, mut acc) = contexts();
        let w = wrap_iov_once(&mut init, b"iov-hello", None);
        assert_eq!(w.header.len(), 32, "GSS 16 + AES confounder 16");
        assert_eq!(w.padding.len(), 0, "AES padding empty");
        assert_eq!(w.trailer.len(), 16 + 12, "E(header)+HMAC-SHA1-96");
        assert_eq!(&w.header[..2], &TOK_WRAP);
        assert_eq!(&w.header[6..8], &[0, 0], "RRC=0");
        let tok: Vec<u8> = [&w.header[..], &w.data[..], &w.padding[..], &w.trailer[..]].concat();
        assert_eq!(acc.unwrap(&tok).unwrap(), b"iov-hello");
        let (mut init, mut acc) = contexts();
        let mut h = Vec::new();
        let mut d = b"iov-hello".to_vec();
        let mut p = Vec::new();
        let mut t = Vec::new();
        init.wrap_iov(
            true,
            &mut [
                IovBuf {
                    kind: IovType::Header,
                    data: &mut h,
                },
                IovBuf {
                    kind: IovType::Data,
                    data: &mut d,
                },
                IovBuf {
                    kind: IovType::Padding,
                    data: &mut p,
                },
                IovBuf {
                    kind: IovType::Trailer,
                    data: &mut t,
                },
            ],
        )
        .unwrap();
        unwrap_iov_once(&mut acc, &mut h, &mut d, &mut p, &mut t, None).unwrap();
        assert_eq!(d, b"iov-hello");
    }

    #[test]
    fn wrap_iov_sign_only_is_checksummed_not_encrypted() {
        let (mut init, mut acc) = contexts();
        let assoc = b"rpc-hdr";
        let mut w = wrap_iov_once(&mut init, b"body", Some(assoc));
        assert_eq!(w.sign, assoc, "SIGN_ONLY is not encrypted");
        assert_ne!(w.data, b"body", "DATA is ciphertext");
        unwrap_iov_once(
            &mut acc,
            &mut w.header,
            &mut w.data,
            &mut w.padding,
            &mut w.trailer,
            Some(&mut w.sign),
        )
        .unwrap();
        assert_eq!(w.data, b"body");
        let (mut init, mut acc) = contexts();
        let mut w = wrap_iov_once(&mut init, b"body", Some(assoc));
        let mut bad = assoc.to_vec();
        bad[0] ^= 1;
        assert!(matches!(
            unwrap_iov_once(
                &mut acc,
                &mut w.header,
                &mut w.data,
                &mut w.padding,
                &mut w.trailer,
                Some(&mut bad)
            ),
            Err(Error::Integrity)
        ));
    }

    fn bare_ctx(key: ProtocolKey, initiator: bool) -> GssContext {
        GssContext {
            session: key,
            acceptor_subkey: None,
            send_seq: 0,
            recv_seq: 0,
            recv_seen: false,
            recv_window: std::collections::HashSet::new(),
            initiator,
            rpcsec_init_window: false,
            replay: krb5_protocol::ReplayCache::new(),
            client: None,
            delegated: None,
            spnego_mech_list: None,
            lifetime_end: 0,
            gss_flags: GSS_C_INTEG | GSS_C_CONF,
        }
    }

    #[test]
    fn wrap_iov_rfc8009_sign_only_round_trips() {
        let et = EncryptionType::Aes256CtsHmacSha384192;
        let key = ProtocolKey::from_bytes(et, &[0x5au8; 32]).unwrap();
        let mut init = bare_ctx(key.clone(), true);
        let mut acc = bare_ctx(key, false);
        let mut w = wrap_iov_once(&mut init, b"sha2-body", Some(b"rpc-hdr"));
        assert_eq!(w.trailer.len(), 16 + 24, "E(header)+HMAC-SHA384-192");
        assert_eq!(w.sign, b"rpc-hdr");
        unwrap_iov_once(
            &mut acc,
            &mut w.header,
            &mut w.data,
            &mut w.padding,
            &mut w.trailer,
            Some(&mut w.sign),
        )
        .unwrap();
        assert_eq!(w.data, b"sha2-body");
    }

    #[test]
    fn export_import_wrap_still_works() {
        let (mut init, acc) = contexts();
        let w = init.wrap(b"keep").unwrap();
        let tok = acc.export_sec_context().unwrap();
        let mut acc2 = GssContext::import_sec_context(&tok).unwrap();
        assert_eq!(acc2.unwrap(&w).unwrap(), b"keep");
        let w2 = init.wrap(b"again").unwrap();
        assert_eq!(acc2.unwrap(&w2).unwrap(), b"again");
        assert!(matches!(
            GssContext::import_sec_context(&tok[..8]),
            Err(Error::Truncated)
        ));
        assert!(matches!(
            GssContext::import_sec_context(b"XXXX"),
            Err(Error::Truncated)
        ));
    }

    #[test]
    fn inquire_reports_lifetime_and_flags() {
        let (_init, acc) = contexts();
        let q = acc.inquire_context();
        assert!(!q.initiator);
        assert_ne!(q.flags & GSS_C_INTEG, 0);
        assert_ne!(q.flags & GSS_C_CONF, 0);
        assert_ne!(q.flags & GSS_C_TRANS, 0);
        assert!(q.lifetime > 0, "ticket endtime must be stashed");
        assert!(q.client.is_some());
        let (init, _) = contexts();
        assert!(init.inquire_context().initiator);
        assert_ne!(init.gss_flags() & GSS_C_INTEG, 0);
    }

    #[test]
    fn wrap_iov_hostile_header_is_truncated() {
        let (mut init, _acc) = contexts();
        let mut data = b"x".to_vec();
        let mut trailer = Vec::new();
        let r = init.wrap_iov(
            true,
            &mut [
                IovBuf {
                    kind: IovType::Data,
                    data: &mut data,
                },
                IovBuf {
                    kind: IovType::Trailer,
                    data: &mut trailer,
                },
            ],
        );
        assert!(matches!(r, Err(Error::Truncated)));
        let (h, pad, t) = init.wrap_iov_length(true).unwrap();
        assert_eq!((h, pad, t), (32, 0, 28));
    }
}
