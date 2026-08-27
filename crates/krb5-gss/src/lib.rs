//! GSS-API Kerberos V5 mechanism (RFC 4121) and SPNEGO (RFC 4178).
//!
//! Interop with MIT `libgssapi_krb5` is out-of-process only. This crate
//! never links C libraries.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use krb5_asn1::encode;
use krb5_crypto::{KeyUsage, ProtocolKey, checksum, decrypt, encrypt, verify_checksum};
use krb5_protocol::{ReplayCache, build_ap_rep, build_ap_req_with_cksum};
use krb5_types::{ApOptions, Checksum, PrincipalName, Realm, Ticket, ku};
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

const GSS_C_MUTUAL: u32 = 2;
const GSS_C_REPLAY: u32 = 4;
const GSS_C_SEQUENCE: u32 = 8;
const GSS_C_CONF: u32 = 16;
const GSS_C_INTEG: u32 = 32;

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
    send_seq: u64,
    recv_seq: u64,
    recv_seen: bool,
    recv_window: std::collections::HashSet<u64>,
    initiator: bool,
    replay: ReplayCache,
    /// Authenticated client `name@REALM` (set on accept; initiator from cname).
    pub client: Option<String>,
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
        let cksum = Checksum {
            cksumtype: GSS_CHECKSUM_TYPE,
            checksum: authenticator_checksum(channel_bindings, flags).into(),
        };
        let sub = random_subkey(session)?;
        let enc_sub = krb5_types::EncryptionKey {
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
                send_seq: 0,
                recv_seq: 0,
                recv_seen: false,
                recv_window: std::collections::HashSet::new(),
                initiator: true,
                replay: ReplayCache::new(),
                client: Some(format!(
                    "{}@{}",
                    cname.components_joined(),
                    String::from_utf8_lossy(crealm.as_bytes())
                )),
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
            send_seq: 0,
            recv_seq: 0,
            recv_seen: false,
            recv_window: std::collections::HashSet::new(),
            initiator: false,
            replay: ReplayCache::new(),
            client: None,
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
        let mut want_mutual = ok.mutual_required;
        if let Some(ck) = &ok.authenticator.cksum {
            if ck.cksumtype == GSS_CHECKSUM_TYPE {
                check_channel_bindings(ck.checksum.as_ref(), channel_bindings)?;
                if ck.checksum.as_ref().len() >= 24 {
                    let mut f = [0u8; 4];
                    f.copy_from_slice(&ck.checksum.as_ref()[20..24]);
                    want_mutual |= u32::from_le_bytes(f) & GSS_C_MUTUAL != 0;
                }
            }
        }
        let sess = if let Some(sk) = &ok.authenticator.subkey {
            ProtocolKey::from_bytes(
                krb5_crypto::EncryptionType::from_iana(sk.keytype)
                    .or_else(|_| krb5_crypto::EncryptionType::known(sk.keytype))?,
                sk.keyvalue.as_ref(),
            )?
        } else {
            ProtocolKey::from_bytes(
                krb5_crypto::EncryptionType::from_iana(ok.ticket_part.key.keytype)
                    .or_else(|_| krb5_crypto::EncryptionType::known(ok.ticket_part.key.keytype))?,
                ok.ticket_part.key.keyvalue.as_ref(),
            )?
        };
        let base = ok.authenticator.seq_number.unwrap_or(0);
        let out = Self {
            session: sess,
            send_seq: 0,
            recv_seq: u64::from(base),
            recv_seen: false,
            recv_window: std::collections::HashSet::new(),
            initiator: false,
            replay: ctx.replay,
            client: Some(client),
        };
        let mut ap_rep_tok = None;
        if want_mutual {
            let ap_rep = build_ap_rep(&out.session, &ok.authenticator, None, Some(0))?;
            let der = encode(&ap_rep)?;
            ap_rep_tok = Some(gss_wrap_app(TOK_AP_REP, &der));
        }
        Ok((out, ap_rep_tok))
    }

    /// Per-message wrap (confidentiality). RFC 4121 §4.2.6 token.
    ///
    /// # Errors
    ///
    /// Crypto failures.
    pub fn wrap(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        // RFC 4121 RRC: rotate EC bytes of ciphertext toward the header so
        // SSPI can decrypt in place. AES confounder is 16 octets.
        self.wrap_with_rrc_inner(plaintext, 16)
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
            verify_checksum(&self.session, usage, &to_ck, mac).map_err(|_| Error::Integrity)?;
            return Ok(data.to_vec());
        }
        let plain = decrypt(&self.session, usage, &payload)?;
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
        let mut buf = data.to_vec();
        buf.extend_from_slice(&inner[..16]);
        verify_checksum(&self.session, usage, &buf, &inner[16..]).map_err(|_| Error::Integrity)?;
        Ok(())
    }

    /// Session key established by the context (for tests and the acceptor binary).
    #[must_use]
    pub fn session_key(&self) -> &ProtocolKey {
        &self.session
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
        let header = wrap_header(self.initiator, true, self.send_seq);
        let mut to_enc = plaintext.to_vec();
        to_enc.extend_from_slice(&header);
        let cipher = encrypt(&self.session, usage, &to_enc)?;
        self.send_seq = self.send_seq.wrapping_add(1);
        let mut tok = header.to_vec();
        tok.extend_from_slice(&cipher);
        apply_send_rrc(&mut tok, rrc)?;
        Ok(tok)
    }

    fn accept_seq(&mut self, seq: u64) -> Result<(), Error> {
        if self.recv_window.contains(&seq) {
            return Err(Error::Sequence);
        }
        if !self.recv_seen {
            if seq != self.recv_seq {
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

fn random_subkey(session: &ProtocolKey) -> Result<ProtocolKey, Error> {
    let n = session.etype().key_len();
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).map_err(|e| Error::Inner(e.to_string()))?;
    ProtocolKey::from_bytes(session.etype(), &b).map_err(Error::from)
}

fn authenticator_checksum(cb: Option<&ChannelBindings>, flags: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(24);
    v.extend_from_slice(&16u32.to_le_bytes());
    v.extend_from_slice(&ChannelBindings::bnd_hash(cb));
    v.extend_from_slice(&flags.to_le_bytes());
    v
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
    let usage = seal_usage(initiator);
    let header = wrap_header(initiator, true, seq);
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
        assert_ne!(&wrapped[6..8], &[0, 0], "production wrap emits RRC≠0");
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
}
