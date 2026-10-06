//! The acceptor's auth context (`krb/auth_con.c`, `rd_req_dec.c`, `mk_rep.c`, `mk_priv.c`,
//! `rd_priv.c`, `rd_safe.c`, `privsafe.c`, `gen_seqnum.c`, `gen_save_subkey.c`): what an accepted
//! AP-REQ leaves for the AP-REP that answers it and the KRB-SAFE and KRB-PRIV messages after it.
//!
//! The context starts as `krb5_auth_con_init` leaves one (`DO_TIME`); the caller sets the flags
//! its MIT program sets. `krb5_mk_rep` takes a fresh subkey only under `USE_SUBKEY` and otherwise
//! echoes the authenticator's own, and its sequence number is random only when the context has
//! none yet. `krb5_rd_priv` and `krb5_rd_safe` take the peer's messages in order under
//! `DO_SEQUENCE`, from the authenticator's sequence number on.

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    CipherState, EncryptionType, KeyUsage, ProtocolKey, checksum_output_size, decrypt,
    decrypt_with_state, encrypt, encrypt_with_state, parse_enctype_list,
};
use krb5_types::{
    ApRep, Authenticator, AuthorizationData, EncApRepPart, EncKrbPrivPart, EncryptedData,
    EncryptionKey, HostAddress, KerberosTime, KrbPriv, Microseconds, OctetString, err, ku, pa,
};

use crate::ap_req::ApVerifyOk;
use crate::error::Error;
use crate::replay::{ReplayCache, ReplayKey};
use crate::safe_priv::{check_privsafe_addrs, verify_krb_safe_checksum, wipe_octets, wipe_vec};

/// MIT `KRB5_AUTH_CONTEXT_DO_TIME`: KRB-SAFE and KRB-PRIV carry a timestamp.
pub const AUTH_CONTEXT_DO_TIME: u32 = 0x0000_0001;
/// MIT `KRB5_AUTH_CONTEXT_DO_SEQUENCE`: messages carry sequence numbers.
pub const AUTH_CONTEXT_DO_SEQUENCE: u32 = 0x0000_0004;
/// MIT `KRB5_AUTH_CONTEXT_USE_SUBKEY`: the AP-REP carries a fresh subkey of the negotiated
/// enctype.
pub const AUTH_CONTEXT_USE_SUBKEY: u32 = 0x0000_0020;

const ADDRTYPE_INET: i32 = 2;
const ADDRTYPE_DIRECTIONAL: i32 = 3;
const ADDRTYPE_INET6: i32 = 24;

/// MIT's default `clockskew` (`DEFAULT_CLOCKSKEW`, 300 seconds), for a profile that sets none.
const DEFAULT_CLOCKSKEW: i64 = 300;

/// The acceptor's side of an authenticated exchange after the AP-REQ verified.
pub struct AcceptorAuthContext {
    flags: u32,
    key: ProtocolKey,
    authenticator: Authenticator,
    send_subkey: Option<ProtocolKey>,
    recv_subkey: Option<ProtocolKey>,
    local_seq: u32,
    remote: RemoteSeq,
    negotiated_etype: EncryptionType,
    ap_req_use_subkey: bool,
    local_addr: Option<HostAddress>,
    remote_addr: Option<HostAddress>,
    cstate: Option<CipherState>,
    memrcache: Option<ReplayCache>,
}

/// The sequence number the peer's next KRB-SAFE or KRB-PRIV must carry, and what its earlier
/// ones showed the peer to be (MIT `KRB5_AUTH_CONN_SANE_SEQ`, `KRB5_AUTH_CONN_HEIMDAL_SEQ`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RemoteSeq {
    expected: u32,
    sane: bool,
    heimdal: bool,
}

impl RemoteSeq {
    /// A peer whose next message must carry `expected` (`remote_seq_number`).
    #[must_use]
    pub const fn new(expected: u32) -> Self {
        Self {
            expected,
            sane: false,
            heimdal: false,
        }
    }

    /// The sequence number the next message must carry.
    #[must_use]
    pub const fn expected(&self) -> u32 {
        self.expected
    }

    /// Whether a message carrying `in_seq` is the next one, learning from it whether the peer
    /// is a sane sender or an old Heimdal that sends short numbers sign-extended.
    /// MIT `k5_privsafe_check_seqnum` (`lib/krb5/krb/privsafe.c:225-304`): a peer known sane must match exactly; otherwise a number in the ambiguous range 0xFF800000..0xFFFFFFFF matches exactly or as a Heimdal encoding of the expected one (which marks the peer Heimdal), an exact match of an expected number in the ambiguous counter ranges marks the peer sane, and an expected 0 takes Heimdal's wraparound values 0x100, 0x10000 and 0x1000000.
    pub const fn check(&mut self, in_seq: u32) -> bool {
        let exp_seq = self.expected;
        if self.sane {
            return in_seq == exp_seq;
        }
        if in_seq & 0xFF80_0000 == 0xFF80_0000 {
            if exp_seq & 0xFF80_0000 == 0xFF80_0000 && in_seq == exp_seq {
                return true;
            }
            if !self.heimdal && in_seq == exp_seq {
                return true;
            }
            if chk_heimdal_seqnum(exp_seq, in_seq) {
                self.heimdal = true;
                return true;
            }
            return false;
        }
        if in_seq == exp_seq {
            if exp_seq & 0xFFFF_FF80 == 0x0000_0080
                || exp_seq & 0xFFFF_8000 == 0x0000_8000
                || exp_seq & 0xFF80_0000 == 0x0080_0000
            {
                self.sane = true;
            }
            return true;
        }
        if exp_seq == 0 && !self.heimdal {
            return match in_seq {
                0x100 | 0x1_0000 | 0x100_0000 => {
                    self.heimdal = true;
                    true
                }
                _ => false,
            };
        }
        false
    }

    /// The number after a message that passed (`remote_seq_number++`).
    pub const fn advance(&mut self) {
        self.expected = self.expected.wrapping_add(1);
    }
}

/// MIT `chk_heimdal_seqnum` (`lib/krb5/krb/privsafe.c:206-223`): `in_seq` is `exp_seq` as an old Heimdal encodes it, a 1-, 2- or 3-octet count read back sign-extended.
const fn chk_heimdal_seqnum(exp_seq: u32, in_seq: u32) -> bool {
    (exp_seq & 0xFF80_0000 == 0x0080_0000
        && in_seq & 0xFF80_0000 == 0xFF80_0000
        && in_seq & 0x00FF_FFFF == exp_seq)
        || (exp_seq & 0xFFFF_8000 == 0x0000_8000
            && in_seq & 0xFFFF_8000 == 0xFFFF_8000
            && in_seq & 0x0000_FFFF == exp_seq)
        || (exp_seq & 0xFFFF_FF80 == 0x0000_0080
            && in_seq & 0xFFFF_FF80 == 0xFFFF_FF80
            && in_seq & 0x0000_00FF == exp_seq)
}

fn krb_error(code: i32, text: &str) -> Error {
    Error::KrbError {
        code,
        text: Some(text.into()),
    }
}

/// Whether a ticket encrypted in `ticket_etype` may be read where `permitted` holds.
/// MIT `krb5_decrypt_tkt_part` (`lib/krb5/krb/decrypt_tk.c:46-50`): an enctype the library does not implement is `KRB5_PROG_ETYPE_NOSUPP`, one it does but `permitted_enctypes` leaves out is `KRB5_NOPERM_ETYPE`, before any decryption.
///
/// # Errors
///
/// [`Error::ProgEtypeNosupp`] for an enctype not implemented; [`Error::NopermEtype`] for one not
/// permitted.
pub fn check_ticket_etype(ticket_etype: i32, permitted: &[EncryptionType]) -> Result<(), Error> {
    let etype = EncryptionType::known(ticket_etype).map_err(|_| Error::ProgEtypeNosupp)?;
    if permitted.contains(&etype) {
        Ok(())
    } else {
        Err(Error::NopermEtype(NOPERM_ETYPE.into()))
    }
}

/// The enctype an AP-REQ's authenticator negotiates against `permitted`, as `krb5_rd_req` does
/// on every acceptor, the KDC's own included.
/// MIT `rd_req_decoded_opt` (`lib/krb5/krb/rd_req_dec.c:652-723`): the RFC 4537 list, then the subkey's and the session key's enctypes, go to `negotiate_etype`; every enctype after the RFC 4537 list must be permitted.
///
/// # Errors
///
/// [`Error::NopermEtype`] when `permitted` lacks the session key's or the subkey's enctype;
/// [`Error::Asn1`] when the authenticator's AD-ETYPE-NEGOTIATION list does not decode.
pub fn negotiate_ap_req_etypes(
    authenticator: &Authenticator,
    session_etype: i32,
    permitted: &[EncryptionType],
) -> Result<EncryptionType, Error> {
    let mut desired = decode_etype_list(authenticator)?.unwrap_or_default();
    let rfc4537_len = desired.len();
    if let Some(sk) = &authenticator.subkey {
        desired.push(sk.keytype);
    }
    desired.push(session_etype);
    negotiate_etype(&desired, rfc4537_len, permitted)
}

impl AcceptorAuthContext {
    /// The auth context an accepted AP-REQ leaves, checked against the `permitted` enctypes.
    /// MIT `rd_req_decoded_opt` (`lib/krb5/krb/rd_req_dec.c:652-773`): the RFC 4537 list, then the subkey's and the session key's enctypes, are negotiated, the peer's sequence number and subkey are kept, and without mutual authentication the local sequence number starts from the peer's.
    /// MIT `krb5_decrypt_tkt_part` (`lib/krb5/krb/decrypt_tk.c:46-50`): the ticket's own enctype must be permitted too.
    ///
    /// # Errors
    ///
    /// [`Error::NopermEtype`] when `permitted` lacks the ticket's, the session key's or the
    /// subkey's enctype; [`Error::ProgEtypeNosupp`] for a ticket enctype not implemented;
    /// [`Error::Asn1`] when the authenticator's AD-ETYPE-NEGOTIATION list does not decode;
    /// [`Error::Crypto`] when the session key or the subkey is not a usable key.
    pub fn from_ap_req(ok: &ApVerifyOk, permitted: &[EncryptionType]) -> Result<Self, Error> {
        check_ticket_etype(ok.ticket_etype, permitted)?;
        let key = protocol_key(&ok.ticket_part.key)?;
        let authenticator = ok.authenticator.clone();
        let negotiated_etype =
            negotiate_ap_req_etypes(&authenticator, ok.ticket_part.key.keytype, permitted)?;
        let remote_seq = authenticator.seq_number.unwrap_or(0);
        let recv_subkey = authenticator
            .subkey
            .as_ref()
            .map(protocol_key)
            .transpose()?;
        let mut local_seq = 0u32;
        if !ok.mutual_required && remote_seq != 0 {
            local_seq ^= remote_seq;
        }
        let ap_req_use_subkey = negotiated_etype != key.etype();
        Ok(Self {
            flags: AUTH_CONTEXT_DO_TIME,
            key,
            authenticator,
            send_subkey: recv_subkey.clone(),
            recv_subkey,
            local_seq,
            remote: RemoteSeq::new(remote_seq),
            negotiated_etype,
            ap_req_use_subkey,
            local_addr: None,
            remote_addr: None,
            cstate: None,
            memrcache: None,
        })
    }

    /// Set the addresses messages are checked against and sent from, as `krb5_auth_con_setaddrs`
    /// does: `local` is this side's (a KRB-PRIV's or KRB-SAFE's receiver must be it when named),
    /// `remote` the peer's (a message's sender must be it).
    pub fn set_addrs(&mut self, local: Option<HostAddress>, remote: Option<HostAddress>) {
        self.local_addr = local;
        self.remote_addr = remote;
    }

    /// Start chaining KRB-PRIV encryption from the initial cipher state, as kprop and kpropd do
    /// for the dump's blocks.
    /// MIT `krb5_auth_con_initivector` (`lib/krb5/krb/auth_con.c:314-322`): the cipher state starts from the session key's initial state for `KRB_PRIV` encryption, and `krb5_mk_priv` and `krb5_rd_priv` chain through it from then on.
    pub fn init_ivector(&mut self) {
        self.cstate = Some(CipherState::initial());
    }

    /// The context flags (`AUTH_CONTEXT_*`).
    #[must_use]
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Replace the context flags, as `krb5_auth_con_setflags` does.
    pub const fn set_flags(&mut self, flags: u32) {
        self.flags = flags;
    }

    /// The ticket's session key (`auth_context->key`).
    #[must_use]
    pub const fn key(&self) -> &ProtocolKey {
        &self.key
    }

    /// The subkey messages are sent under: the AP-REP's own after `USE_SUBKEY`, else the
    /// authenticator's.
    #[must_use]
    pub const fn send_subkey(&self) -> Option<&ProtocolKey> {
        self.send_subkey.as_ref()
    }

    /// The subkey messages are received under.
    #[must_use]
    pub const fn recv_subkey(&self) -> Option<&ProtocolKey> {
        self.recv_subkey.as_ref()
    }

    /// This side's sequence number: the AP-REP's, then advanced by each message sent.
    #[must_use]
    pub const fn local_seq(&self) -> u32 {
        self.local_seq
    }

    /// The sequence number the peer's next message must carry: the authenticator's, then
    /// advanced by each message read.
    #[must_use]
    pub const fn remote_seq(&self) -> u32 {
        self.remote.expected()
    }

    /// The enctype `krb5_mk_rep` gives a fresh subkey.
    #[must_use]
    pub const fn negotiated_etype(&self) -> EncryptionType {
        self.negotiated_etype
    }

    /// Whether the negotiation chose an enctype other than the session key's
    /// (`AP_OPTS_USE_SUBKEY` in `krb5_rd_req`'s `ap_req_options`).
    #[must_use]
    pub const fn ap_req_use_subkey(&self) -> bool {
        self.ap_req_use_subkey
    }

    /// The AP-REP answering the AP-REQ.
    /// MIT `k5_mk_rep` (`lib/krb5/krb/mk_rep.c:67-140`): under `DO_SEQUENCE` a context with no sequence number takes a random one, `USE_SUBKEY` makes a fresh subkey of the negotiated enctype (else the authenticator's subkey is echoed), and the part is encrypted in the session key.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] when the OS random source fails or the part does not encrypt;
    /// [`Error::Asn1`] when it does not encode.
    pub fn mk_rep(&mut self) -> Result<ApRep, Error> {
        if self.flags & AUTH_CONTEXT_DO_SEQUENCE != 0 && self.local_seq == 0 {
            self.local_seq = generate_seq_number()?;
        }
        let subkey = if self.flags & AUTH_CONTEXT_USE_SUBKEY != 0 {
            let fresh = ProtocolKey::random(self.negotiated_etype)?;
            let wire = encryption_key(&fresh);
            self.send_subkey = Some(fresh.clone());
            self.recv_subkey = Some(fresh);
            Some(wire)
        } else {
            self.authenticator.subkey.clone()
        };
        let part = EncApRepPart {
            ctime: self.authenticator.ctime.clone(),
            cusec: self.authenticator.cusec,
            subkey,
            seq_number: (self.local_seq != 0).then_some(self.local_seq),
        };
        let der = encode(&part)?;
        let cipher = KeyUsage::new(ku::AP_REP_ENC_PART)
            .map_err(Error::from)
            .and_then(|usage| Ok(encrypt(&self.key, usage, &der)?));
        // MIT `k5_mk_rep` (`lib/krb5/krb/mk_rep.c:135-137`): the encoded part, subkey and all, is zeroed before it is freed, whether or not it encrypted.
        wipe_vec(der);
        let cipher = cipher?;
        Ok(ApRep {
            pvno: ApRep::PVNO,
            msg_type: ApRep::MSG_TYPE,
            enc_part: EncryptedData {
                etype: self.key.etype().to_iana(),
                kvno: None,
                cipher: cipher.into(),
            },
        })
    }

    /// A KRB-PRIV of `user_data` from `local_addr` (and to `remote_addr`).
    /// MIT `krb5_mk_priv` (`lib/krb5/krb/mk_priv.c:105-155`): the send subkey else the session key, the timestamp only under `DO_TIME`, the sequence number under `DO_SEQUENCE`, which then advances.
    ///
    /// # Errors
    ///
    /// [`Error::Asn1`] when the part does not encode; [`Error::Crypto`] when it does not
    /// encrypt.
    pub fn mk_priv(
        &mut self,
        user_data: &[u8],
        local_addr: &HostAddress,
        remote_addr: Option<&HostAddress>,
    ) -> Result<KrbPriv, Error> {
        let (timestamp, usec) = if self.flags & AUTH_CONTEXT_DO_TIME != 0 {
            let (secs, usec) = us_timeofday();
            (Some(secs), Some(usec))
        } else {
            (None, None)
        };
        let do_sequence = self.flags & AUTH_CONTEXT_DO_SEQUENCE != 0;
        let seq = if do_sequence { self.local_seq } else { 0 };
        let part = EncKrbPrivPart {
            user_data: user_data.to_vec().into(),
            timestamp,
            usec,
            seq_number: (seq != 0).then_some(seq),
            s_address: local_addr.clone(),
            r_address: remote_addr.cloned(),
        };
        let key = self.send_subkey.as_ref().unwrap_or(&self.key);
        let der = encode(&part);
        // The user data was copied into the part only to be encoded.
        wipe_octets(part.user_data);
        let der = der?;
        let cstate = self.cstate.as_mut();
        let cipher = KeyUsage::new(ku::KRB_PRIV_ENC_PART)
            .map_err(Error::from)
            .and_then(|usage| match cstate {
                Some(state) => Ok(encrypt_with_state(key, usage, state, &der)?),
                None => Ok(encrypt(key, usage, &der)?),
            });
        // MIT `create_krbpriv` (`lib/krb5/krb/mk_priv.c:97-100`): the encoded part is zeroed before it is freed, whether or not it encrypted.
        wipe_vec(der);
        let cipher = cipher?;
        let msg = KrbPriv {
            pvno: KrbPriv::PVNO,
            msg_type: KrbPriv::MSG_TYPE,
            enc_part: EncryptedData {
                etype: key.etype().to_iana(),
                kvno: None,
                cipher: cipher.into(),
            },
        };
        if do_sequence {
            self.local_seq = self.local_seq.wrapping_add(1);
        }
        Ok(msg)
    }

    /// The user data of a KRB-PRIV from the peer.
    /// MIT `krb5_rd_priv` (`lib/krb5/krb/rd_priv.c:99-150`): decrypted under the receive subkey else the session key (through the cipher state once `krb5_auth_con_initivector` set one), its addresses checked against the context's, a replay refused under `DO_TIME`, and its sequence number checked against the peer's next one, which then advances, under `DO_SEQUENCE`.
    /// MIT `read_krbpriv` (`lib/krb5/krb/rd_priv.c:43-97`): a message that is not a KRB-PRIV is `KRB5KRB_AP_ERR_MSG_TYPE`, and the decrypted part is zeroed before it is freed.
    ///
    /// # Errors
    ///
    /// [`Error::KrbError`] `MSG_TYPE` (40) for another message type, `BADADDR` (38) for an
    /// address that does not match, `SKEW` (37) or `REPEAT` (34) under `DO_TIME`, and `BADORDER`
    /// (42) for an out-of-order sequence number under `DO_SEQUENCE`; [`Error::Asn1`] when the
    /// message or its part does not decode; [`Error::Crypto`] when it does not decrypt.
    pub fn rd_priv(&mut self, raw: &[u8]) -> Result<Vec<u8>, Error> {
        // MIT `krb5_is_krb_priv`: [APPLICATION 21], constructed or not.
        if raw.first().is_none_or(|b| b & !0x20 != 0x55) {
            return Err(krb_error(err::MSG_TYPE, "Invalid message type"));
        }
        let msg: KrbPriv = decode(raw)?;
        let key = self.recv_subkey.as_ref().unwrap_or(&self.key);
        let etype = key.etype();
        let usage = KeyUsage::new(ku::KRB_PRIV_ENC_PART)?;
        let cipher = msg.enc_part.cipher.as_ref();
        let plain = match self.cstate.as_mut() {
            Some(state) => decrypt_with_state(key, usage, state, cipher)?,
            None => decrypt(key, usage, cipher)?,
        };
        let part = decode::<EncKrbPrivPart>(&plain);
        wipe_vec(plain);
        let part = part?;
        let checked = check_privsafe_addrs(
            &part.s_address,
            part.r_address.as_ref(),
            self.remote_addr.as_ref(),
            self.local_addr.as_ref(),
        )
        .and_then(|()| {
            let tag = ciphertext_tag(etype, cipher)?;
            self.check_replay(part.timestamp.as_ref(), tag)
        })
        .and_then(|()| self.check_seq(part.seq_number));
        let user_data = part.user_data.to_vec();
        wipe_octets(part.user_data);
        checked.map(|()| user_data)
    }

    /// The user data of a KRB-SAFE from the peer.
    /// MIT `krb5_rd_safe` (`lib/krb5/krb/rd_safe.c:127-178`): its checksum verified under the receive subkey else the session key (`read_krbsafe`), a replay refused under `DO_TIME`, and its sequence number checked against the peer's next one, which then advances, under `DO_SEQUENCE`.
    ///
    /// # Errors
    ///
    /// [`Error::KrbError`] as [`verify_krb_safe_checksum`] reports a message it refuses, `SKEW`
    /// (37) or `REPEAT` (34) under `DO_TIME`, and `BADORDER` (42) for an out-of-order sequence
    /// number under `DO_SEQUENCE`; [`Error::Asn1`] when the message does not decode.
    pub fn rd_safe(&mut self, raw: &[u8]) -> Result<Vec<u8>, Error> {
        let key = self.recv_subkey.as_ref().unwrap_or(&self.key);
        let msg = verify_krb_safe_checksum(
            key,
            raw,
            self.remote_addr.as_ref(),
            self.local_addr.as_ref(),
        )?;
        self.check_replay(
            msg.safe_body.timestamp.as_ref(),
            msg.cksum.checksum.as_ref(),
        )?;
        self.check_seq(msg.safe_body.seq_number)?;
        Ok(msg.safe_body.user_data.to_vec())
    }

    /// MIT `k5_privsafe_check_replay` (`lib/krb5/krb/privsafe.c:107-141`): only under `DO_TIME`, a timestamp outside the clock skew is `KRB5KRB_AP_ERR_SKEW`, and a message whose tag the context's memory replay cache already holds is `KRB5KRB_AP_ERR_REPEAT`.
    /// MIT `krb5_init_context_profile` (`lib/krb5/krb/init_ctx.c:251-252`): the clock skew is `[libdefaults] clockskew`, 300 seconds when it is unset.
    fn check_replay(&mut self, timestamp: Option<&KerberosTime>, tag: &[u8]) -> Result<(), Error> {
        if self.flags & AUTH_CONTEXT_DO_TIME == 0 {
            return Ok(());
        }
        let skew =
            krb5_config::load_krb5_conf().map_or(DEFAULT_CLOCKSKEW, |c| i64::from(c.clockskew));
        let now = i64::from(KerberosTime::now().unix_seconds());
        let then = timestamp.map_or(0, |t| i64::from(t.unix_seconds()));
        if (now - then).abs() > skew {
            return Err(krb_error(err::SKEW, "Clock skew too great"));
        }
        let key = ReplayKey {
            client: String::new(),
            server: String::new(),
            ctime: 0,
            cusec: 0,
            auth_hash: ReplayCache::hash_authenticator(tag),
        };
        if self
            .memrcache
            .get_or_insert_with(ReplayCache::new)
            .check_and_store(key)
        {
            return Err(krb_error(err::REPEAT, "Request is a replay"));
        }
        Ok(())
    }

    /// MIT `krb5_rd_priv` (`lib/krb5/krb/rd_priv.c:128-134`): under `DO_SEQUENCE`, a message whose sequence number (0 when it carries none) is not the peer's next is `KRB5KRB_AP_ERR_BADORDER`, and one that is moves the peer on; `krb5_rd_safe` does the same.
    fn check_seq(&mut self, seq: Option<u32>) -> Result<(), Error> {
        if self.flags & AUTH_CONTEXT_DO_SEQUENCE == 0 {
            return Ok(());
        }
        if !self.remote.check(seq.unwrap_or(0)) {
            return Err(krb_error(err::BADORDER, "Message out of order"));
        }
        self.remote.advance();
        Ok(())
    }
}

/// The replay tag of an encrypted message: its last checksum-length octets.
/// MIT `k5_rc_tag_from_ciphertext` (`lib/krb5/rcache/rc_base.c:146-164`): the tag is the end of the ciphertext, as long as the enctype's checksum; a shorter ciphertext is `EINVAL`.
fn ciphertext_tag(etype: EncryptionType, cipher: &[u8]) -> Result<&[u8], Error> {
    let len = checksum_output_size(etype.checksum_type())
        .ok_or_else(|| Error::Crypto("no checksum length for the enctype".into()))?;
    let at = cipher
        .len()
        .checked_sub(len)
        .ok_or_else(|| Error::Crypto("ciphertext shorter than its checksum".into()))?;
    Ok(&cipher[at..])
}

impl std::fmt::Debug for AcceptorAuthContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcceptorAuthContext")
            .field("flags", &self.flags)
            .field("negotiated_etype", &self.negotiated_etype)
            .field("local_seq", &self.local_seq)
            .field("remote", &self.remote)
            .field("send_subkey", &self.send_subkey)
            .field("recv_subkey", &self.recv_subkey)
            .finish_non_exhaustive()
    }
}

/// The time now, to the microsecond, from one clock read.
/// MIT `krb5_us_timeofday` (`lib/krb5/os/ustime.c:66-82`): the seconds and the microseconds come from the same reading (`KerberosTime::now` keeps whole seconds only).
#[must_use]
pub fn us_timeofday() -> (KerberosTime, Microseconds) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = u32::try_from(now.as_secs()).unwrap_or(u32::MAX);
    (
        KerberosTime::from_unix_seconds(secs),
        Microseconds::from_subsec_micros(now.subsec_micros()),
    )
}

/// A fresh initial sequence number.
/// MIT `krb5_generate_seq_number` (`lib/krb5/krb/gen_seqnum.c:39-63`): 30 random bits, so peers that read sequence numbers as signed never see a negative one, and never 0.
///
/// # Errors
///
/// [`Error::Crypto`] when the OS random source fails.
pub fn generate_seq_number() -> Result<u32, Error> {
    let n = seq_random()? & 0x3fff_ffff;
    Ok(if n == 0 { 1 } else { n })
}

#[cfg(any(test, feature = "test-hooks"))]
thread_local! {
    static TEST_SEQ_RANDOM: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

/// Test hook: on this thread, [`generate_seq_number`] takes `raw` as its four random octets, or
/// the OS random source again when `None`. Behind the `test-hooks` feature, so no release build
/// carries it.
#[cfg(any(test, feature = "test-hooks"))]
pub fn set_test_seq_random(raw: Option<u32>) {
    TEST_SEQ_RANDOM.with(|c| c.set(raw));
}

fn seq_random() -> Result<u32, Error> {
    #[cfg(any(test, feature = "test-hooks"))]
    if let Some(raw) = TEST_SEQ_RANDOM.with(std::cell::Cell::get) {
        return Ok(raw);
    }
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(u32::from_ne_bytes(b))
}

/// The enctypes an acceptor permits: krb5.conf `permitted_enctypes`, else MIT's default list.
///
/// # Errors
///
/// [`Error::ConfigEtypeNosupp`] when the configured list names no enctype.
pub fn permitted_enctypes() -> Result<Vec<EncryptionType>, Error> {
    permitted_enctypes_in(None, krb5_config::load_krb5_conf().as_ref())
}

/// The enctypes a server on the KDC profile permits (kadmind, the kpasswd service in it, and
/// kpropd): kdc.conf's `[libdefaults]` relations first, then krb5.conf's.
/// MIT `add_kdc_config_file` (`lib/krb5/os/init_os_ctx.c:339-366`): a KDC context lists kdc.conf ahead of the krb5.conf files, so its relations are found first.
///
/// # Errors
///
/// [`Error::ConfigEtypeNosupp`] when the list that applies names no enctype.
pub fn permitted_enctypes_kdc() -> Result<Vec<EncryptionType>, Error> {
    let kdc = krb5_config::KdcConf::load_file(krb5_config::kdc_conf_path()).ok();
    permitted_enctypes_in(kdc.as_ref(), krb5_config::load_krb5_conf().as_ref())
}

/// MIT `krb5_get_permitted_enctypes` (`lib/krb5/krb/init_ctx.c:573-595`): the first profile file that sets `permitted_enctypes` gives the list (else `DEFAULT`), filtered by `allow_weak_crypto` as the first file setting it says.
fn permitted_enctypes_in(
    kdc: Option<&krb5_config::KdcConf>,
    krb5: Option<&krb5_config::Krb5Conf>,
) -> Result<Vec<EncryptionType>, Error> {
    let allow_weak = kdc
        .and_then(|k| k.allow_weak_crypto)
        .unwrap_or_else(|| krb5.is_some_and(|c| c.allow_weak_crypto));
    let profstr = kdc
        .map(|k| &k.permitted_enctypes)
        .filter(|list| !list.is_empty())
        .or_else(|| {
            krb5.map(|c| &c.permitted_enctypes)
                .filter(|list| !list.is_empty())
        })
        .map_or_else(|| "DEFAULT".to_owned(), |list| list.join(" "));
    parse_enctype_list(&profstr, allow_weak).ok_or(Error::ConfigEtypeNosupp)
}

/// The address a reply's KRB-PRIV names as its sender: the address the request came in on.
/// MIT `k5_sockaddr_to_address` (`lib/krb5/os/addr.c:43-75`): an IPv4-mapped IPv6 address is IPv4, and no address is the directional "accept" address (`k5_addr_directional_accept`).
#[must_use]
pub fn local_host_address(local: Option<IpAddr>) -> HostAddress {
    let (addr_type, octets) = match local {
        Some(IpAddr::V4(v4)) => (ADDRTYPE_INET, v4.octets().to_vec()),
        Some(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => (ADDRTYPE_INET, v4.octets().to_vec()),
            None => (ADDRTYPE_INET6, v6.octets().to_vec()),
        },
        None => (ADDRTYPE_DIRECTIONAL, vec![0, 0, 0, 1]),
    };
    HostAddress {
        addr_type,
        address: OctetString::from(octets),
    }
}

/// MIT `decode_etype_list` (`lib/krb5/krb/rd_req_dec.c:906-976`): the first AD-ETYPE-NEGOTIATION element, inside an AD-IF-RELEVANT container or bare; a container that does not decode is passed over, a list that does not decode fails the request.
fn decode_etype_list(a: &Authenticator) -> Result<Option<Vec<i32>>, Error> {
    let Some(ad) = &a.authorization_data else {
        return Ok(None);
    };
    for el in ad {
        let found = match el.ad_type {
            pa::AD_IF_RELEVANT => {
                let Ok(inner) = decode::<AuthorizationData>(el.ad_data.as_ref()) else {
                    continue;
                };
                inner
                    .into_iter()
                    .find(|e| e.ad_type == pa::AD_ETYPE_NEGOTIATION)
            }
            pa::AD_ETYPE_NEGOTIATION => Some(el.clone()),
            _ => None,
        };
        if let Some(e) = found {
            return Ok(Some(decode::<Vec<i32>>(e.ad_data.as_ref())?));
        }
    }
    Ok(None)
}

/// MIT `negotiate_etype` (`lib/krb5/krb/rd_req_dec.c:854-904`): every enctype from `mandatory` on must be permitted, and the result is the first permitted enctype the peer desires.
fn negotiate_etype(
    desired: &[i32],
    mandatory: usize,
    permitted: &[EncryptionType],
) -> Result<EncryptionType, Error> {
    for &d in desired.get(mandatory..).unwrap_or_default() {
        if !permitted.iter().any(|p| p.to_iana() == d) {
            return Err(Error::NopermEtype(EncryptionType::known(d).map_or_else(
                |_| NOPERM_ETYPE.to_owned(),
                |e| format!("Encryption type {} not permitted", e.to_mit_name()),
            )));
        }
    }
    permitted
        .iter()
        .copied()
        .find(|p| desired.contains(&p.to_iana()))
        .ok_or_else(|| Error::NopermEtype(NOPERM_ETYPE.to_owned()))
}

/// MIT `KRB5_NOPERM_ETYPE` (`krb5_err.et:325-325`): the text without an enctype name.
const NOPERM_ETYPE: &str = "Encryption type not permitted";

fn protocol_key(k: &EncryptionKey) -> Result<ProtocolKey, Error> {
    let etype = EncryptionType::known(k.keytype)?;
    Ok(ProtocolKey::from_bytes(etype, k.keyvalue.as_ref())?)
}

fn encryption_key(k: &ProtocolKey) -> EncryptionKey {
    EncryptionKey {
        keytype: k.etype().to_iana(),
        keyvalue: k.as_bytes().to_vec().into(),
    }
}

#[cfg(test)]
mod tests;
