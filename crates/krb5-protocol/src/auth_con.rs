use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    CipherState, EncryptionType, KeyUsage, ProtocolKey, checksum_output_size, decrypt_enc_data,
    decrypt_enc_data_with_state, encrypt, encrypt_with_state,
};
use krb5_types::{
    ApRep, Authenticator, AuthorizationData, EncApRepPart, EncKrbPrivPart, EncryptedData,
    EncryptionKey, HostAddress, KerberosTime, KrbPriv, Microseconds, OctetString, err, ku, pa,
};

use crate::acceptor_conf::AcceptorConfig;
use crate::ap_req::ApVerifyOk;
use crate::error::Error;
use crate::replay::{ReplayCache, ReplayKey};
use crate::safe_priv::{
    check_privsafe_addrs_in, verify_krb_safe_checksum_in, wipe_octets, wipe_vec,
};

pub const AUTH_CONTEXT_DO_TIME: u32 = 0x0000_0001;
pub const AUTH_CONTEXT_DO_SEQUENCE: u32 = 0x0000_0004;
pub const AUTH_CONTEXT_USE_SUBKEY: u32 = 0x0000_0020;

const ADDRTYPE_INET: i32 = 2;
const ADDRTYPE_DIRECTIONAL: i32 = 3;
const ADDRTYPE_INET6: i32 = 24;

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
    host_addrs: Option<Vec<HostAddress>>,
    cstate: Option<CipherState>,
    memrcache: Option<ReplayCache>,
    clockskew: i64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RemoteSeq {
    expected: u32,
    sane: bool,
    heimdal: bool,
}

impl RemoteSeq {
    #[must_use]
    pub const fn new(expected: u32) -> Self {
        Self {
            expected,
            sane: false,
            heimdal: false,
        }
    }

    #[must_use]
    pub const fn expected(&self) -> u32 {
        self.expected
    }

    /// Sane peer: exact match. Ambiguous number: maybe old Heimdal.
    // MIT: `k5_privsafe_check_seqnum` (lib/krb5/krb/privsafe.c:225-304)
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

    pub const fn advance(&mut self) {
        self.expected = self.expected.wrapping_add(1);
    }
}

// MIT: `chk_heimdal_seqnum` (lib/krb5/krb/privsafe.c:206-223)
/// Old Heimdal sign-extends 1-3 octet sequence numbers.
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

// MIT: `krb5_decrypt_tkt_part` (lib/krb5/krb/decrypt_tk.c:46-50)
/// Before decryption: unknown ProgEtypeNosupp; not permitted NopermEtype.
pub fn check_ticket_etype(ticket_etype: i32, permitted: &[EncryptionType]) -> Result<(), Error> {
    let etype = EncryptionType::known(ticket_etype).map_err(|_| Error::ProgEtypeNosupp)?;
    if permitted.contains(&etype) {
        Ok(())
    } else {
        Err(Error::NopermEtype(NOPERM_ETYPE.into()))
    }
}

// MIT: `rd_req_decoded_opt` (lib/krb5/krb/rd_req_dec.c:652-723)
/// Enctypes past the RFC 4537 list must be permitted.
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
    pub fn from_ap_req(ok: &ApVerifyOk, conf: &AcceptorConfig) -> Result<Self, Error> {
        let permitted = conf.permitted()?;
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
            host_addrs: None,
            cstate: None,
            memrcache: None,
            clockskew: i64::from(conf.clockskew),
        })
    }

    pub fn set_addrs(&mut self, local: Option<HostAddress>, remote: Option<HostAddress>) {
        self.local_addr = local;
        self.remote_addr = remote;
    }

    /// None: machine's own addresses, not none.
    pub fn set_host_addrs(&mut self, hosts: Option<Vec<HostAddress>>) {
        self.host_addrs = hosts;
    }

    // MIT: `krb5_auth_con_initivector` (lib/krb5/krb/auth_con.c:314-322)
    pub fn init_ivector(&mut self) {
        self.cstate = Some(CipherState::initial());
    }

    #[must_use]
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    pub const fn set_flags(&mut self, flags: u32) {
        self.flags = flags;
    }

    #[must_use]
    pub const fn key(&self) -> &ProtocolKey {
        &self.key
    }

    #[must_use]
    pub const fn send_subkey(&self) -> Option<&ProtocolKey> {
        self.send_subkey.as_ref()
    }

    #[must_use]
    pub const fn recv_subkey(&self) -> Option<&ProtocolKey> {
        self.recv_subkey.as_ref()
    }

    #[must_use]
    pub const fn local_seq(&self) -> u32 {
        self.local_seq
    }

    #[must_use]
    pub const fn remote_seq(&self) -> u32 {
        self.remote.expected()
    }

    #[must_use]
    pub const fn negotiated_etype(&self) -> EncryptionType {
        self.negotiated_etype
    }

    #[must_use]
    pub const fn ap_req_use_subkey(&self) -> bool {
        self.ap_req_use_subkey
    }

    // MIT: `k5_mk_rep` (lib/krb5/krb/mk_rep.c:67-140)
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
        // Subkey and all: zeroed before free, encrypted or not.
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

    // MIT: `krb5_mk_priv` (lib/krb5/krb/mk_priv.c:105-155)
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
        wipe_octets(part.user_data);
        let der = der?;
        let cstate = self.cstate.as_mut();
        let cipher = KeyUsage::new(ku::KRB_PRIV_ENC_PART)
            .map_err(Error::from)
            .and_then(|usage| match cstate {
                Some(state) => Ok(encrypt_with_state(key, usage, state, &der)?),
                None => Ok(encrypt(key, usage, &der)?),
            });
        // MIT: `create_krbpriv` (lib/krb5/krb/mk_priv.c:97-100)
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

    // MIT: `krb5_rd_priv` (lib/krb5/krb/rd_priv.c:99-150)
    // MIT: `read_krbpriv` (lib/krb5/krb/rd_priv.c:43-97)
    pub fn rd_priv(&mut self, raw: &[u8]) -> Result<Vec<u8>, Error> {
        if raw.first().is_none_or(|b| b & !0x20 != 0x55) {
            return Err(krb_error(err::MSG_TYPE, "Invalid message type"));
        }
        let msg: KrbPriv = decode(raw)?;
        let key = self.recv_subkey.as_ref().unwrap_or(&self.key);
        let etype = key.etype();
        let usage = KeyUsage::new(ku::KRB_PRIV_ENC_PART)?;
        let cipher = msg.enc_part.cipher.as_ref();
        let enc_etype = msg.enc_part.etype;
        let plain = match self.cstate.as_mut() {
            Some(state) => decrypt_enc_data_with_state(key, usage, state, enc_etype, cipher)?,
            None => decrypt_enc_data(key, usage, enc_etype, cipher)?,
        };
        let part = decode::<EncKrbPrivPart>(&plain);
        wipe_vec(plain);
        let part = part?;
        let checked = check_privsafe_addrs_in(
            &part.s_address,
            part.r_address.as_ref(),
            self.remote_addr.as_ref(),
            self.local_addr.as_ref(),
            self.host_addrs.as_deref(),
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

    // MIT: `krb5_rd_safe` (lib/krb5/krb/rd_safe.c:127-178)
    pub fn rd_safe(&mut self, raw: &[u8]) -> Result<Vec<u8>, Error> {
        let key = self.recv_subkey.as_ref().unwrap_or(&self.key);
        let msg = verify_krb_safe_checksum_in(
            key,
            raw,
            self.remote_addr.as_ref(),
            self.local_addr.as_ref(),
            self.host_addrs.as_deref(),
        )?;
        self.check_replay(
            msg.safe_body.timestamp.as_ref(),
            msg.cksum.checksum.as_ref(),
        )?;
        self.check_seq(msg.safe_body.seq_number)?;
        Ok(msg.safe_body.user_data.to_vec())
    }

    // MIT: `k5_privsafe_check_replay` (lib/krb5/krb/privsafe.c:107-141)
    // MIT: `krb5_check_clockskew` (lib/krb5/os/timeofday.c:55-67)
    fn check_replay(&mut self, timestamp: Option<&KerberosTime>, tag: &[u8]) -> Result<(), Error> {
        if self.flags & AUTH_CONTEXT_DO_TIME == 0 {
            return Ok(());
        }
        let skew = self.clockskew;
        let now = i64::from(KerberosTime::now().unix_seconds());
        let then = timestamp.map_or(0, |t| i64::from(t.unix_seconds()));
        if (now - then).abs() > skew {
            return Err(krb_error(err::SKEW, "Clock skew too great"));
        }
        if self
            .memrcache
            .get_or_insert_with(ReplayCache::new)
            .check_and_store(ReplayKey::tag(tag), skew)
        {
            return Err(krb_error(err::REPEAT, "Request is a replay"));
        }
        Ok(())
    }

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

// MIT: `k5_rc_tag_from_ciphertext` (lib/krb5/rcache/rc_base.c:146-164)
/// Short ciphertext: Crypto, not MIT's EINVAL.
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

// MIT: `krb5_us_timeofday` (lib/krb5/os/ustime.c:66-82)
/// One reading: both; KerberosTime keeps seconds only.
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

// MIT: `krb5_timeofday` (lib/krb5/os/timeofday.c:45-45)
/// MIT's time(): Linux second is CLOCK_REALTIME_COARSE.
#[must_use]
pub(crate) fn kdc_time_seconds() -> u32 {
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "emscripten",
        target_os = "fuchsia"
    ))]
    if let Ok(ts) = nix::time::clock_gettime(nix::time::ClockId::CLOCK_REALTIME_COARSE) {
        return u32::try_from(ts.tv_sec()).unwrap_or(u32::MAX);
    }
    us_timeofday().0.unix_seconds()
}

#[must_use]
pub(crate) fn lifetime_second(precise_s: u32, kdc_s: u32) -> u32 {
    if precise_s == kdc_s.saturating_add(1) {
        kdc_s
    } else {
        precise_s
    }
}

#[must_use]
pub(crate) fn request_lifetime_now(precise: KerberosTime) -> KerberosTime {
    let precise_s = precise.unix_seconds();
    let snapped = lifetime_second(precise_s, kdc_time_seconds());
    if snapped == precise_s {
        precise
    } else {
        KerberosTime::from_unix_seconds(snapped)
    }
}

// MIT: `krb5_generate_seq_number` (lib/krb5/krb/gen_seqnum.c:39-63)
/// 30 random bits: never negative as signed, never 0.
pub fn generate_seq_number() -> Result<u32, Error> {
    let n = seq_random()? & 0x3fff_ffff;
    Ok(if n == 0 { 1 } else { n })
}

#[cfg(any(test, feature = "test-hooks"))]
thread_local! {
    static TEST_SEQ_RANDOM: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

#[cfg(feature = "test-hooks")]
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

// MIT: `k5_sockaddr_to_address` (lib/krb5/os/addr.c:43-75)
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

// MIT: `decode_etype_list` (lib/krb5/krb/rd_req_dec.c:906-976)
/// Undecodable container skipped; bad list fails the request.
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

// MIT: `negotiate_etype` (lib/krb5/krb/rd_req_dec.c:854-904)
/// Every enctype from the mandatory index on must be permitted.
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

// MIT: `KRB5_NOPERM_ETYPE` (krb5_err.et:325-325)
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
