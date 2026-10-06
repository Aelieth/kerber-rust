//! The acceptor's auth context (`krb/auth_con.c`, `rd_req_dec.c`, `mk_rep.c`, `mk_priv.c`,
//! `gen_seqnum.c`, `gen_save_subkey.c`): what an accepted AP-REQ leaves for the AP-REP and the
//! KRB-PRIV that answer it.
//!
//! The context starts as `krb5_auth_con_init` leaves one (`DO_TIME`); the caller sets the flags
//! its MIT program sets. `krb5_mk_rep` takes a fresh subkey only under `USE_SUBKEY` and otherwise
//! echoes the authenticator's own, and its sequence number is random only when the context has
//! none yet.

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, encrypt, parse_enctype_list};
use krb5_types::{
    ApRep, Authenticator, AuthorizationData, EncApRepPart, EncKrbPrivPart, EncryptedData,
    EncryptionKey, HostAddress, KerberosTime, KrbPriv, Microseconds, OctetString, ku, pa,
};

use crate::ap_req::ApVerifyOk;
use crate::error::Error;
use crate::safe_priv::{wipe_octets, wipe_vec};

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

/// The acceptor's side of an authenticated exchange after the AP-REQ verified.
pub struct AcceptorAuthContext {
    flags: u32,
    key: ProtocolKey,
    authenticator: Authenticator,
    send_subkey: Option<ProtocolKey>,
    recv_subkey: Option<ProtocolKey>,
    local_seq: u32,
    remote_seq: u32,
    negotiated_etype: EncryptionType,
    ap_req_use_subkey: bool,
}

impl AcceptorAuthContext {
    /// The auth context an accepted AP-REQ leaves, checked against the `permitted` enctypes.
    /// MIT `rd_req_decoded_opt` (`lib/krb5/krb/rd_req_dec.c:652-773`): the RFC 4537 list, then the subkey's and the session key's enctypes, are negotiated, the peer's sequence number and subkey are kept, and without mutual authentication the local sequence number starts from the peer's.
    ///
    /// # Errors
    ///
    /// [`Error::NopermEtype`] when `permitted` lacks the session key's or the subkey's enctype;
    /// [`Error::Asn1`] when the authenticator's AD-ETYPE-NEGOTIATION list does not decode;
    /// [`Error::Crypto`] when the session key or the subkey is not a usable key.
    pub fn from_ap_req(ok: &ApVerifyOk, permitted: &[EncryptionType]) -> Result<Self, Error> {
        let key = protocol_key(&ok.ticket_part.key)?;
        let authenticator = ok.authenticator.clone();
        let mut desired = decode_etype_list(&authenticator)?.unwrap_or_default();
        let rfc4537_len = desired.len();
        if let Some(sk) = &authenticator.subkey {
            desired.push(sk.keytype);
        }
        desired.push(ok.ticket_part.key.keytype);
        let negotiated_etype = negotiate_etype(&desired, rfc4537_len, permitted)?;
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
            remote_seq,
            negotiated_etype,
            ap_req_use_subkey,
        })
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

    /// The peer's sequence number from the authenticator.
    #[must_use]
    pub const fn remote_seq(&self) -> u32 {
        self.remote_seq
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
        let cipher = KeyUsage::new(ku::KRB_PRIV_ENC_PART)
            .map_err(Error::from)
            .and_then(|usage| Ok(encrypt(key, usage, &der)?));
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
}

impl std::fmt::Debug for AcceptorAuthContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcceptorAuthContext")
            .field("flags", &self.flags)
            .field("negotiated_etype", &self.negotiated_etype)
            .field("local_seq", &self.local_seq)
            .field("remote_seq", &self.remote_seq)
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
