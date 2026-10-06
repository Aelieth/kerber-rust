//! The SPAKE kdcpreauth module.
//!
//! The KDC answers a support message with a challenge in the first of the client's groups it
//! permits, or sends an optimistic challenge with PREAUTH_REQUIRED when
//! `spake_preauth_kdc_challenge` names a group. It keeps the private scalar and the transcript hash
//! in its secure cookie, checks the response's encrypted SF-NONE factor with `K'[1]`, and makes the
//! reply key `K'[0]`.

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    KeyUsage, ProtocolKey, SpakeGroup, decrypt, spake_derive_key, spake_keygen, spake_result,
    spake_thash_update, spake_wbytes,
};
use krb5_types::spake::{
    PaSpake, SF_NONE, SpakeChallenge, SpakeResponse, SpakeSecondFactor, SpakeSupport,
};
use krb5_types::{MethodData, PaData, err, ku, pa};
use zeroize::Zeroizing;

use super::{find_pa, make_cookie, open_cookie, proto};
use crate::error::Error;
use crate::kdb::PrincipalRead;
use crate::plugins::PreauthHint;
use crate::status;
use crate::store::{Principal, SpakeKdc};

/// SPAKE: support → challenge; response → shared key.
pub(crate) enum SpakeStep {
    /// Need a challenge (PREAUTH_REQUIRED).
    Challenge(Vec<u8>),
    /// Finished; key encrypts AS-REP.
    Done(ProtocolKey),
}

/// The SPAKE cookie version, MIT's only one.
const COOKIE_VERSION: u16 = 1;

/// MIT `ENCTYPE_UNKNOWN` (`krb5.hin:449-449`): an `EncryptedData` of this enctype skips the enctype check.
const ENCTYPE_UNKNOWN: i32 = 0x01ff;

fn failed() -> Error {
    proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED)
}

fn pa_spake(value: Vec<u8>) -> PaData {
    PaData {
        padata_type: pa::SPAKE,
        padata_value: value.into(),
    }
}

/// The module's cookie: version 1, the stage, the group, then the SPAKE value and the transcript
/// hash.
///
/// MIT `make_cookie` (`spake_kdc.c:127-153`): the integers are big-endian, and each data field is a 32-bit length and its octets; a stage-0 cookie's SPAKE value is the private scalar.
fn make_spake_cookie(
    stage: u16,
    group: SpakeGroup,
    spake: &[u8],
    thash: &[u8],
) -> Zeroizing<Vec<u8>> {
    let mut buf = Zeroizing::new(Vec::with_capacity(16 + spake.len() + thash.len()));
    buf.extend_from_slice(&COOKIE_VERSION.to_be_bytes());
    buf.extend_from_slice(&stage.to_be_bytes());
    buf.extend_from_slice(&group.number().to_be_bytes());
    for data in [spake, thash] {
        let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(data);
    }
    buf
}

/// A parsed SPAKE cookie; the slices alias the cookie.
struct SpakeCookie<'a> {
    stage: u16,
    group: i32,
    spake: &'a [u8],
    thash: &'a [u8],
}

/// Big-endian reads that fail past the end, like MIT's `k5input`.
struct Input<'a>(&'a [u8]);

impl<'a> Input<'a> {
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }

    fn u16(&mut self) -> Option<u16> {
        self.bytes(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        self.bytes(4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// MIT `parse_data` (`spake_kdc.c:71-79`): a 32-bit big-endian length and that many octets.
    fn data(&mut self) -> Option<&'a [u8]> {
        let len = usize::try_from(self.u32()?).ok()?;
        self.bytes(len)
    }
}

/// MIT `parse_cookie` (`spake_kdc.c:81-117`): a version other than 1 is PREAUTH_FAILED, a short field an error, and what follows the transcript hash is factor data.
fn parse_spake_cookie(cookie: &[u8]) -> Result<SpakeCookie<'_>, Error> {
    let mut input = Input(cookie);
    if input.u16() != Some(COOKIE_VERSION) {
        return Err(failed());
    }
    let parsed = (|| {
        let stage = input.u16()?;
        let group = i32::from_be_bytes(input.u32()?.to_be_bytes());
        let spake = input.data()?;
        let thash = input.data()?;
        Some(SpakeCookie {
            stage,
            group,
            spake,
            thash,
        })
    })();
    parsed.ok_or_else(failed)
}

/// A challenge in `group` and the stage-0 cookie that keeps the private scalar.
///
/// MIT `send_challenge` (`spake_kdc.c:207-294`): the challenge offers only SF-NONE, and the transcript hash starts with the support message (none for an optimistic challenge) and the challenge.
///
/// # Errors
///
/// [`Error::Crypto`] when the key generation fails; [`Error::Asn1`] when the challenge does not
/// encode.
fn send_challenge(
    ikey: &ProtocolKey,
    group: SpakeGroup,
    support: &[u8],
) -> Result<(PaData, PaData), Error> {
    let wbytes = spake_wbytes(ikey, group)?;
    let (kdcpriv, kdcpub) = spake_keygen(group, &wbytes, true)?;
    let challenge = encode(&PaSpake::Challenge(SpakeChallenge {
        group: group.number(),
        pubkey: kdcpub.into(),
        factors: vec![SpakeSecondFactor {
            factor_type: SF_NONE,
            data: None,
        }],
    }))?;
    let thash = spake_thash_update(group, &[], support, &challenge);
    let cookie = make_spake_cookie(0, group, &kdcpriv, &thash);
    Ok((pa_spake(challenge), pa_spake(cookie.to_vec())))
}

/// The module's PREAUTH_REQUIRED hint, and the cookie state of an optimistic challenge.
///
/// MIT `spake_edata` (`spake_kdc.c:296-324`): no client key is no hint, a configured challenge group sends a challenge, and otherwise the hint is an empty PA-SPAKE.
pub(crate) fn spake_edata(store: &dyn PrincipalRead, ikey: Option<&ProtocolKey>) -> PreauthHint {
    // MIT `load_preauth_plugins` (`kdc_preauth.c:207-219`): a module whose init failed is left out.
    let Ok(conf) = store.policy().spake_kdc() else {
        return PreauthHint::default();
    };
    let Some(ikey) = ikey else {
        return PreauthHint::default();
    };
    let Some(group) = conf.challenge else {
        return PreauthHint {
            padata: vec![pa_spake(Vec::new())],
            cookie: Vec::new(),
        };
    };
    match send_challenge(ikey, group, &[]) {
        Ok((challenge, cookie)) => PreauthHint {
            padata: vec![challenge],
            cookie: vec![cookie],
        },
        Err(_) => PreauthHint::default(),
    }
}

/// A challenge in the first of the client's groups the KDC permits.
///
/// MIT `verify_support` (`spake_kdc.c:326-355`): the client's order decides, and a support message sharing no group is PREAUTH_FAILED.
fn verify_support(
    store: &dyn PrincipalRead,
    client: &Principal,
    conf: SpakeKdc<'_>,
    support: &SpakeSupport,
    der_msg: &[u8],
    ikey: &ProtocolKey,
) -> Result<SpakeStep, Error> {
    let group = support
        .groups
        .iter()
        .filter_map(|&n| SpakeGroup::from_number(n))
        .find(|g| conf.groups.contains(g))
        .ok_or_else(failed)?;
    let (challenge, cookie) = send_challenge(ikey, group, der_msg)?;
    // MIT `send_challenge` (`spake_kdc.c:288-292`): MORE_PREAUTH_DATA_REQUIRED carries the challenge, and the cookie follows it.
    let method: MethodData = vec![
        challenge,
        PaData {
            padata_type: pa::FX_COOKIE,
            padata_value: make_cookie(store, &client.name, &[cookie])?.into(),
        },
    ];
    Ok(SpakeStep::Challenge(encode(&method)?))
}

/// The reply key `K'[0]` once the response's factor decrypts under `K'[1]` and is SF-NONE.
///
/// MIT `verify_response` (`spake_kdc.c:357-475`): the stage-0 cookie gives the group, the private scalar and the transcript hash; a missing cookie, another stage, a bad factor or another factor type is PREAUTH_FAILED.
fn verify_response(
    store: &dyn PrincipalRead,
    client: &Principal,
    padata: Option<&[PaData]>,
    resp: &SpakeResponse,
    ikey: &ProtocolKey,
    body_der: &[u8],
) -> Result<SpakeStep, Error> {
    let blob = find_pa(padata, pa::FX_COOKIE).ok_or_else(failed)?;
    let inner = open_cookie(store, &client.name, blob);
    let cookie = inner
        .iter()
        .find(|p| p.padata_type == pa::SPAKE)
        .map(|p| p.padata_value.as_ref())
        .ok_or_else(failed)?;
    let cookie = parse_spake_cookie(cookie)?;
    if cookie.stage != 0 {
        return Err(failed());
    }
    // MIT `derive_wbytes` (`util.c:114-117`): a group the KDC does not implement is EINVAL.
    let group = SpakeGroup::from_number(cookie.group).ok_or_else(failed)?;
    let pubkey = resp.pubkey.as_ref();
    let thash = spake_thash_update(group, cookie.thash, pubkey, &[]);
    let wbytes = spake_wbytes(ikey, group)?;
    let result = spake_result(group, &wbytes, cookie.spake, pubkey, true)?;
    let k1 = spake_derive_key(ikey, group, &wbytes, &result, &thash, body_der, 1)?;
    // MIT `krb5_k_decrypt` (`decrypt.c:45-46`): a factor of another enctype is KRB5_BAD_ENCTYPE.
    if resp.factor.etype != ENCTYPE_UNKNOWN && resp.factor.etype != k1.etype().to_iana() {
        return Err(failed());
    }
    let usage = KeyUsage::new(ku::SPAKE)?;
    let factor_der =
        Zeroizing::new(decrypt(&k1, usage, resp.factor.cipher.as_ref()).map_err(|_| failed())?);
    let factor = decode::<SpakeSecondFactor>(&factor_der).map_err(|_| failed())?;
    if factor.factor_type != SF_NONE {
        return Err(failed());
    }
    let k0 = spake_derive_key(ikey, group, &wbytes, &result, &thash, body_der, 0)?;
    Ok(SpakeStep::Done(k0))
}

/// The module's answer to a PA-SPAKE in an AS-REQ: a challenge for a support message, the reply
/// key for a response. `None` when the request has no PA-SPAKE or the module did not load.
///
/// MIT `spake_verify` (`spake_kdc.c:501-539`): a message that does not decode fails, and an encdata or any other message type is PREAUTH_FAILED.
/// MIT `next_padata` (`kdc_preauth.c:1306-1307`): a module that did not load is no pa_system, so its padata is skipped.
///
/// # Errors
///
/// [`Error::Protocol`] `PREAUTH_FAILED` for a support message sharing no permitted group, a
/// response without a readable stage-0 cookie or with a bad factor, an encdata or challenge
/// message, or a cookie in a group not implemented; [`Error::Asn1`] when the PA-SPAKE does not
/// decode or the challenge does not encode; [`Error::Crypto`] when a SPAKE derivation, the
/// client's element or the cookie encryption fails.
pub(crate) fn process_spake(
    store: &dyn PrincipalRead,
    client: &Principal,
    padata: Option<&[PaData]>,
    ikey: &ProtocolKey,
    body_der: &[u8],
) -> Result<Option<SpakeStep>, Error> {
    let Some(raw) = find_pa(padata, pa::SPAKE) else {
        return Ok(None);
    };
    let Ok(conf) = store.policy().spake_kdc() else {
        return Ok(None);
    };
    match decode::<PaSpake>(raw)? {
        PaSpake::Support(support) => {
            verify_support(store, client, conf, &support, raw, ikey).map(Some)
        }
        PaSpake::Response(resp) => {
            verify_response(store, client, padata, &resp, ikey, body_der).map(Some)
        }
        // MIT `verify_encdata` (`spake_kdc.c:477-499`): second factors are not implemented, so encdata is PREAUTH_FAILED.
        // MIT `spake_verify` (`spake_kdc.c:532-536`): a challenge from a client is an unknown request type.
        PaSpake::EncData(_) | PaSpake::Challenge(_) => Err(failed()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cookie_round_trips_in_mit_layout() {
        let cookie = make_spake_cookie(0, SpakeGroup::Edwards25519, &[7; 32], &[9; 32]);
        assert_eq!(&cookie[..12], [0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 32]);
        assert_eq!(cookie.len(), 2 + 2 + 4 + 4 + 32 + 4 + 32);
        let parsed = parse_spake_cookie(&cookie).unwrap();
        assert_eq!(parsed.stage, 0);
        assert_eq!(parsed.group, 1);
        assert_eq!(parsed.spake, [7; 32]);
        assert_eq!(parsed.thash, [9; 32]);
    }

    #[test]
    fn a_cookie_of_another_version_or_cut_short_is_preauth_failed() {
        let cookie = make_spake_cookie(0, SpakeGroup::P256, &[7; 32], &[9; 32]);
        let mut other = cookie.to_vec();
        other[1] = 2;
        for bad in [&other[..], &cookie[..cookie.len() - 1], &cookie[..1], &[]] {
            assert!(matches!(
                parse_spake_cookie(bad),
                Err(Error::Protocol { code, .. }) if code == err::PREAUTH_FAILED
            ));
        }
        // MIT keeps what follows the transcript hash as factor data.
        let mut longer = cookie.to_vec();
        longer.extend_from_slice(&[0, 0, 0, 1]);
        assert!(parse_spake_cookie(&longer).is_ok());
    }
}
