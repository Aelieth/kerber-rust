//! SPAKE preauth on the KDC.

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    KeyUsage, ProtocolKey, SpakeGroup, decrypt_enc_data, spake_derive_key, spake_keygen,
    spake_result, spake_thash_update, spake_wbytes,
};
use krb5_types::spake::{
    PaSpake, SF_NONE, SpakeChallenge, SpakeResponse, SpakeSecondFactor, SpakeSupport,
};
use krb5_types::{MethodData, PaData, err, ku, pa};
use zeroize::Zeroizing;

use super::otp::{E_BAD_ENCTYPE, E_BAD_MSIZE, E_EINVAL};
use super::{find_pa, make_cookie, open_cookie, proto};
use crate::asn1_text::{decode_failure_text, pa_spake_failure_text};
use crate::error::Error;
use crate::kdb::PrincipalRead;
use crate::plugins::PreauthHint;
use crate::status;
use crate::store::{Principal, SpakeKdc};

pub(crate) enum SpakeStep {
    Challenge(Vec<u8>),
    Done(ProtocolKey),
}

const COOKIE_VERSION: u16 = 1;

// MIT: `ENCTYPE_UNKNOWN` (krb5.hin:449-449)
const ENCTYPE_UNKNOWN: i32 = 0x01ff;

fn failed() -> Error {
    proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED)
}

const EINVAL: i32 = 22;
// MIT: `KRB5_BAD_ENCTYPE` (krb5_err.et)
const KRB5_BAD_ENCTYPE: i32 = -1_765_328_196;
// MIT: `KRB5_BAD_MSIZE` (krb5_err.et)
const KRB5_BAD_MSIZE: i32 = -1_765_328_194;

fn library_failure(message: &str) -> Error {
    let code = if message == E_EINVAL {
        EINVAL
    } else if message == E_BAD_ENCTYPE {
        KRB5_BAD_ENCTYPE
    } else if message == E_BAD_MSIZE {
        KRB5_BAD_MSIZE
    } else {
        crate::asn1_text::asn1_code(message)
    };
    Error::PreauthModule {
        code,
        message: message.to_owned(),
    }
}

fn pa_spake(value: Vec<u8>) -> PaData {
    PaData {
        padata_type: pa::SPAKE,
        padata_value: value.into(),
    }
}

// MIT: `make_cookie` (spake_kdc.c:127-153)
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

struct SpakeCookie<'a> {
    stage: u16,
    group: i32,
    spake: &'a [u8],
    thash: &'a [u8],
}

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

    // MIT: `parse_data` (spake_kdc.c:71-79)
    fn data(&mut self) -> Option<&'a [u8]> {
        let len = usize::try_from(self.u32()?).ok()?;
        self.bytes(len)
    }
}

// MIT: `parse_cookie` (spake_kdc.c:81-117)
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

// MIT: `send_challenge` (spake_kdc.c:207-294)
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

// MIT: `spake_edata` (spake_kdc.c:296-324)
/// No key is no hint; no configured group is an empty PA-SPAKE.
pub(crate) fn spake_edata(store: &dyn PrincipalRead, ikey: Option<&ProtocolKey>) -> PreauthHint {
    // MIT: `load_preauth_plugins` (kdc_preauth.c:207-219)
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

// MIT: `verify_support` (spake_kdc.c:326-355)
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
    // MIT: `send_challenge` (spake_kdc.c:288-292)
    let method: MethodData = vec![
        challenge,
        PaData {
            padata_type: pa::FX_COOKIE,
            padata_value: make_cookie(store, &client.name, &[cookie])?.into(),
        },
    ];
    Ok(SpakeStep::Challenge(encode(&method)?))
}

// MIT: `verify_response` (spake_kdc.c:357-475)
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
    // MIT: `derive_wbytes` (util.c:114-117)
    let group = SpakeGroup::from_number(cookie.group).ok_or_else(|| library_failure(E_EINVAL))?;
    let pubkey = resp.pubkey.as_ref();
    let thash = spake_thash_update(group, cookie.thash, pubkey, &[]);
    let wbytes = spake_wbytes(ikey, group)?;
    let result = spake_result(group, &wbytes, cookie.spake, pubkey, true)?;
    let k1 = spake_derive_key(ikey, group, &wbytes, &result, &thash, body_der, 1)?;
    // MIT: `krb5_k_decrypt` (decrypt.c:45-46)
    // Unknown factor enctype skips the check; a mismatch fails.
    if resp.factor.etype != ENCTYPE_UNKNOWN && resp.factor.etype != k1.etype().to_iana() {
        return Err(library_failure(E_BAD_ENCTYPE));
    }
    let usage = KeyUsage::new(ku::SPAKE)?;
    let factor_der = Zeroizing::new(
        decrypt_enc_data(&k1, usage, resp.factor.etype, resp.factor.cipher.as_ref()).map_err(
            |e| match e {
                krb5_crypto::Error::CiphertextTooShort => library_failure(E_BAD_MSIZE),
                // MIT: `verify_response` (spake_kdc.c:431-432)
                _ => failed(),
            },
        )?,
    );
    // MIT: `verify_response` (spake_kdc.c:435-437)
    let factor = decode::<SpakeSecondFactor>(&factor_der)
        .map_err(|_| library_failure(decode_failure_text(&factor_der, true)))?;
    if factor.factor_type != SF_NONE {
        return Err(failed());
    }
    let k0 = spake_derive_key(ikey, group, &wbytes, &result, &thash, body_der, 0)?;
    Ok(SpakeStep::Done(k0))
}

// MIT: `spake_verify` (spake_kdc.c:501-539)
// MIT: `next_padata` (kdc_preauth.c:1306-1307)
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
    // MIT: `spake_verify` (spake_kdc.c:519-521)
    let msg = decode::<PaSpake>(raw).map_err(|_| library_failure(pa_spake_failure_text(raw)))?;
    match msg {
        PaSpake::Support(support) => {
            verify_support(store, client, conf, &support, raw, ikey).map(Some)
        }
        PaSpake::Response(resp) => {
            verify_response(store, client, padata, &resp, ikey, body_der).map(Some)
        }
        // MIT: `verify_encdata` (spake_kdc.c:477-499)
        // MIT: `spake_verify` (spake_kdc.c:532-536)
        // A second factor, or encdata, is PREAUTH_FAILED.
        PaSpake::EncData(_) => Err(failed()),
        // MIT: `spake_verify` (spake_kdc.c:532-535)
        PaSpake::Challenge(_) | PaSpake::Unknown => Err(Error::PreauthModule {
            code: krb5_types::err::PREAUTH_FAILED,
            message: "Unknown SPAKE request type".to_owned(),
        }),
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
