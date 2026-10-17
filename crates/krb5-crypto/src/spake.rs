//! MIT 1.22.2 SPAKE preauth (draft-ietf-kitten-krb-spake-preauth): the registered groups, the
//! group interface and its configuration words, the edwards25519 group, the P-256 group, and the
//! derivations the KDC and the client share.
//!
//! An element or scalar of the wrong length, or an element that does not decode, is
//! `Error::Integrity` (MIT's `EINVAL`). MIT built with OpenSSL also has P-384 and P-521; this port
//! has edwards25519 and P-256, so those two names are unknown words here.

mod edwards25519;
mod p256;

use sha2::{Digest as Sha2Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::key::ProtocolKey;
use crate::krb_fx_cf2;
use crate::prf::prf_plus;
use crate::wipe::wipe;

/// A SPAKE group: its number, name, lengths and constants are MIT's registry entry.
///
/// MIT `spake_iana_edwards25519` (`iana.c:93-96`): number 1, `edwards25519`, 32-octet scalars and elements, SHA-256.
/// MIT `spake_iana_p256` (`iana.c:98-100`): number 2, `P-256`, 32-octet scalars, 33-octet elements, SHA-256.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SpakeGroup {
    /// edwards25519 (group 1): MIT's built-in group and its client default.
    Edwards25519,
    /// P-256 (group 2).
    P256,
}

/// MIT `DEFAULT_GROUPS_CLIENT` (`groups.c:59-59`): a client without `spake_preauth_groups` permits edwards25519.
pub const SPAKE_DEFAULT_GROUPS_CLIENT: &str = "edwards25519";

/// MIT `DEFAULT_GROUPS_KDC` (`groups.c:60-60`): a KDC without `spake_preauth_groups` permits none, so it offers no SPAKE.
pub const SPAKE_DEFAULT_GROUPS_KDC: &str = "";

impl SpakeGroup {
    /// MIT `groupdefs` (`groups.c:89-97`): edwards25519 first, then the OpenSSL groups.
    pub const ALL: [Self; 2] = [Self::Edwards25519, Self::P256];

    /// MIT `find_gdef` (`groups.c:99-111`): the group a number names, or none.
    #[must_use]
    pub fn from_number(group: i32) -> Option<Self> {
        Self::ALL.into_iter().find(|g| g.number() == group)
    }

    /// MIT `find_gnum` (`groups.c:113-124`): the group a name names, compared without case.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|g| g.name().eq_ignore_ascii_case(name))
    }

    /// The IANA group number.
    #[must_use]
    pub const fn number(self) -> i32 {
        match self {
            Self::Edwards25519 => 1,
            Self::P256 => 2,
        }
    }

    /// The name `spake_preauth_groups` and `spake_preauth_kdc_challenge` use.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Edwards25519 => "edwards25519",
            Self::P256 => "P-256",
        }
    }

    /// Octets in a scalar (`w`, `x`, `y`).
    #[must_use]
    pub const fn mult_len(self) -> usize {
        32
    }

    /// Octets in a group element (`T`, `S`, `K`).
    #[must_use]
    pub const fn elem_len(self) -> usize {
        match self {
            Self::Edwards25519 => 32,
            Self::P256 => 33,
        }
    }

    /// Octets in the group's hash output.
    #[must_use]
    pub const fn hash_len(self) -> usize {
        32
    }

    /// The registry's M, the KDC's constant.
    #[must_use]
    pub const fn m(self) -> &'static [u8] {
        match self {
            Self::Edwards25519 => &edwards25519::M,
            Self::P256 => &p256::M,
        }
    }

    /// The registry's N, the client's constant.
    #[must_use]
    pub const fn n(self) -> &'static [u8] {
        match self {
            Self::Edwards25519 => &edwards25519::N,
            Self::P256 => &p256::N,
        }
    }
}

/// The groups a `spake_preauth_groups` value permits, in its order.
///
/// MIT `parse_groups` (`groups.c:176-211`): words split at space, tab, CR, LF or comma; an unknown word is skipped and a repeat kept once.
#[must_use]
pub fn spake_parse_groups(value: &str) -> Vec<SpakeGroup> {
    let mut out = Vec::new();
    for word in value
        .split([' ', '\t', '\r', '\n', ','])
        .filter(|w| !w.is_empty())
    {
        let Some(group) = SpakeGroup::from_name(word) else {
            tracing::debug!(name = word, "Unrecognized SPAKE group name");
            continue;
        };
        if !out.contains(&group) {
            out.push(group);
        }
    }
    out
}

/// The multiplier octets `w` the initial key gives for `group`.
///
/// MIT `derive_wbytes` (`util.c:101-141`): PRF+ of the initial key over "SPAKEsecret" and the big-endian group number, `mult_len` octets.
///
/// # Errors
///
/// The refusals of [`crate::prf`] for a des3-cbc-sha1 `ikey` MIT refuses; otherwise none: the PRF+ length
/// is the group's 32 octets.
pub fn spake_wbytes(ikey: &ProtocolKey, group: SpakeGroup) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut input = b"SPAKEsecret".to_vec();
    input.extend_from_slice(&group.number().to_be_bytes());
    Ok(Zeroizing::new(prf_plus(ikey, &input, group.mult_len())?))
}

/// A random private scalar and its public element: `T = x·G + w·M` on the KDC, `S = y·G + w·N` on
/// the client.
///
/// MIT `group_keygen` (`groups.c:332-371`): the KDC uses M and the client N, and `w` is the group's `mult_len` octets.
///
/// # Errors
///
/// [`Error::Rng`] when the CSPRNG fails; [`Error::Integrity`] when `wbytes` is not the group's
/// `mult_len` octets.
pub fn spake_keygen(
    group: SpakeGroup,
    wbytes: &[u8],
    kdc: bool,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), Error> {
    if wbytes.len() != group.mult_len() {
        return Err(Error::Integrity);
    }
    match group {
        SpakeGroup::Edwards25519 => edwards25519::keygen(wbytes, kdc),
        SpakeGroup::P256 => p256::keygen(wbytes, kdc),
    }
}

/// The public element [`spake_keygen`] makes from a given private scalar (MIT's vectors give `x`
/// and `y`).
///
/// # Errors
///
/// [`Error::Integrity`] when `wbytes` or `private` is not the group's `mult_len` octets, or (P-256)
/// the element is the point at infinity.
pub fn spake_public(
    group: SpakeGroup,
    wbytes: &[u8],
    private: &[u8],
    kdc: bool,
) -> Result<Vec<u8>, Error> {
    if wbytes.len() != group.mult_len() || private.len() != group.mult_len() {
        return Err(Error::Integrity);
    }
    match group {
        SpakeGroup::Edwards25519 => edwards25519::public(wbytes, private, kdc),
        SpakeGroup::P256 => p256::public(wbytes, private, kdc),
    }
}

/// The SPAKE result `K = x·(S − w·N)` on the KDC, `K = y·(T − w·M)` on the client.
///
/// MIT `group_result` (`groups.c:373-412`): lengths are checked first, and each side removes the other party's constant.
///
/// # Errors
///
/// [`Error::Integrity`] when a length is not the group's, `theirpub` does not decode, or (P-256)
/// `K` is the point at infinity.
pub fn spake_result(
    group: SpakeGroup,
    wbytes: &[u8],
    ourpriv: &[u8],
    theirpub: &[u8],
    kdc: bool,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if wbytes.len() != group.mult_len()
        || ourpriv.len() != group.mult_len()
        || theirpub.len() != group.elem_len()
    {
        return Err(Error::Integrity);
    }
    match group {
        SpakeGroup::Edwards25519 => edwards25519::result(wbytes, ourpriv, theirpub, !kdc),
        SpakeGroup::P256 => p256::result(wbytes, ourpriv, theirpub, !kdc),
    }
}

/// Whether `bytes` is a group element of `group` (the fuzz target's decoder).
///
/// # Errors
///
/// [`Error::Integrity`] when `bytes` is not the group's `elem_len` octets or does not decode.
pub fn spake_decode_point(group: SpakeGroup, bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() != group.elem_len() {
        return Err(Error::Integrity);
    }
    match group {
        SpakeGroup::Edwards25519 => edwards25519::element(bytes).map(|_| ()),
        SpakeGroup::P256 => p256::element(bytes).map(|_| ()),
    }
}

/// The group's hash over the concatenation of `parts`.
///
/// MIT `builtin_sha256` (`edwards25519.c:1741-1746`): edwards25519 hashes with SHA-256.
/// MIT `ossl_hash` (`plugins/preauth/spake/openssl.c:271-288`): P-256 hashes with SHA-256 too.
fn group_hash(group: SpakeGroup, parts: &[&[u8]]) -> sha2::digest::Output<Sha256> {
    match group {
        SpakeGroup::Edwards25519 | SpakeGroup::P256 => {
            let mut h = <Sha256 as Sha2Digest>::new();
            for part in parts {
                Sha2Digest::update(&mut h, part);
            }
            Sha2Digest::finalize(h)
        }
    }
}

/// The transcript hash after `data1` and `data2`.
///
/// MIT `update_thash` (`util.c:69-99`): the group's hash of the old value, `data1` and `data2`; an empty value starts as `hash_len` zeros.
#[must_use]
pub fn spake_thash_update(group: SpakeGroup, thash: &[u8], data1: &[u8], data2: &[u8]) -> Vec<u8> {
    let zeros = vec![0u8; group.hash_len()];
    let old = if thash.is_empty() { &zeros } else { thash };
    group_hash(group, &[old, data1, data2]).to_vec()
}

/// `K'[n]`, a key of the initial key's enctype.
///
/// The seed's own allocation, the whole hashed block, is wiped on every return; each hash output
/// it is copied from, a stack value, is not.
///
/// MIT `derive_key` (`util.c:143-212`): `CF2(ikey, "SPAKE", random-to-key(seed), "keyderiv")`, the seed the enctype's random-to-key length of hash blocks.
///
/// # Errors
///
/// The refusals of [`krb_fx_cf2`] for a des3-cbc-sha1 `ikey` MIT refuses; otherwise none: the seed
/// is cut to the random-to-key length of `ikey`'s enctype.
pub fn spake_derive_key(
    ikey: &ProtocolKey,
    group: SpakeGroup,
    wbytes: &[u8],
    spakeresult: &[u8],
    thash: &[u8],
    der_req: &[u8],
    n: u32,
) -> Result<ProtocolKey, Error> {
    let etype = ikey.etype();
    let seedlen = etype.keybytes();
    let hashlen = group.hash_len();
    let nblocks = seedlen.div_ceil(hashlen);
    let groupn = group.number().to_be_bytes();
    let etypen = etype.to_iana().to_be_bytes();
    let nbuf = n.to_be_bytes();
    let mut seed = vec![0u8; nblocks * hashlen];
    for (i, block) in seed.chunks_exact_mut(hashlen).enumerate() {
        let bcount = [u8::try_from(i + 1).unwrap_or(u8::MAX)];
        block.copy_from_slice(&group_hash(
            group,
            &[
                b"SPAKEkey",
                &groupn,
                &etypen,
                wbytes,
                spakeresult,
                thash,
                der_req,
                &nbuf,
                &bcount,
            ],
        ));
    }
    seed.truncate(seedlen);
    let hkey = ProtocolKey::from_random(etype, &seed);
    wipe(&mut seed);
    krb_fx_cf2(ikey, &hkey?, b"SPAKE", b"keyderiv")
}
