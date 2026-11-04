mod edwards25519;
mod p256;

use sha2::{Digest as Sha2Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::key::ProtocolKey;
use crate::krb_fx_cf2;
use crate::prf::prf_plus;
use crate::wipe::wipe;

// MIT: `spake_iana_edwards25519` (plugins/preauth/spake/iana.c:93-96)
// MIT: `spake_iana_p256` (plugins/preauth/spake/iana.c:98-100)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SpakeGroup {
    Edwards25519,
    P256,
}

// MIT: `DEFAULT_GROUPS_CLIENT` (plugins/preauth/spake/groups.c:59-59)
// MIT: `KRB5_CONF_SPAKE_PREAUTH_GROUPS` (include/k5-int.h:301-301)
pub const SPAKE_DEFAULT_GROUPS_CLIENT: &str = "edwards25519";

// MIT: `DEFAULT_GROUPS_KDC` (plugins/preauth/spake/groups.c:60-60)
pub const SPAKE_DEFAULT_GROUPS_KDC: &str = "";

impl SpakeGroup {
    // MIT: `groupdefs` (plugins/preauth/spake/groups.c:89-97)
    pub const ALL: [Self; 2] = [Self::Edwards25519, Self::P256];

    // MIT: `find_gdef` (plugins/preauth/spake/groups.c:99-111)
    #[must_use]
    pub fn from_number(group: i32) -> Option<Self> {
        Self::ALL.into_iter().find(|g| g.number() == group)
    }

    // MIT: `find_gnum` (plugins/preauth/spake/groups.c:113-124)
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|g| g.name().eq_ignore_ascii_case(name))
    }

    #[must_use]
    pub const fn number(self) -> i32 {
        match self {
            Self::Edwards25519 => 1,
            Self::P256 => 2,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Edwards25519 => "edwards25519",
            Self::P256 => "P-256",
        }
    }

    #[must_use]
    pub const fn mult_len(self) -> usize {
        32
    }

    #[must_use]
    pub const fn elem_len(self) -> usize {
        match self {
            Self::Edwards25519 => 32,
            Self::P256 => 33,
        }
    }

    #[must_use]
    pub const fn hash_len(self) -> usize {
        32
    }

    #[must_use]
    pub const fn m(self) -> &'static [u8] {
        match self {
            Self::Edwards25519 => &edwards25519::M,
            Self::P256 => &p256::M,
        }
    }

    #[must_use]
    pub const fn n(self) -> &'static [u8] {
        match self {
            Self::Edwards25519 => &edwards25519::N,
            Self::P256 => &p256::N,
        }
    }
}

pub fn spake_group_words(value: &str) -> impl Iterator<Item = &str> {
    value
        .split([' ', '\t', '\r', '\n', ','])
        .filter(|word| !word.is_empty())
}

// MIT: `parse_groups` (plugins/preauth/spake/groups.c:176-211)
#[must_use]
pub fn spake_parse_groups(value: &str) -> Vec<SpakeGroup> {
    let mut out = Vec::new();
    for word in spake_group_words(value) {
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

// MIT: `derive_wbytes` (plugins/preauth/spake/util.c:101-141)
pub fn spake_wbytes(ikey: &ProtocolKey, group: SpakeGroup) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut input = b"SPAKEsecret".to_vec();
    input.extend_from_slice(&group.number().to_be_bytes());
    Ok(Zeroizing::new(prf_plus(ikey, &input, group.mult_len())?))
}

// MIT: `group_keygen` (plugins/preauth/spake/groups.c:332-371)
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

// MIT: `group_result` (plugins/preauth/spake/groups.c:373-412)
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

pub fn spake_decode_point(group: SpakeGroup, bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() != group.elem_len() {
        return Err(Error::Integrity);
    }
    match group {
        SpakeGroup::Edwards25519 => edwards25519::element(bytes).map(|_| ()),
        SpakeGroup::P256 => p256::element(bytes).map(|_| ()),
    }
}

// MIT: `builtin_sha256` (plugins/preauth/spake/edwards25519.c:1741-1746)
// MIT: `ossl_hash` (plugins/preauth/spake/openssl.c:271-288)
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

// MIT: `update_thash` (plugins/preauth/spake/util.c:69-99)
#[must_use]
pub fn spake_thash_update(group: SpakeGroup, thash: &[u8], data1: &[u8], data2: &[u8]) -> Vec<u8> {
    let zeros = vec![0u8; group.hash_len()];
    let old = if thash.is_empty() { &zeros } else { thash };
    group_hash(group, &[old, data1, data2]).to_vec()
}

// MIT: `derive_key` (plugins/preauth/spake/util.c:143-212)
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
