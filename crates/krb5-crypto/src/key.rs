use zeroize::Zeroize;

use crate::error::Error;
use crate::etype::EncryptionType;
use crate::wipe::wipe;

pub struct ProtocolKey {
    etype: EncryptionType,
    bytes: Vec<u8>,
}

impl ProtocolKey {
    pub fn from_bytes(etype: EncryptionType, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != etype.key_len() {
            return Err(Error::InvalidKeyLength);
        }
        Ok(Self {
            etype,
            bytes: bytes.to_vec(),
        })
    }

    // MIT krb5_c_make_random_key; see docs/parity/b1-crypto-keys.md
    pub fn random(etype: EncryptionType) -> Result<Self, Error> {
        let mut raw = vec![0u8; etype.keybytes()];
        getrandom::getrandom(&mut raw).map_err(|_| Error::Rng)?;
        let key = if etype == EncryptionType::Des3CbcSha1 {
            let mut k = crate::weak::des3_random_to_key(&raw);
            let out = Self::from_bytes(etype, &k);
            k.zeroize();
            out
        } else {
            Self::from_bytes(etype, &raw)
        };
        raw.zeroize();
        key
    }

    // MIT k5_rand2key_direct; see docs/parity/b1-crypto-keys.md
    // MIT k5_rand2key_des3; see docs/parity/b1-crypto-keys.md
    pub(crate) fn from_random(etype: EncryptionType, random: &[u8]) -> Result<Self, Error> {
        if random.len() != etype.keybytes() {
            return Err(Error::InvalidKeyLength);
        }
        if etype != EncryptionType::Des3CbcSha1 {
            return Self::from_bytes(etype, random);
        }
        let raw = zeroize::Zeroizing::new(crate::weak::des3_random_to_key(random));
        Self::from_bytes(etype, &*raw)
    }

    #[must_use]
    pub const fn etype(&self) -> EncryptionType {
        self.etype
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for ProtocolKey {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
    }
}

impl Clone for ProtocolKey {
    fn clone(&self) -> Self {
        Self {
            etype: self.etype,
            bytes: self.bytes.clone(),
        }
    }
}

impl std::fmt::Debug for ProtocolKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtocolKey")
            .field("etype", &self.etype)
            .field("len", &self.bytes.len())
            .finish()
    }
}

const _: fn() = || {
    trait AmbiguousIfComparable<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfComparable<()> for T {}
    impl<T: ?Sized + PartialEq> AmbiguousIfComparable<u8> for T {}
    impl<T: ?Sized + PartialEq<[u8]>> AmbiguousIfComparable<u16> for T {}
    impl<T: ?Sized + PartialEq<Vec<u8>>> AmbiguousIfComparable<u32> for T {}
    let _ = <ProtocolKey as AmbiguousIfComparable<_>>::check;
};

#[cfg(test)]
mod tests {
    use super::*;

    const KAT: &str = include_str!("../tests/data/mit-des3.kat");

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn odd_parity(octets: &[u8]) -> bool {
        octets.iter().all(|b| b.count_ones() % 2 == 1)
    }

    #[test]
    fn des3_random_to_key_is_mits() {
        let mut n = 0;
        for line in KAT.lines() {
            let p: Vec<&str> = line.split(' ').collect();
            if p[0] != "rtk" {
                continue;
            }
            let key = ProtocolKey::from_random(EncryptionType::Des3CbcSha1, &hex(p[1])).unwrap();
            assert_eq!(key.as_bytes(), hex(p[2]), "{line}");
            assert!(odd_parity(key.as_bytes()), "{line}");
            n += 1;
        }
        assert_eq!(n, 12);
    }
}
