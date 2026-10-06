//! Long-term protocol keys. Bytes are zeroized on drop.
//!
//! `from_bytes` refuses a buffer that is not the etype's key length.
//! Drop wipes the key's own allocation, whole. Cloning copies it.

use zeroize::Zeroize;

use crate::error::Error;
use crate::etype::EncryptionType;
use crate::wipe::wipe;

/// Protocol-format AES key for one etype.
///
/// The key's own allocation is wiped, whole, when the value is dropped. Cloning
/// copies the secret into a buffer the clone wipes when it drops; avoid cloning
/// unless a second owner is required.
pub struct ProtocolKey {
    etype: EncryptionType,
    bytes: Vec<u8>,
}

impl ProtocolKey {
    /// Wrap already-derived key bytes.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKeyLength`] when `bytes` is not the etype's key size.
    pub fn from_bytes(etype: EncryptionType, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != etype.key_len() {
            return Err(Error::InvalidKeyLength);
        }
        Ok(Self {
            etype,
            bytes: bytes.to_vec(),
        })
    }

    /// A fresh random key of `etype`.
    /// MIT `krb5_c_make_random_key` (`lib/crypto/krb/make_random_key.c:30-76`): `keybytes` random octets through the enctype's random-to-key, so a DES3 key gets its parity bits.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`] when the OS random source fails.
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

    /// Encryption type of this key.
    #[must_use]
    pub const fn etype(&self) -> EncryptionType {
        self.etype
    }

    /// Borrow the raw key octets. Callers must not persist the slice beyond
    /// the borrow.
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

// No `==` on keys, which would compare key bytes in variable time. `ProtocolKey` implementing
// `PartialEq` against itself (so also `Eq`, `PartialOrd` or `Ord`), against `[u8]` or against
// `Vec<u8>` makes the path below ambiguous, and the crate stops compiling; other right-hand
// types are not caught.
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
