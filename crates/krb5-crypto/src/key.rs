//! Long-term protocol keys. Bytes are zeroized on drop.
//!
//! `from_bytes` refuses a buffer that is not the etype's key length.
//! Drop wipes the key's own allocation, whole. Cloning copies it.

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
