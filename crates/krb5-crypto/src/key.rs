//! Long-term protocol keys. Bytes are zeroized on drop.

use zeroize::Zeroize;

use crate::error::Error;
use crate::etype::EncryptionType;

/// Protocol-format AES key for one etype.
///
/// The key bytes are wiped when the value is dropped. Cloning copies the
/// secret; avoid cloning unless a second owner is required.
pub struct ProtocolKey {
    etype: EncryptionType,
    bytes: Vec<u8>,
}

impl ProtocolKey {
    /// Wrap already-derived key bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `bytes` is not the etype's key size.
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
        self.bytes.zeroize();
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
