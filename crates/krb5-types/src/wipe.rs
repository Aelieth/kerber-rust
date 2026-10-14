//! The wipe an [`EncryptionKey`](crate::EncryptionKey) runs on its octets when it drops, and
//! [`Wiped`] on a temporary buffer of key material.
//!
//! rasn's `OctetString` is a newtype over a reference-counted `bytes::Bytes`, so a key can wipe
//! its buffer only while it holds the last handle on it. A test build keeps each wiped allocation
//! instead of freeing it, so a test can see that the buffer the key held is the one zeroed, whole.

use std::ops::{Deref, DerefMut};

use rasn::types::OctetString;
use zeroize::Zeroize;

/// Zeroizes every byte of `octets`' allocation in place, then frees it, when `octets` is the last
/// handle on it. rasn's `From<OctetString> for Bytes` clones the handle and drops `octets` before
/// `try_into_mut` looks, so the clone is the last handle exactly when `octets` was. A buffer
/// another handle still shares is released untouched (the last handle wipes it if it is a key),
/// and a static buffer is never written.
pub(crate) fn wipe_octets(octets: OctetString) {
    let Ok(last) = bytes::Bytes::from(octets).try_into_mut() else {
        return;
    };
    wipe_vec(&mut Vec::<u8>::from(last));
}

/// Zeroizes every byte of `buf`'s allocation in place, then frees it and leaves `buf` empty.
pub(crate) fn wipe_vec(buf: &mut Vec<u8>) {
    let mut owned = std::mem::take(buf);
    if owned.capacity() == 0 {
        return;
    }
    owned.resize(owned.capacity(), 0);
    owned.as_mut_slice().zeroize();
    #[cfg(test)]
    let _ = tests::WIPED.try_with(|w| w.borrow_mut().push(owned));
}

/// A temporary buffer of key material that [`wipe_vec`] zeroes, whole, when it drops, so every
/// return wipes it, the `?` ones included. `DerefMut` hands out the `&mut Vec<u8>`, so a push
/// past its capacity, a `.clone()` or a `.to_vec()` leaves a copy nothing wipes; every site
/// sizes its buffer up front.
pub(crate) struct Wiped(pub(crate) Vec<u8>);

impl Drop for Wiped {
    fn drop(&mut self) {
        wipe_vec(&mut self.0);
    }
}

impl Deref for Wiped {
    type Target = Vec<u8>;

    fn deref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl DerefMut for Wiped {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use rasn::types::OctetString;

    use crate::EncryptionKey;

    thread_local! {
        /// The allocations `wipe_vec` zeroed on this thread, kept alive.
        pub(super) static WIPED: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
    }

    fn take_wiped() -> Vec<Vec<u8>> {
        WIPED.with(|w| std::mem::take(&mut *w.borrow_mut()))
    }

    fn key(keyvalue: OctetString) -> EncryptionKey {
        EncryptionKey {
            keytype: 18,
            keyvalue,
        }
    }

    #[test]
    fn a_dropped_key_wipes_its_own_buffer() {
        take_wiped();
        let k = key(OctetString::from(vec![0x5a; 32]));
        let at = k.keyvalue.as_ptr();
        drop(k);
        let wiped = take_wiped();
        assert_eq!(wiped.len(), 1, "the drop wiped no buffer");
        assert_eq!(
            wiped[0].as_ptr(),
            at,
            "the drop wiped a copy, not the key's buffer"
        );
        assert_eq!(wiped[0], [0; 32]);
    }

    #[test]
    fn a_decoded_key_wipes_its_own_buffer() {
        let der = rasn::der::encode(&key(OctetString::from(vec![0x5a; 16]))).unwrap();
        let k: EncryptionKey = rasn::der::decode(&der).unwrap();
        take_wiped();
        let at = k.keyvalue.as_ptr();
        drop(k);
        let wiped = take_wiped();
        assert_eq!(
            wiped.len(),
            1,
            "a key decoded from DER holds its buffer alone"
        );
        assert_eq!(wiped[0].as_ptr(), at);
        assert_eq!(wiped[0], [0; 16]);
    }

    #[test]
    fn the_last_clone_to_drop_wipes_the_shared_buffer() {
        take_wiped();
        let k = key(OctetString::from(vec![0x5a; 32]));
        let at = k.keyvalue.as_ptr();
        let twin = k.clone();
        drop(k);
        assert_eq!(
            take_wiped(),
            [] as [Vec<u8>; 0],
            "a buffer a clone still reads was wiped"
        );
        assert_eq!(*twin.keyvalue, [0x5a; 32]);
        drop(twin);
        let wiped = take_wiped();
        assert_eq!(wiped.len(), 1, "the last handle left the buffer unwiped");
        assert_eq!(wiped[0].as_ptr(), at);
        assert_eq!(wiped[0], [0; 32]);
    }

    #[test]
    fn a_key_cut_from_a_larger_buffer_wipes_all_of_it_once_it_is_the_last_handle() {
        take_wiped();
        let whole = bytes::Bytes::from(vec![0x5a; 64]);
        let at = whole.as_ptr();
        let k = key(OctetString::from(whole.slice(16..48)));
        drop(whole);
        drop(k);
        let wiped = take_wiped();
        assert_eq!(wiped.len(), 1);
        assert_eq!(wiped[0].as_ptr(), at);
        assert_eq!(wiped[0], [0; 64], "the bytes around the key are wiped too");
    }

    #[test]
    fn a_static_key_is_never_written() {
        static OCTETS: [u8; 16] = [0x5a; 16];
        take_wiped();
        drop(key(OctetString::from_static(&OCTETS)));
        assert_eq!(take_wiped(), [] as [Vec<u8>; 0]);
        assert_eq!(OCTETS, [0x5a; 16]);
    }

    /// The base64 text between `kind`'s PEM markers, as `parse_pem` takes it.
    fn pem_body<'a>(pem: &'a str, kind: &str) -> &'a str {
        let begin = format!("-----BEGIN {kind}-----");
        let rest = &pem[pem.find(&begin).unwrap() + begin.len()..];
        rest[..rest.find(&format!("-----END {kind}-----")).unwrap()].trim()
    }

    #[test]
    fn parsing_an_identity_wipes_its_key_text_and_der() {
        let ca = crate::pkinit::PkinitCa::generate().unwrap();
        let pem = ca.user_identity_pem("user").unwrap();
        let kind = if pem.contains("BEGIN EC PRIVATE KEY") {
            "EC PRIVATE KEY"
        } else {
            "PRIVATE KEY"
        };
        let cert_text = pem_body(&pem, "CERTIFICATE").len();
        let key_text = pem_body(&pem, kind);
        let key_chars = key_text
            .bytes()
            .filter(|b| *b != b'=' && !b.is_ascii_whitespace())
            .count();
        take_wiped();
        let (_cert, scalar) = crate::pkinit::parse_identity_pem(&pem).unwrap();
        assert_ne!(scalar, [0; 32]);
        // Each block's base64 text, wiped once decoded; then the key's DER, wiped once the
        // scalar is read out of it.
        assert_eq!(
            take_wiped(),
            [
                vec![0; cert_text],
                vec![0; key_text.len()],
                vec![0; key_chars * 3 / 4 + 1]
            ]
        );
    }
}
