//! The wipe an [`EncryptionKey`](crate::EncryptionKey) runs on its octets when it drops.
//!
//! rasn's `OctetString` is a newtype over a reference-counted `bytes::Bytes`, so a key can wipe
//! its buffer only while it holds the last handle on it. A test build keeps each wiped allocation
//! instead of freeing it, so a test can see that the buffer the key held is the one zeroed, whole.

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
    let mut buf = Vec::<u8>::from(last);
    buf.resize(buf.capacity(), 0);
    buf.as_mut_slice().zeroize();
    #[cfg(test)]
    let _ = tests::WIPED.try_with(|w| w.borrow_mut().push(buf));
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use rasn::types::OctetString;

    use crate::EncryptionKey;

    thread_local! {
        /// The allocations `wipe_octets` zeroed on this thread, kept alive.
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
}
