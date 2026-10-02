//! The wipe each zeroize-on-drop type in this crate runs on its secret buffers, and
//! `spake_derive_key` on its seed.
//!
//! A test build keeps each wiped allocation instead of freeing it, so a test can see that the
//! buffer a value owned is the one zeroed, whole.

use zeroize::Zeroize;

/// Zeroizes every byte of `buf`'s allocation in place, then frees it and leaves `buf` empty.
pub(crate) fn wipe(buf: &mut Vec<u8>) {
    let mut owned = std::mem::take(buf);
    owned.resize(owned.capacity(), 0);
    owned.as_mut_slice().zeroize();
    #[cfg(test)]
    let _ = tests::WIPED.try_with(|w| w.borrow_mut().push(owned));
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use crate::{
        EncryptionType, KeyUsage, OAKLEY_2048, ProtocolKey, SPAKE_GROUP_P256, derive_keys,
        dh_generate, spake_derive_key,
    };

    thread_local! {
        /// The allocations `wipe` zeroed on this thread, kept alive.
        pub(super) static WIPED: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
    }

    fn take_wiped() -> Vec<Vec<u8>> {
        WIPED.with(|w| std::mem::take(&mut *w.borrow_mut()))
    }

    fn addresses(wiped: &[Vec<u8>]) -> Vec<*const u8> {
        wiped.iter().map(Vec::as_ptr).collect()
    }

    fn aes128(fill: u8) -> ProtocolKey {
        ProtocolKey::from_bytes(EncryptionType::Aes128CtsHmacSha256128, &[fill; 16]).unwrap()
    }

    #[test]
    fn a_dropped_protocol_key_and_its_clone_each_wipe_their_own_buffer() {
        let key = aes128(0x5a);
        let twin = key.clone();
        let at = [key.as_bytes().as_ptr(), twin.as_bytes().as_ptr()];
        take_wiped();
        drop(key);
        drop(twin);
        let wiped = take_wiped();
        assert_eq!(addresses(&wiped), at, "a drop wiped a copy, or nothing");
        assert_eq!(wiped, [[0; 16]; 2]);
    }

    #[test]
    fn dropped_derived_keys_wipe_kc_ke_and_ki_whole() {
        let key = aes128(0x5a);
        let derived = derive_keys(&key, KeyUsage::new(2).unwrap()).unwrap();
        let at = [
            derived.kc.as_ptr(),
            derived.ke.as_ptr(),
            derived.ki.as_ptr(),
        ];
        take_wiped();
        drop(derived);
        let wiped = take_wiped();
        assert_eq!(addresses(&wiped), at, "a drop wiped a copy, or nothing");
        // Each key is cut from a 32-octet HMAC-SHA-256 output, all of which is zeroed.
        assert_eq!(wiped, [[0; 32]; 3]);
    }

    #[test]
    fn a_dropped_dh_keypair_wipes_its_exponent() {
        let kp = dh_generate(&OAKLEY_2048).unwrap();
        let at = kp.secret.as_ptr();
        take_wiped();
        drop(kp);
        let wiped = take_wiped();
        assert_eq!(addresses(&wiped), [at], "the drop wiped a copy, or nothing");
        assert_eq!(wiped, [[0; 32]]);
    }

    #[test]
    fn spake_derive_key_wipes_the_whole_seed_block_it_hashed() {
        let ikey = aes128(0x5a);
        take_wiped();
        let key = spake_derive_key(
            &ikey,
            SPAKE_GROUP_P256,
            &[1; 32],
            &[2; 33],
            &[3; 32],
            b"req",
            0,
        )
        .unwrap();
        // The seed is one 32-octet SHA-256 block cut to the 16-octet key: that block's own
        // allocation is wiped whole, then the hash key copied from it.
        assert_eq!(take_wiped(), [vec![0; 32], vec![0; 16]]);
        drop(key);
    }
}
