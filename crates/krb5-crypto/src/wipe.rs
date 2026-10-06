//! The wipe each zeroize-on-drop type in this crate runs on its secret buffers, and [`Wiped`]
//! on a buffer a key is cut from.
//!
//! A test build keeps each wiped allocation instead of freeing it, so a test can see that the
//! buffer a value owned is the one zeroed, whole. `P256Keypair` zeroizes its inline scalar
//! itself, and a test build records that array as the drop left it.

use std::ops::{Deref, DerefMut};

use zeroize::Zeroize;

/// Zeroizes every byte of `buf`'s allocation in place, then frees it and leaves `buf` empty.
pub(crate) fn wipe(buf: &mut Vec<u8>) {
    let mut owned = std::mem::take(buf);
    if owned.capacity() == 0 {
        return;
    }
    owned.resize(owned.capacity(), 0);
    owned.as_mut_slice().zeroize();
    #[cfg(test)]
    let _ = tests::WIPED.try_with(|w| w.borrow_mut().push(owned));
}

/// A temporary buffer of key material that [`wipe`] zeroes, whole, when it drops, so every
/// return wipes it, the `?` ones included. `DerefMut` hands out the `&mut Vec<u8>`, so a push
/// past its capacity, a `.clone()` or a `.to_vec()` leaves a copy nothing wipes; every site
/// sizes its buffer up front.
pub(crate) struct Wiped(pub(crate) Vec<u8>);

impl Drop for Wiped {
    fn drop(&mut self) {
        wipe(&mut self.0);
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
pub(crate) mod tests {
    use std::cell::RefCell;

    use crate::{
        EncryptionType, KeyUsage, OAKLEY_2048, ProtocolKey, SpakeGroup, derive_keys,
        derive_prfplus, dh_generate, key_from_shared, krb_fx_cf2, octetstring2key, p256_generate,
        pkinit_kdf_agile, prf, spake_derive_key, string_to_key,
    };

    thread_local! {
        /// The allocations `wipe` zeroed on this thread, kept alive.
        pub(super) static WIPED: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
        /// The scalar of each `P256Keypair` dropped on this thread, as its drop left it.
        pub(crate) static DROPPED_SCALARS: RefCell<Vec<[u8; 32]>> =
            const { RefCell::new(Vec::new()) };
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
            SpakeGroup::P256,
            &[1; 32],
            &[2; 33],
            &[3; 32],
            b"req",
            0,
        )
        .unwrap();
        // The seed is one 32-octet SHA-256 block cut to the 16-octet key: that block's own
        // allocation is wiped whole; then CF2's two PRF+ blocks and its two outputs; then the
        // hash key copied from the seed.
        assert_eq!(
            take_wiped(),
            [
                vec![0; 32],
                vec![0; 32],
                vec![0; 32],
                vec![0; 16],
                vec![0; 16],
                vec![0; 16]
            ]
        );
        drop(key);
    }

    #[test]
    fn a_dropped_p256_keypair_wipes_its_scalar_in_place() {
        let kp = p256_generate().unwrap();
        assert_ne!(kp.secret, [0; 32]);
        DROPPED_SCALARS.with(|d| d.borrow_mut().clear());
        drop(kp);
        assert_eq!(DROPPED_SCALARS.with(|d| d.borrow().clone()), [[0; 32]]);
    }

    /// Zeroed allocations of these sizes, in this order.
    fn zeroed(sizes: &[usize]) -> Vec<Vec<u8>> {
        sizes.iter().map(|n| vec![0; *n]).collect()
    }

    fn key(etype: EncryptionType, fill: u8) -> ProtocolKey {
        ProtocolKey::from_bytes(etype, &vec![fill; etype.key_len()]).unwrap()
    }

    #[test]
    fn cf2_wipes_both_prf_plus_outputs() {
        let (k1, k2) = (aes128(0x11), aes128(0x22));
        take_wiped();
        let k = krb_fx_cf2(&k1, &k2, b"one", b"two").unwrap();
        // Each PRF+ wipes its 32-octet HMAC block; then the two 16-octet outputs, b and a.
        assert_eq!(take_wiped(), zeroed(&[32, 32, 16, 16]));
        drop(k);
    }

    #[test]
    fn the_pkinit_kdfs_wipe_the_buffer_a_key_is_cut_from() {
        let aes256 = EncryptionType::Aes256CtsHmacSha196;
        take_wiped();
        let keys = [
            octetstring2key(EncryptionType::Aes128CtsHmacSha256128, b"z").unwrap(),
            pkinit_kdf_agile(aes256, b"z", b"other info").unwrap(),
            key_from_shared(EncryptionType::Aes128CtsHmacSha256128, b"short").unwrap(),
            key_from_shared(EncryptionType::Aes128CtsHmacSha256128, &[7; 40]).unwrap(),
        ];
        // The SHA-1 stream (16 + 20), the SHA-256 stream (32 + 32), the hashed short secret;
        // a secret long enough is cut in place and leaves no buffer.
        assert_eq!(take_wiped(), zeroed(&[36, 64, 16]));
        drop(keys);
    }

    #[test]
    fn string_to_key_wipes_every_intermediate_key() {
        let one = 1u32.to_be_bytes();
        let salt = b"ATHENA.MIT.EDUraeburn";
        take_wiped();
        let aes = string_to_key(
            EncryptionType::Aes256CtsHmacSha196,
            b"password",
            salt,
            Some(&one),
        );
        // DK's output, then the PBKDF2 output.
        assert_eq!(take_wiped(), zeroed(&[32, 32]));
        let rc4 = string_to_key(EncryptionType::Rc4Hmac, b"password", salt, None);
        // The UTF-16 copy of the password, then the unused PBKDF2 buffer.
        assert_eq!(take_wiped(), zeroed(&[16, 16]));
        let des3 = string_to_key(EncryptionType::Des3CbcSha1, b"password", salt, None);
        // DK's three cipher blocks and its DR buffer; the key; the n-fold; the password and
        // salt; the unused PBKDF2 buffer.
        assert_eq!(take_wiped(), zeroed(&[8, 8, 8, 24, 24, 21, 29, 24]));
        drop((aes, rc4, des3));
    }

    #[test]
    fn prf_wipes_its_derived_keys() {
        let sha1 = key(EncryptionType::Aes128CtsHmacSha196, 0x33);
        let camellia = key(EncryptionType::Camellia128CtsCmac, 0x44);
        let sha2 = aes128(0x55);
        take_wiped();
        let out = prf(&sha1, b"input").unwrap();
        // Kp = DK(key, "prf").
        assert_eq!(take_wiped(), zeroed(&[16]));
        let out2 = prf(&camellia, b"input").unwrap();
        // The CMAC block, the CMAC input, the feedback block, then Kp.
        assert_eq!(take_wiped(), zeroed(&[16, 28, 16, 16]));
        let k = derive_prfplus(&sha2, b"input").unwrap();
        // PRF+'s HMAC block, then its 16-octet output.
        assert_eq!(take_wiped(), zeroed(&[32, 16]));
        drop((out, out2, k));
    }
}
