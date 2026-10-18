use std::ops::{Deref, DerefMut};

use zeroize::Zeroize;

/// The allocation is resized to its capacity before it is zeroed, so the slack is cleared too.
/// A `Wiped` buffer is wiped on drop, and that includes every `?` return.
/// `DerefMut` can grow or clone a copy nothing wipes, so every caller sizes the buffer first.
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
        EncryptionType, KeyUsage, OAKLEY_2048, ProtocolKey, derive_keys, dh_generate, p256_generate,
    };

    thread_local! {
        pub(super) static WIPED: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
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
    fn a_dropped_p256_keypair_wipes_its_scalar_in_place() {
        let kp = p256_generate().unwrap();
        assert_ne!(kp.secret, [0; 32]);
        DROPPED_SCALARS.with(|d| d.borrow_mut().clear());
        drop(kp);
        assert_eq!(DROPPED_SCALARS.with(|d| d.borrow().clone()), [[0; 32]]);
    }
}
