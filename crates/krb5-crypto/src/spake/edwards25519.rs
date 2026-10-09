//! MIT's built-in SPAKE group edwards25519 on curve25519-dalek.
//!
//! Scalars are 32 octets little-endian and elements are the 32-octet Edwards point encoding. A
//! private scalar is a multiple of the cofactor 8, so `K` lies in the prime-order subgroup even
//! when the peer's element does not.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use zeroize::Zeroizing;

use crate::error::Error;

/// The KDC's constant M.
///
/// MIT `edwards25519_M` (`iana.c:35-39`): the registry's M, found by hashing "edwards25519 point generation seed (M)".
pub(super) const M: [u8; 32] = [
    0xd0, 0x48, 0x03, 0x2c, 0x6e, 0xa0, 0xb6, 0xd6, 0x97, 0xdd, 0xc2, 0xe8, 0x6b, 0xda, 0x85, 0xa3,
    0x3a, 0xda, 0xc9, 0x20, 0xf1, 0xbf, 0x18, 0xe1, 0xb0, 0xc6, 0xd1, 0x66, 0xa5, 0xce, 0xcd, 0xaf,
];

/// The client's constant N.
///
/// MIT `edwards25519_N` (`iana.c:41-45`): the registry's N, found by hashing "edwards25519 point generation seed (N)".
pub(super) const N: [u8; 32] = [
    0xd3, 0xbf, 0xb5, 0x18, 0xf4, 0x4f, 0x34, 0x30, 0xf2, 0x9d, 0x0c, 0x92, 0xaf, 0x50, 0x38, 0x65,
    0xa1, 0xed, 0x32, 0x81, 0xdc, 0x69, 0xb3, 0x5d, 0xd8, 0x68, 0xba, 0x85, 0xf8, 0x86, 0xc4, 0xab,
];

/// An element from its 32-octet encoding.
///
/// MIT `x25519_ge_frombytes_vartime` (`edwards25519.c:618-662`): the y top bit is the sign of x, a y at or above p is taken mod p, and a y off the curve is refused.
pub(super) fn element(bytes: &[u8]) -> Result<EdwardsPoint, Error> {
    let encoded: [u8; 32] = bytes.try_into().map_err(|_| Error::Integrity)?;
    CompressedEdwardsY(encoded)
        .decompress()
        .ok_or(Error::Integrity)
}

fn constant(use_m: bool) -> Result<EdwardsPoint, Error> {
    element(if use_m { &M } else { &N })
}

/// A 32-octet little-endian number reduced modulo the group order `l`, as MIT's `x25519_sc_reduce`
/// does with the 32 octets zero-extended to 64.
fn reduce(bytes: &[u8]) -> Result<Zeroizing<Scalar>, Error> {
    let mut wide = Zeroizing::new([0u8; 32]);
    if bytes.len() != wide.len() {
        return Err(Error::Integrity);
    }
    wide.copy_from_slice(bytes);
    Ok(Zeroizing::new(Scalar::from_bytes_mod_order(*wide)))
}

/// `n·8`, little-endian.
///
/// MIT `left_shift_3` (`edwards25519.c:1633-1644`): the reduced random scalar times the cofactor, without a reduction after.
fn left_shift_3(n: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    let mut carry = 0u8;
    for (o, b) in out.iter_mut().zip(n) {
        *o = (b << 3) | carry;
        carry = b >> 5;
    }
    out
}

/// A random private scalar and its public element.
///
/// MIT `builtin_edwards25519_keygen` (`edwards25519.c:1646-1693`): x or y is 32 random octets reduced modulo l, then times 8; the element is x·G + w·M, or y·G + w·N.
pub(super) fn keygen(wbytes: &[u8], use_m: bool) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), Error> {
    let mut random = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(random.as_mut_slice()).map_err(|_| Error::Rng)?;
    let reduced = reduce(random.as_slice())?;
    let private = left_shift_3(reduced.as_bytes());
    let public = public(wbytes, private.as_slice(), use_m)?;
    Ok((Zeroizing::new(private.to_vec()), public))
}

/// The public element of a private scalar: x·G + w·M, or y·G + w·N, encoded.
///
/// MIT `builtin_edwards25519_keygen` (`edwards25519.c:1664-1688`): w is reduced modulo l and the base multiple is taken of the whole scalar.
pub(super) fn public(wbytes: &[u8], private: &[u8], use_m: bool) -> Result<Vec<u8>, Error> {
    // G has order l, so x·G is (x mod l)·G for any 256-bit x.
    let x = reduce(private)?;
    let w = reduce(wbytes)?;
    let x_g = Zeroizing::new(EdwardsPoint::mul_base(&x));
    let w_c = Zeroizing::new(constant(use_m)? * *w);
    let masked = *x_g + *w_c;
    Ok(masked.compress().to_bytes().to_vec())
}

/// `K = x·(S − w·N)` or `K = y·(T − w·M)`, encoded.
///
/// MIT `builtin_edwards25519_result` (`edwards25519.c:1695-1739`): an element off the curve is EINVAL, and K is the private scalar's whole 256-bit multiple of the unmasked element.
pub(super) fn result(
    wbytes: &[u8],
    ourpriv: &[u8],
    theirpub: &[u8],
    use_m: bool,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let masked = element(theirpub)?;
    let w = reduce(wbytes)?;
    // The unmasked element would let an eavesdropper test passwords offline: it, the mask w·N
    // (or w·M) and every multiple below are `Zeroizing`.
    let w_c = Zeroizing::new(constant(use_m)? * *w);
    let unmasked = Zeroizing::new(masked - *w_c);
    // MIT multiplies by the private scalar as an integer, not reduced modulo l. With
    // x = 8·high + low, x·U = high·(8·U) + low·U, and 8·U lies in the subgroup of order l, so
    // `high` may be reduced there; `low` is 0 for every scalar `keygen` makes.
    let mut high = Zeroizing::new([0u8; 32]);
    if ourpriv.len() != high.len() {
        return Err(Error::Integrity);
    }
    for (i, h) in high.iter_mut().enumerate() {
        let next = ourpriv.get(i + 1).copied().unwrap_or(0);
        *h = (ourpriv[i] >> 3) | (next << 5);
    }
    let high = Zeroizing::new(Scalar::from_bytes_mod_order(*high));
    let low = Zeroizing::new(Scalar::from(u64::from(ourpriv[0] & 7)));
    let eight_u = Zeroizing::new(unmasked.mul_by_cofactor());
    let high_part = Zeroizing::new(*eight_u * *high);
    let low_part = Zeroizing::new(*unmasked * *low);
    let k = Zeroizing::new(*high_part + *low_part);
    let encoded = Zeroizing::new(k.compress());
    Ok(Zeroizing::new(encoded.as_bytes().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// MIT's point search: SHA-256 of the seed, then of the previous hash, until the hash decodes
    /// to a point of order l.
    fn find_point(seed: &[u8]) -> ([u8; 32], usize) {
        let mut v: [u8; 32] = Sha256::digest(seed).into();
        for iteration in 1.. {
            if let Some(p) = CompressedEdwardsY(v).decompress()
                && p.is_torsion_free()
                && !p.is_small_order()
            {
                return (p.compress().to_bytes(), iteration);
            }
            v = Sha256::digest(v).into();
        }
        unreachable!()
    }

    #[test]
    fn m_and_n_are_the_seeds_points_found_where_mit_found_them() {
        // MIT `edwards25519.c` (the comment above kSpakeNSmallPrecomp): N in 7 iterations, M in
        // 21.
        assert_eq!(
            find_point(b"edwards25519 point generation seed (N)"),
            (N, 7)
        );
        assert_eq!(
            find_point(b"edwards25519 point generation seed (M)"),
            (M, 21)
        );
    }

    #[test]
    fn a_private_scalar_is_a_multiple_of_8() {
        for _ in 0..32 {
            let (private, public) = keygen(&[5u8; 32], true).unwrap();
            assert_eq!(private[0] & 7, 0);
            assert_eq!(public.len(), 32);
        }
    }

    #[test]
    fn a_small_order_part_of_the_peers_element_does_not_reach_k() {
        // T + a point of order 2 gives the same K as T: the private scalar is a multiple of 8.
        let w = [3u8; 32];
        let (y, _) = keygen(&w, false).unwrap();
        let (_, t) = keygen(&w, true).unwrap();
        let order_two = element(&{
            let mut b = [0u8; 32];
            b[0] = 0xec;
            b[1..31].fill(0xff);
            b[31] = 0x7f;
            b
        })
        .unwrap();
        assert!(order_two.is_small_order());
        let shifted = (element(&t).unwrap() + order_two).compress().to_bytes();
        assert_ne!(shifted.as_slice(), t.as_slice());
        assert_eq!(
            result(&w, &y, &t, true).unwrap(),
            result(&w, &y, &shifted, true).unwrap()
        );
    }

    #[test]
    fn a_non_canonical_y_decodes_like_mit() {
        // y + p for y = 1 (the identity) still decodes: MIT and dalek reduce y modulo p.
        let mut p_plus_one = [0xffu8; 32];
        p_plus_one[0] = 0xee;
        p_plus_one[31] = 0x7f;
        assert_eq!(
            element(&p_plus_one).unwrap().compress(),
            EdwardsPoint::default().compress()
        );
    }
}
