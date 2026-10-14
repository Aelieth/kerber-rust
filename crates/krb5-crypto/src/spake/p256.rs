//! MIT's SPAKE group P-256 (its OpenSSL groups) on the p256 crate.
//!
//! Scalars are 32 octets big-endian and elements are 33-octet compressed SEC1 points.

use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar, U256};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::p256_generate;

/// The KDC's constant M.
///
/// MIT `P256_M` (`iana.c:47-51`): the registry's M, compressed.
pub(super) const M: [u8; 33] = [
    0x02, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2,
    0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1,
    0x2f,
];

/// The client's constant N.
///
/// MIT `P256_N` (`iana.c:53-57`): the registry's N, compressed.
pub(super) const N: [u8; 33] = [
    0x03, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77,
    0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b,
    0x49,
];

/// A point from its SEC1 encoding; one not on the curve is refused.
pub(super) fn element(bytes: &[u8]) -> Result<ProjectivePoint, Error> {
    let encoded = EncodedPoint::from_bytes(bytes).map_err(|_| Error::Integrity)?;
    let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .ok_or(Error::Integrity)?;
    Ok(ProjectivePoint::from(affine))
}

fn constant(use_m: bool) -> Result<ProjectivePoint, Error> {
    element(if use_m { &M } else { &N })
}

/// A 32-octet big-endian number reduced modulo the group order, `Zeroizing`.
///
/// MIT `unmarshal_w` (`plugins/preauth/spake/openssl.c:141-161`): the multiplier octets are reduced modulo the order, so w may be 0.
fn reduce(bytes: &[u8]) -> Result<Zeroizing<Scalar>, Error> {
    if bytes.len() != 32 {
        return Err(Error::Integrity);
    }
    let wide = Zeroizing::new(U256::from_be_slice(bytes));
    Ok(Zeroizing::new(<Scalar as Reduce<U256>>::reduce(*wide)))
}

/// The compressed encoding; the point at infinity has a 1-octet one, which MIT's length check
/// after `EC_POINT_point2oct` refuses. The affine point and the encoding are `Zeroizing`, as
/// for K they are secret.
fn encode(point: &ProjectivePoint) -> Result<Vec<u8>, Error> {
    let affine = Zeroizing::new(AffinePoint::from(*point));
    let encoded = Zeroizing::new(affine.to_encoded_point(true));
    if encoded.len() != M.len() {
        return Err(Error::Integrity);
    }
    Ok(encoded.as_bytes().to_vec())
}

/// A random private scalar and its public element.
///
/// MIT `ossl_keygen` (`plugins/preauth/spake/openssl.c:163-210`): priv is random below the order, the element is priv·G + w·M (or N), and both are marshalled big-endian and compressed.
pub(super) fn keygen(wbytes: &[u8], use_m: bool) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), Error> {
    let pair = p256_generate()?;
    let public = public(wbytes, &pair.secret, use_m)?;
    Ok((Zeroizing::new(pair.secret.to_vec()), public))
}

/// The public element of a private scalar, `priv·G + w·M` (or N), compressed.
///
/// MIT `ossl_keygen` (`plugins/preauth/spake/openssl.c:189-209`): one EC_POINT_mul, then a 33-octet compressed encoding or a failure; priv and w are cleared (`BN_clear_free`).
pub(super) fn public(wbytes: &[u8], private: &[u8], use_m: bool) -> Result<Vec<u8>, Error> {
    let w = reduce(wbytes)?;
    let x = reduce(private)?;
    let x_g = Zeroizing::new(ProjectivePoint::GENERATOR * *x);
    let w_c = Zeroizing::new(constant(use_m)? * *w);
    encode(&(*x_g + *w_c))
}

/// `K = priv·(pub − w·constant)`, compressed.
///
/// MIT `ossl_result` (`plugins/preauth/spake/openssl.c:212-269`): an undecodable element is EINVAL, and a K at infinity fails the length check; priv, w and the point that becomes K are cleared (`BN_clear_free`, `EC_POINT_clear_free`).
pub(super) fn result(
    wbytes: &[u8],
    ourpriv: &[u8],
    theirpub: &[u8],
    use_m: bool,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let w = reduce(wbytes)?;
    let x = reduce(ourpriv)?;
    let peer = element(theirpub)?;
    let w_c = Zeroizing::new(constant(use_m)? * *w);
    let unmasked = Zeroizing::new(peer - *w_c);
    let k = Zeroizing::new(*unmasked * *x);
    Ok(Zeroizing::new(encode(&k)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn k_at_infinity_is_refused() {
        // A peer element equal to w·N leaves the KDC's K at infinity.
        let w = [9u8; 32];
        let x = [1u8; 32];
        let w_n = encode(&(constant(false).unwrap() * *reduce(&w).unwrap())).unwrap();
        assert_eq!(result(&w, &x, &w_n, false), Err(Error::Integrity));
    }

    #[test]
    fn a_zero_multiplier_masks_nothing_like_mit() {
        // MIT's `unmarshal_w` reduces w modulo the order and keeps 0.
        let x = [1u8; 32];
        let unmasked = public(&[0u8; 32], &x, true).unwrap();
        let base = encode(&(ProjectivePoint::GENERATOR * *reduce(&x).unwrap())).unwrap();
        assert_eq!(unmasked, base);
    }
}
