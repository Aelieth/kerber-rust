use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use p256::{AffinePoint, ProjectivePoint, Scalar, Sec1Point, U256};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::p256_generate;

// MIT: `P256_M` (plugins/preauth/spake/iana.c:47-51)
pub(super) const M: [u8; 33] = [
    0x02, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2,
    0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1,
    0x2f,
];

// MIT: `P256_N` (plugins/preauth/spake/iana.c:53-57)
pub(super) const N: [u8; 33] = [
    0x03, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77,
    0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b,
    0x49,
];

pub(super) fn element(bytes: &[u8]) -> Result<ProjectivePoint, Error> {
    let encoded = Sec1Point::from_bytes(bytes).map_err(|_| Error::Integrity)?;
    let affine = Option::<AffinePoint>::from(AffinePoint::from_sec1_point(&encoded))
        .ok_or(Error::Integrity)?;
    Ok(ProjectivePoint::from(affine))
}

fn constant(use_m: bool) -> Result<ProjectivePoint, Error> {
    element(if use_m { &M } else { &N })
}

// MIT: `unmarshal_w` (plugins/preauth/spake/openssl.c:141-161)
fn reduce(bytes: &[u8]) -> Result<Zeroizing<Scalar>, Error> {
    if bytes.len() != 32 {
        return Err(Error::Integrity);
    }
    let wide = Zeroizing::new(U256::from_be_slice(bytes));
    Ok(Zeroizing::new(<Scalar as Reduce<U256>>::reduce(&wide)))
}

fn encode(point: &ProjectivePoint) -> Result<Vec<u8>, Error> {
    let affine = Zeroizing::new(AffinePoint::from(*point));
    let encoded = Zeroizing::new(affine.to_sec1_point(true));
    if encoded.len() != M.len() {
        return Err(Error::Integrity);
    }
    Ok(encoded.as_bytes().to_vec())
}

// MIT: `ossl_keygen` (plugins/preauth/spake/openssl.c:163-210)
pub(super) fn keygen(wbytes: &[u8], use_m: bool) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), Error> {
    let pair = p256_generate()?;
    let public = public(wbytes, &pair.secret, use_m)?;
    Ok((Zeroizing::new(pair.secret.to_vec()), public))
}

pub(super) fn public(wbytes: &[u8], private: &[u8], use_m: bool) -> Result<Vec<u8>, Error> {
    let w = reduce(wbytes)?;
    let x = reduce(private)?;
    let x_g = Zeroizing::new(ProjectivePoint::GENERATOR * *x);
    let w_c = Zeroizing::new(constant(use_m)? * *w);
    encode(&(*x_g + *w_c))
}

// MIT: `ossl_result` (plugins/preauth/spake/openssl.c:212-269)
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
        let w = [9u8; 32];
        let x = [1u8; 32];
        let w_n = encode(&(constant(false).unwrap() * *reduce(&w).unwrap())).unwrap();
        assert_eq!(result(&w, &x, &w_n, false), Err(Error::Integrity));
    }
}
