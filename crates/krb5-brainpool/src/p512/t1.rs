#[cfg(feature = "ecdsa")]
#[path = "t1_ecdsa.rs"]
pub mod ecdsa;

#[cfg(all(feature = "arithmetic", target_pointer_width = "64"))]
#[path = "t1_curve.rs"]
mod arithmetic;

#[cfg(all(feature = "arithmetic", target_pointer_width = "64"))]
pub use {
    self::arithmetic::{AffinePoint, NonZeroScalar, ProjectivePoint, ScalarValue},
    crate::p512::Scalar,
};

use crate::p512::ORDER;
use elliptic_curve::{
    bigint::{Odd, U512},
    consts::U64,
};

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct BrainpoolP512t1;

impl elliptic_curve::Curve for BrainpoolP512t1 {
    type FieldBytesSize = U64;
    type Uint = U512;
    const ORDER: Odd<U512> = ORDER;
}

impl elliptic_curve::PrimeCurve for BrainpoolP512t1 {}

impl elliptic_curve::point::PointCompression for BrainpoolP512t1 {
    const COMPRESS_POINTS: bool = false;
}

pub type Sec1Point = elliptic_curve::sec1::Sec1Point<BrainpoolP512t1>;

pub type FieldBytes = elliptic_curve::FieldBytes<BrainpoolP512t1>;

pub type SecretKey = elliptic_curve::SecretKey<BrainpoolP512t1>;

#[cfg(not(feature = "arithmetic"))]
impl elliptic_curve::sec1::ValidatePublicKey for BrainpoolP512t1 {}
