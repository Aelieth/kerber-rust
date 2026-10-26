//! Gen 2 is a non-residue. p-1 is not fully factored. S = 1, so the root is -1.
//! Scalar gen 7 is the least non-residue mod n.

pub mod r1;
pub mod t1;

#[cfg(target_pointer_width = "64")]
mod field;
#[cfg(target_pointer_width = "64")]
mod scalar;

pub use elliptic_curve::bigint::U512;

#[cfg(target_pointer_width = "64")]
pub(crate) use field::FieldElement;
#[cfg(target_pointer_width = "64")]
pub use scalar::Scalar;

use elliptic_curve::{array::typenum::U64, bigint::Odd};

pub type FieldBytes = elliptic_curve::array::Array<u8, U64>;

pub(crate) const ORDER_HEX: &str = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
pub(crate) const ORDER: Odd<U512> = Odd::<U512>::from_be_hex(ORDER_HEX);
