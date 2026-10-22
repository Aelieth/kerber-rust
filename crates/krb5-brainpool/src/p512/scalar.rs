//! The arithmetic in `../fiat/` is fiat-crypto's output (MIT, Apache-2.0 or BSD-1-Clause).

use super::r1::BrainpoolP512r1;
use super::t1::BrainpoolP512t1;
use super::{ORDER_HEX, U512};
use elliptic_curve::{
    ff::PrimeField,
    scalar::{FromUintUnchecked, IsHigh},
    subtle::{Choice, ConstantTimeEq, ConstantTimeGreater, CtOption},
};
use primeorder::wnaf;

#[cfg(target_pointer_width = "64")]
#[path = "../fiat/bp512_scalar_64.rs"]
#[allow(dead_code, clippy::all, clippy::pedantic, unused)]
mod scalar_impl;

#[cfg(target_pointer_width = "64")]
#[allow(clippy::wildcard_imports)]
use scalar_impl::*;

primefield::monty_field_params! {
    name: ScalarParams,
    modulus: ORDER_HEX,
    uint: U512,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 7,
    doc: "Montgomery parameters for brainpoolP512's scalar modulus"
}

primefield::monty_field_element! {
    name: Scalar,
    params: ScalarParams,
    uint: U512,
    doc: "Element in the brainpoolP512 scalar field modulo n"
}

#[cfg(target_pointer_width = "64")]
primefield::fiat_monty_field_arithmetic! {
    name: Scalar,
    params: ScalarParams,
    uint: U512,
    non_mont: fiat_bp512_scalar_non_montgomery_domain_field_element,
    mont: fiat_bp512_scalar_montgomery_domain_field_element,
    from_mont: fiat_bp512_scalar_from_montgomery,
    to_mont: fiat_bp512_scalar_to_montgomery,
    add: fiat_bp512_scalar_add,
    sub: fiat_bp512_scalar_sub,
    mul: fiat_bp512_scalar_mul,
    neg: fiat_bp512_scalar_opp,
    square: fiat_bp512_scalar_square,
    divstep_precomp: fiat_bp512_scalar_divstep_precomp,
    divstep: fiat_bp512_scalar_divstep,
    msat: fiat_bp512_scalar_msat,
    selectnz: fiat_bp512_scalar_selectznz
}

primefield::monty_field_reduce! {
    name: Scalar,
    params: ScalarParams,
    uint: U512,
}

elliptic_curve::scalar_impls!(BrainpoolP512r1, Scalar);
elliptic_curve::scalar_impls!(BrainpoolP512t1, Scalar);

wnaf::impl_wnaf_size_for_scalar!(Scalar);

impl AsRef<Scalar> for Scalar {
    fn as_ref(&self) -> &Scalar {
        self
    }
}

impl FromUintUnchecked for Scalar {
    type Uint = U512;

    fn from_uint_unchecked(uint: Self::Uint) -> Self {
        Self::from_uint_unchecked(uint)
    }
}

impl IsHigh for Scalar {
    fn is_high(&self) -> Choice {
        const MODULUS_SHR1: U512 = crate::p512::ORDER.as_ref().shr_vartime(1);
        self.to_canonical().ct_gt(&MODULUS_SHR1)
    }
}

#[cfg(all(test, target_pointer_width = "64"))]
mod tests {
    use super::{Scalar, ScalarParams, U512};
    use super::{
        fiat_bp512_scalar_montgomery_domain_field_element, fiat_bp512_scalar_msat,
        fiat_bp512_scalar_non_montgomery_domain_field_element, fiat_bp512_scalar_to_montgomery,
    };

    primefield::test_primefield!(Scalar, U512);

    primefield::test_fiat_monty_field_arithmetic!(
        name: Scalar,
        params: ScalarParams,
        uint: U512,
        non_mont: fiat_bp512_scalar_non_montgomery_domain_field_element,
        mont: fiat_bp512_scalar_montgomery_domain_field_element,
        to_mont: fiat_bp512_scalar_to_montgomery,
        msat: fiat_bp512_scalar_msat
    );
}
