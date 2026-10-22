//! Synthesized by fiat-crypto. MIT, Apache-2.0, or BSD-1-Clause.

use elliptic_curve::{
    bigint::U512,
    ff::PrimeField,
    ops::BatchInvert,
    subtle::{Choice, ConstantTimeEq, CtOption},
};

#[cfg(target_pointer_width = "64")]
#[path = "../fiat/bp512_64.rs"]
#[allow(dead_code, clippy::all, clippy::pedantic, unused)]
mod field_impl;

#[cfg(target_pointer_width = "64")]
#[allow(clippy::wildcard_imports)]
use field_impl::*;

const MODULUS_HEX: &str = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";

primefield::monty_field_params! {
    name: FieldParams,
    modulus: MODULUS_HEX,
    uint: U512,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 2,
    doc: "Montgomery parameters for brainpoolP512's field modulus"
}

primefield::monty_field_element! {
    name: FieldElement,
    params: FieldParams,
    uint: U512,
    doc: "Element in the brainpoolP512 field modulo p"
}

#[cfg(target_pointer_width = "64")]
primefield::fiat_monty_field_arithmetic! {
    name: FieldElement,
    params: FieldParams,
    uint: U512,
    non_mont: fiat_bp512_non_montgomery_domain_field_element,
    mont: fiat_bp512_montgomery_domain_field_element,
    from_mont: fiat_bp512_from_montgomery,
    to_mont: fiat_bp512_to_montgomery,
    add: fiat_bp512_add,
    sub: fiat_bp512_sub,
    mul: fiat_bp512_mul,
    neg: fiat_bp512_opp,
    square: fiat_bp512_square,
    divstep_precomp: fiat_bp512_divstep_precomp,
    divstep: fiat_bp512_divstep,
    msat: fiat_bp512_msat,
    selectnz: fiat_bp512_selectznz
}

impl BatchInvert for FieldElement {}

#[cfg(all(test, target_pointer_width = "64"))]
mod tests {
    use super::{FieldElement, FieldParams, U512};
    use super::{
        fiat_bp512_montgomery_domain_field_element, fiat_bp512_msat,
        fiat_bp512_non_montgomery_domain_field_element, fiat_bp512_to_montgomery,
    };

    primefield::test_primefield!(FieldElement, U512);

    primefield::test_fiat_monty_field_arithmetic!(
        name: FieldElement,
        params: FieldParams,
        uint: U512,
        non_mont: fiat_bp512_non_montgomery_domain_field_element,
        mont: fiat_bp512_montgomery_domain_field_element,
        to_mont: fiat_bp512_to_montgomery,
        msat: fiat_bp512_msat
    );
}
