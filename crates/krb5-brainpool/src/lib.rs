//! brainpoolP512, r1 and t1, on a fiat field. A 32-bit build does not compile it.

#![no_std]
#![forbid(unsafe_code)]

pub mod p512;

pub use elliptic_curve;
