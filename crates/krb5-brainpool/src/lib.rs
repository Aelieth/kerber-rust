//! brainpoolP512 r1, t1. 32-bit builds do not compile.

#![no_std]
#![forbid(unsafe_code)]

pub mod p512;

pub use elliptic_curve;
