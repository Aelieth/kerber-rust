#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

extern crate alloc;

mod dk;
mod error;
mod kdf;
mod nfold;
mod s2k;

pub use dk::dk_rfc3961;
pub use error::S2kError;
pub use kdf::{Sha2Kdf, kdf_hmac_sha2};
pub use nfold::nfold;
pub use s2k::{MAX_ITERATIONS, string_to_key, string_to_key_iter};
