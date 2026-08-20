//! Kerberos V5 AS and TGS exchanges (RFC 4120).
//!
//! Transport is UDP with TCP fallback. Preauthentication uses
//! PA-ENC-TIMESTAMP and ETYPE-INFO2. There is no C FFI.

#![forbid(unsafe_code)]

mod as_ex;
mod error;
mod tgs;
mod transport;

pub use as_ex::{as_exchange, AsOutcome, AsRequest};
pub use error::Error;
pub use tgs::{tgs_exchange, TgsOutcome};
pub use transport::{exchange, KdcAddr, KDC_PORT};
