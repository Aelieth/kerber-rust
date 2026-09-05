//! Fallible constructors for untrusted principal / realm bytes.

use thiserror::Error;

/// Failure to interpret bytes as a KerberosString / principal.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NameError {
    /// Input is not valid UTF-8.
    #[error("principal/realm bytes are not UTF-8")]
    NotUtf8,
    /// Input is outside the GeneralString / IA5 alphabet.
    #[error("principal/realm is not a GeneralString")]
    NotGeneralString,
    /// Empty name component or realm.
    #[error("empty principal component")]
    Empty,
    /// Trailing `\` or other `parse.c` malformation.
    #[error("malformed principal name")]
    Malformed,
}

/// Failure to represent a Kerberos time or microseconds value.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TimeError {
    /// Microseconds outside `0..=999999`.
    #[error("microseconds {0} outside 0..=999999")]
    MicrosecondsOutOfRange(u32),
    /// Adding a duration overflowed the calendar.
    #[error("KerberosTime addition overflow")]
    Overflow,
    /// Input is not `YYYYMMDDHHMMSSZ`.
    #[error("invalid KerberosTime: {0}")]
    Parse(String),
}
