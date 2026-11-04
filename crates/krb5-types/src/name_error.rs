use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NameError {
    #[error("principal/realm bytes are not UTF-8")]
    NotUtf8,
    #[error("principal/realm is not a GeneralString")]
    NotGeneralString,
    #[error("empty principal component")]
    Empty,
    #[error("malformed principal name")]
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TimeError {
    #[error("microseconds {0} outside 0..=999999")]
    MicrosecondsOutOfRange(u32),
    #[error("KerberosTime addition overflow")]
    Overflow,
    #[error("invalid KerberosTime: {0}")]
    Parse(String),
}
