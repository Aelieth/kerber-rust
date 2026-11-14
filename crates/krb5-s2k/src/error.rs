use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S2kError {
    UnsupportedEtype(i32),
    BadParams,
    InvalidKeyLength,
}

impl fmt::Display for S2kError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedEtype(n) => write!(f, "unsupported encryption type {n}"),
            Self::BadParams => write!(f, "invalid string-to-key parameters"),
            Self::InvalidKeyLength => write!(f, "protocol key length does not match etype"),
        }
    }
}

impl core::error::Error for S2kError {}
