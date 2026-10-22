pub use super::BrainpoolP512r1;

pub type Signature = ecdsa::Signature<BrainpoolP512r1>;
pub type DerSignature = ecdsa::der::Signature<BrainpoolP512r1>;

impl ecdsa::EcdsaCurve for BrainpoolP512r1 {
    const NORMALIZE_S: bool = false;
}

#[cfg(feature = "digest")]
impl ecdsa::DigestAlgorithm for BrainpoolP512r1 {
    type Digest = sha2::Sha512;
}
