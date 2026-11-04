pub use super::BrainpoolP512t1;

pub type Signature = ecdsa::Signature<BrainpoolP512t1>;
pub type DerSignature = ecdsa::der::Signature<BrainpoolP512t1>;

impl ecdsa::EcdsaCurve for BrainpoolP512t1 {
    const NORMALIZE_S: bool = false;
}

impl ecdsa::DigestAlgorithm for BrainpoolP512t1 {
    type Digest = sha2::Sha512;
}
