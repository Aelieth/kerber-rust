//! Gating tests: ACL allow/deny, AS/TGS issue, AP-REQ verify negatives.
//! Phase 5–8 protocol tests: kpasswd, FAST, SPAKE, PKINIT, PAC, S4U, U2U.
//!
//! These call shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry
//! points from a bootstrapped realm. They fail if those paths are type-only.

#[path = "common/mod.rs"]
mod common;
