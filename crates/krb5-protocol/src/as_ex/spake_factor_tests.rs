use super::spake::spake_contains_sf_none;
use krb5_types::OctetString;
use krb5_types::spake::{GROUP_P256, SF_NONE, SpakeChallenge, SpakeSecondFactor};

fn challenge(factor_types: &[i32]) -> SpakeChallenge {
    SpakeChallenge {
        group: GROUP_P256,
        pubkey: OctetString::from(vec![0u8; 33]),
        factors: factor_types
            .iter()
            .map(|&t| SpakeSecondFactor {
                factor_type: t,
                data: None,
            })
            .collect(),
    }
}

#[test]
fn sf_none_present_is_answerable() {
    assert!(spake_contains_sf_none(&challenge(&[SF_NONE])));
    assert!(spake_contains_sf_none(&challenge(&[7, SF_NONE, 9])));
}

#[test]
fn no_sf_none_is_refused() {
    // MIT: `process_challenge` (spake_client.c:221-221)
    // Returns KRB5KDC_ERR_PREAUTH_FAILED: no SF-NONE, or an empty list, offers nothing answerable.
    assert!(!spake_contains_sf_none(&challenge(&[])));
    assert!(!spake_contains_sf_none(&challenge(&[2, 7])));
}
