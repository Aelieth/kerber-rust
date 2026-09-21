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
    // MIT contains_sf_none returns TRUE, so the client proceeds.
    assert!(spake_contains_sf_none(&challenge(&[SF_NONE])));
    // ... even when other factor types sit alongside it.
    assert!(spake_contains_sf_none(&challenge(&[7, SF_NONE, 9])));
}

#[test]
fn no_sf_none_is_refused() {
    // MIT spake_client.c:221 returns KRB5KDC_ERR_PREAUTH_FAILED: a factor
    // list without SF-NONE (or an empty one) offers nothing we can answer.
    assert!(!spake_contains_sf_none(&challenge(&[])));
    assert!(!spake_contains_sf_none(&challenge(&[2, 7])));
}
