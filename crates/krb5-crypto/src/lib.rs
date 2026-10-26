// MIT: `KRB5_CONF_ALLOW_WEAK_CRYPTO` (include/k5-int.h:185-185)
// MIT: `krb5int_enctypes_list` (lib/crypto/krb/etypes.c:36-149)

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod cf2;
mod derive;
mod error;
mod etype;
mod key;
mod nfold;
mod ops;
mod prf;
mod spake;
pub(crate) mod weak;
mod wipe;

pub(crate) mod cts;

pub use cf2::{
    P256Keypair, krb_fx_cf2, octetstring2key, p256_ecdsa_sign, p256_ecdsa_verify, p256_generate,
    p256_shared, pkinit_kdf_agile,
};
pub use derive::{DerivedKeys, derive_keys};
pub use error::Error;
pub use etype::{
    EncryptionType, KeyUsage, cksumtype_is_coll_proof, cksumtype_is_keyed, cksumtype_is_known,
    cksumtype_is_unkeyed, default_enctype_list, parse_enctype_list, parse_keysalt_list,
};
pub use key::ProtocolKey;
pub use ops::{
    CipherState, ENCTYPE_UNKNOWN, check_enc_data_etype, checksum, checksum_output_size, decrypt,
    decrypt_cts, decrypt_enc_data, decrypt_enc_data_with_state, decrypt_with_state, encrypt,
    encrypt_with_confounder, encrypt_with_confounder_and_state, encrypt_with_state,
    hmac_md5_arcfour_checksum, integrity_mac, kdb_decrypt_key, kdb_encrypt_key, string_to_key,
    unkeyed_checksum, verify_checksum_collproof, verify_checksum_keyed, verify_checksum_type,
};
pub use prf::{derive_prfplus, derive_prfplus_enctype, prf, prf_plus};
pub use spake::{
    SPAKE_DEFAULT_GROUPS_CLIENT, SPAKE_DEFAULT_GROUPS_KDC, SpakeGroup, spake_decode_point,
    spake_derive_key, spake_group_words, spake_keygen, spake_parse_groups, spake_public,
    spake_result, spake_thash_update, spake_wbytes,
};
