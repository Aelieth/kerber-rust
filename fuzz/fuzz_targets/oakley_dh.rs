#![no_main]
use std::sync::OnceLock;

use krb5_types::pkinit::{KxGroup, KxKey, decode_spki};
use libfuzzer_sys::fuzz_target;

static KEYS: OnceLock<Vec<KxKey>> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let keys = KEYS.get_or_init(|| {
        KxGroup::ALL
            .into_iter()
            .filter_map(|g| {
                let len = match g {
                    KxGroup::P256 | KxGroup::Modp2048 | KxGroup::Modp1024 => 32,
                    KxGroup::P384 | KxGroup::Modp4096 => 48,
                    KxGroup::P521 => 66,
                };
                KxKey::from_secret(g, &[1; 66][..len])
            })
            .collect()
    });
    let _ = decode_spki(data);
    if let Some((&pick, peer)) = data.split_first()
        && let Some(key) = keys.get(usize::from(pick) % keys.len().max(1))
    {
        let _ = key.shared(peer);
    }
});
