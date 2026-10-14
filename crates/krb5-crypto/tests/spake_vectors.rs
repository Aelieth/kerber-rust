//! MIT 1.22.2's SPAKE test vectors (`plugins/preauth/spake/t_vectors.c`), run in both directions.
//!
//! MIT's `run_test` checks w, each side's K, the transcript hash and `K'[0..3]`; its keygen draws x
//! and y at random, so it never checks T and S. Here the KDC direction also makes T from x and the
//! client direction S from y. MIT's vectors 6, 7 and 9 are P-384 and P-521, which this port does
//! not implement.

use krb5_crypto::{
    EncryptionType, ProtocolKey, SpakeGroup, spake_derive_key, spake_public, spake_result,
    spake_thash_update, spake_wbytes,
};

/// One entry of MIT's `tests[]`.
struct Vector {
    /// The entry's position in MIT's `tests[]`, from 1.
    mit: usize,
    etype: EncryptionType,
    group: SpakeGroup,
    ikey: &'static str,
    w: &'static str,
    x: &'static str,
    y: &'static str,
    t: &'static str,
    s: &'static str,
    k: &'static str,
    /// `None` for an optimistic challenge: no support message is in the transcript.
    support: Option<&'static str>,
    challenge: &'static str,
    thash: &'static str,
    body: &'static str,
    k0: &'static str,
    k1: &'static str,
    k2: &'static str,
    k3: &'static str,
}

const VECTORS: &[Vector] = &[
    Vector {
        mit: 1,
        etype: EncryptionType::Des3CbcSha1,
        group: SpakeGroup::Edwards25519,
        ikey: "850bb51358548cd05e86768c313e3bfef7511937dcf72c3e",
        w: "686d84730cb8679ae95416c6567c6a63f2c9cef124f7a3371ae81e11cad42a37",
        x: "201012d07bfd48ddfa33c4aac4fb1e229fb0d043cfe65ebfb14399091c71a723",
        y: "500b294797b8b042aca1bedc0f5931a4f52c537b3608b2d05cc8a2372f439f25",
        t: "18f511e750c97b592acd30db7d9e5fca660389102e6bf610c1bfbed4616c8362",
        s: "5d10705e0d1e43d5dbf30240ccfbde4a0230c70d4c79147ab0b317edad2f8ae7",
        k: "25bde0d875f0feb5755f45ba5e857889d916ecf7476f116aa31dc3e037ec4292",
        support: Some("a0093007a0053003020101"),
        challenge: concat!(
            "a1363034a003020101a122042018f511e750c97b592acd30db7d9e5fca660389",
            "102e6bf610c1bfbed4616c8362a20930073005a003020101"
        ),
        thash: "eaaa08807d0616026ff51c849efbf35ba0ce3c5300e7d486da46351b13d4605b",
        body: concat!(
            "3075a00703050000000000a1143012a003020101a10b30091b07726165627572",
            "6ea2101b0e415448454e412e4d49542e454455a3233021a003020102a11a3018",
            "1b066b72627467741b0e415448454e412e4d49542e454455a511180f31393730",
            "303130313030303030305aa703020100a8053003020110"
        ),
        k0: "baf12fae7cd958cbf1a29bfbc71f89ce49e03e295d89dafd",
        k1: "64f73dd9c41908206bcec1f719026b574f9d13463d7a2520",
        k2: "0454520b086b152c455829e6baeff78a61dfe9e3d04a895d",
        k3: "4a92260b25e3ef94c125d5c24c3e5bced5b37976e67f25c4",
    },
    Vector {
        mit: 2,
        etype: EncryptionType::Rc4Hmac,
        group: SpakeGroup::Edwards25519,
        ikey: "8846f7eaee8fb117ad06bdd830b7586c",
        w: "7c86659d29cf2b2ea93bfe79c3cefb8850e82215b3ea6fcd896561d48048f49c",
        x: "c8a62e7b626f44cad807b2d695450697e020d230a738c5cd5691cc781dce8754",
        y: "18fe7c1512708c7fd06db270361f04593775bc634ceaf45347e5c11c38aae017",
        t: "7db465f1c08c64983a19f560bce966fe5306c4b447f70a5bca14612a92da1d63",
        s: "38f8d4568090148ebc9fd17c241b4cc2769505a7ca6f3f7104417b72b5b5cf54",
        k: "03e75edd2cd7e7677642dd68736e91700953ac55dc650e3c2a1b3b4acdb800f8",
        support: Some("a0093007a0053003020101"),
        challenge: concat!(
            "a1363034a003020101a12204207db465f1c08c64983a19f560bce966fe5306c4",
            "b447f70a5bca14612a92da1d63a20930073005a003020101"
        ),
        thash: "f4b208458017de6ef7f6a307d47d87db6c2af1d291b726860f68bc08bfef440a",
        body: concat!(
            "3075a00703050000000000a1143012a003020101a10b30091b07726165627572",
            "6ea2101b0e415448454e412e4d49542e454455a3233021a003020102a11a3018",
            "1b066b72627467741b0e415448454e412e4d49542e454455a511180f31393730",
            "303130313030303030305aa703020100a8053003020117"
        ),
        k0: "770b720c82384cbb693e85411eedecba",
        k1: "621deec88e2865837c4d3462bb50a1d5",
        k2: "1cc8f6333b9fa3b42662fd9914fbd5bb",
        k3: "edb4032b7fc3806d5211a534dcbc390c",
    },
    Vector {
        mit: 3,
        etype: EncryptionType::Aes128CtsHmacSha196,
        group: SpakeGroup::Edwards25519,
        ikey: "fca822951813fb252154c883f5ee1cf4",
        w: "0d591b197b667e083c2f5f98ac891d3c9f99e710e464e62f1fb7c9b67936f3eb",
        x: "50be049a5a570fa1459fb9f666e6fd80602e4e87790a0e567f12438a2c96c138",
        y: "b877afe8612b406d96be85bd9f19d423e95be96c0e1e0b5824127195c3ed5917",
        t: "9e9311d985c1355e022d7c3c694ad8d6f7ad6d647b68a90b0fe46992818002da",
        s: "fbe08f7f96cd5d4139e7c9eccb95e79b8ace41e270a60198c007df18525b628e",
        k: "c2f7f99997c585e6b686ceb62db42f17cc70932def3bb4cf009e36f22ea5473d",
        support: Some("a0093007a0053003020101"),
        challenge: concat!(
            "a1363034a003020101a12204209e9311d985c1355e022d7c3c694ad8d6f7ad6d",
            "647b68a90b0fe46992818002daa20930073005a003020101"
        ),
        thash: "951285f107c87f0169b9c918a1f51f60cb1a75b9f8bb799a99f53d03add94b5f",
        body: concat!(
            "3075a00703050000000000a1143012a003020101a10b30091b07726165627572",
            "6ea2101b0e415448454e412e4d49542e454455a3233021a003020102a11a3018",
            "1b066b72627467741b0e415448454e412e4d49542e454455a511180f31393730",
            "303130313030303030305aa703020100a8053003020111"
        ),
        k0: "548022d58a7c47eae8c49dccf6baa407",
        k1: "b2c9ba0e13fc8ab3a9d96b51b601cf4a",
        k2: "69f0ee5fdb6c237e7fcd38d9f87df1bd",
        k3: "78f91e2240b5ee528a5cc8d7cbebfba5",
    },
    Vector {
        mit: 4,
        etype: EncryptionType::Aes256CtsHmacSha196,
        group: SpakeGroup::Edwards25519,
        ikey: "01b897121d933ab44b47eb5494db15e50eb74530dbdae9b634d65020ff5d88c1",
        w: "e902341590a1b4bb4d606a1c643cccb3f2108f1b6aa97b381012b9400c9e3f4e",
        x: "88c6c0a4f0241ef217c9788f02c32d00b72e4310748cd8fb5f94717607e6417d",
        y: "88b859df58ef5c69bacdfe681c582754eaab09a74dc29cff50b328613c232f55",
        t: "6f301aacae1220e91be42868c163c5009aeea1e9d9e28afcfc339cda5e7105b5",
        s: "9e2cc32908fc46273279ec75354b4aeafa70c3d99a4d507175ed70d80b255dda",
        k: "cf57f58f6e60169d2ecc8f20bb923a8e4c16e5bc95b9e64b5dc870da7026321b",
        support: Some("a0093007a0053003020101"),
        challenge: concat!(
            "a1363034a003020101a12204206f301aacae1220e91be42868c163c5009aeea1",
            "e9d9e28afcfc339cda5e7105b5a20930073005a003020101"
        ),
        thash: "1c605649d4658b58cbe79a5faf227acc16c355c58b7dade022f90c158fe5ed8e",
        body: concat!(
            "3075a00703050000000000a1143012a003020101a10b30091b07726165627572",
            "6ea2101b0e415448454e412e4d49542e454455a3233021a003020102a11a3018",
            "1b066b72627467741b0e415448454e412e4d49542e454455a511180f31393730",
            "303130313030303030305aa703020100a8053003020112"
        ),
        k0: "a9bfa71c95c575756f922871524b65288b3f695573ccc0633e87449568210c23",
        k1: "1865a9ee1ef0640ec28ac007391cac624c42639c714767a974e99aa10003015f",
        k2: "e57781513fefdb978e374e156b0da0c1a08148f5eb26b8e157ac3c077e28bf49",
        k3: "008e6487293c3cc9fabbbcdd8b392d6dcb88222317fd7fe52d12fbc44fa047f1",
    },
    Vector {
        mit: 5,
        etype: EncryptionType::Aes256CtsHmacSha196,
        group: SpakeGroup::P256,
        ikey: "01b897121d933ab44b47eb5494db15e50eb74530dbdae9b634d65020ff5d88c1",
        w: "eb2984af18703f94dd5288b8596cd36988d0d4e83bfb2b44de14d0e95e2090bd",
        x: "935ddd725129fb7c6288e1a5cc45782198a6416d1775336d71eacd0549a3e80e",
        y: "e07405eb215663abc1f254b8adc0da7a16febaa011af923d79fdef7c42930b33",
        t: "024f62078ceb53840d02612195494d0d0d88de21feeb81187c71cbf3d01e71788d",
        s: "021d07dc31266fc7cfd904ce2632111a169b7ec730e5f74a7e79700f86638e13c8",
        k: "0268489d7a9983f2fde69c6e6a1307e9d252259264f5f2dfc32f58cca19671e79b",
        support: Some("a0093007a0053003020102"),
        challenge: concat!(
            "a1373035a003020102a1230421024f62078ceb53840d02612195494d0d0d88de",
            "21feeb81187c71cbf3d01e71788da20930073005a003020101"
        ),
        thash: "20ad3c1a9a90fc037d1963a1c4bfb15ab4484d7b6cf07b12d24984f14652de60",
        body: concat!(
            "3075a00703050000000000a1143012a003020101a10b30091b07726165627572",
            "6ea2101b0e415448454e412e4d49542e454455a3233021a003020102a11a3018",
            "1b066b72627467741b0e415448454e412e4d49542e454455a511180f31393730",
            "303130313030303030305aa703020100a8053003020112"
        ),
        k0: "7d3b906f7be49932db22cd3463f032d06c9c078be4b1d076d201fc6e61ef531e",
        k1: "17d74e36f8993841fbb7feb12fa4f011243d3ae4d2ace55b39379294bbc4db2c",
        k2: "d192c9044081a2aa6a97a6c69e2724e8e5671c2c9ce073dd439cdbaf96d7dab0",
        k3: "41e5bad6b67f12c53ce0e2720dd6a9887f877bf9463c2d5209c74c36f8d776b7",
    },
    // MIT vector 6 (SPAKE_GROUP_P384) is not run: the group is not implemented.
    // MIT vector 7 (SPAKE_GROUP_P521) is not run: the group is not implemented.
    Vector {
        mit: 8,
        etype: EncryptionType::Aes256CtsHmacSha196,
        group: SpakeGroup::Edwards25519,
        ikey: "01b897121d933ab44b47eb5494db15e50eb74530dbdae9b634d65020ff5d88c1",
        w: "e902341590a1b4bb4d606a1c643cccb3f2108f1b6aa97b381012b9400c9e3f4e",
        x: "70937207344cafbc53c8a55070e399c584cbafce00b836980dd4e7e74fad2a64",
        y: "785d6801a2490df028903ac6449b105f2ff0db895b252953cdc2076649526103",
        t: "83523b35f1565006cbfc4f159885467c2fb9bc6fe23d36cb1da43d199f1a3118",
        s: "2a8f70f46cee9030700037b77f22cec7970dcc238e3e066d9d726baf183992c6",
        k: "d3c5e4266aa6d1b2873a97ce8af91c7e4d7a7ac456acced7908d34c561ad8fa6",
        support: None,
        challenge: concat!(
            "a1363034a003020101a122042083523b35f1565006cbfc4f159885467c2fb9bc",
            "6fe23d36cb1da43d199f1a3118a20930073005a003020101"
        ),
        thash: "26f07f9f8965307434d11ea855461d41e0cbabcc0a1bab48ecee0c6c1a4292b7",
        body: concat!(
            "3075a00703050000000000a1143012a003020101a10b30091b07726165627572",
            "6ea2101b0e415448454e412e4d49542e454455a3233021a003020102a11a3018",
            "1b066b72627467741b0e415448454e412e4d49542e454455a511180f31393730",
            "303130313030303030305aa703020100a8053003020112"
        ),
        k0: "4569ec08b5de5c3cc19d941725913ace8d74524b521a341dc746acd5c3784d92",
        k1: "0d96ce1a4ac0f2e280a0cfc31742b06461d83d04ae45433db2d80478dd882a4c",
        k2: "58018c19315a1ba5d5bb9813b58029f0aec18a6f9ca59e0847de1c60bc25945c",
        k3: "ed7e9bffd68c54d86fb19cd3c03f317f88a71ad9a5e94c28581d93fc4ec72b6a",
    },
    // MIT vector 9 (SPAKE_GROUP_P521) is not run: the group is not implemented.
];

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// One side of MIT's `run_test`: w, this side's public element from its private scalar, K from
/// the other side's element, the transcript hash, and `K'[0..3]`.
fn check(v: &Vector, kdc: bool) {
    let side = if kdc { "KDC" } else { "client" };
    let ikey = ProtocolKey::from_bytes(v.etype, &hex(v.ikey)).unwrap();
    let w = spake_wbytes(&ikey, v.group).unwrap();
    assert_eq!(w.as_slice(), hex(v.w), "vector {}: w", v.mit);
    let (private, ours, theirs) = if kdc {
        (v.x, v.t, v.s)
    } else {
        (v.y, v.s, v.t)
    };
    assert_eq!(
        spake_public(v.group, &w, &hex(private), kdc).unwrap(),
        hex(ours),
        "vector {}: the {side}'s public element",
        v.mit
    );
    let k = spake_result(v.group, &w, &hex(private), &hex(theirs), kdc).unwrap();
    assert_eq!(k.as_slice(), hex(v.k), "vector {}: the {side}'s K", v.mit);
    let support = v.support.map(hex).unwrap_or_default();
    let thash = spake_thash_update(v.group, &[], &support, &hex(v.challenge));
    let thash = spake_thash_update(v.group, &thash, &hex(v.s), &[]);
    assert_eq!(thash, hex(v.thash), "vector {}: transcript hash", v.mit);
    for (n, want) in (0u32..).zip([v.k0, v.k1, v.k2, v.k3]) {
        let key = spake_derive_key(&ikey, v.group, &w, &k, &thash, &hex(v.body), n).unwrap();
        assert_eq!(key.etype(), v.etype);
        assert_eq!(key.as_bytes(), hex(want), "vector {}: K'[{n}]", v.mit);
    }
}

#[test]
fn mit_vectors_from_the_kdc_side() {
    for v in VECTORS {
        check(v, true);
    }
}

#[test]
fn mit_vectors_from_the_client_side() {
    for v in VECTORS {
        check(v, false);
    }
}

#[test]
fn the_vectors_run_cover_both_groups_four_enctypes_and_an_optimistic_challenge() {
    let mits: Vec<usize> = VECTORS.iter().map(|v| v.mit).collect();
    assert_eq!(mits, [1, 2, 3, 4, 5, 8]);
    for group in SpakeGroup::ALL {
        assert!(VECTORS.iter().any(|v| v.group == group), "{group:?}");
    }
    for etype in [
        EncryptionType::Des3CbcSha1,
        EncryptionType::Rc4Hmac,
        EncryptionType::Aes128CtsHmacSha196,
        EncryptionType::Aes256CtsHmacSha196,
    ] {
        assert!(VECTORS.iter().any(|v| v.etype == etype), "{etype:?}");
    }
    assert!(VECTORS.iter().any(|v| v.support.is_none()));
}
