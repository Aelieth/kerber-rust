//! PKINIT's key exchange as MIT's: the `pkinit_constants.c` groups, each weighed as a finite
//! field.

use crypto_bigint::modular::{FixedMontyForm, FixedMontyParams};
use crypto_bigint::{Encoding, Odd, U1024, U2048, U4096, Uint};
use zeroize::Zeroizing;

use super::cms::{OID_P256_CURVE, OID_P384_CURVE, OID_P521_CURVE};
use super::{OID_DHPUBLICNUMBER, der_unsigned, oid_der, strip_leading_zeros, take_tlv, tlv};

const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const P1024: U1024 = U1024::from_be_hex(
    "\
    FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
    020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
    4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
    EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
);
const P2048: U2048 = U2048::from_be_hex(
    "\
    FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
    020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
    4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
    EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05\
    98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB\
    9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
    E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
    3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
);
const P4096: U4096 = U4096::from_be_hex(
    "\
    FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
    020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
    4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
    EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05\
    98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB\
    9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
    E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
    3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33\
    A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7\
    ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864\
    D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2\
    08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7\
    88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8\
    DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2\
    233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9\
    93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KxGroup {
    P256,
    P384,
    P521,
    Modp2048,
    Modp4096,
    Modp1024,
}

impl KxGroup {
    #[cfg(p384_backend = "fiat")]
    pub const ALL: [Self; 6] = [
        Self::P256,
        Self::P384,
        Self::P521,
        Self::Modp2048,
        Self::Modp4096,
        Self::Modp1024,
    ];
    #[cfg(not(p384_backend = "fiat"))]
    pub const ALL: [Self; 5] = [
        Self::P256,
        Self::P521,
        Self::Modp2048,
        Self::Modp4096,
        Self::Modp1024,
    ];

    // MIT check_dh_wellknown; see docs/parity/a3-preauth.md
    #[must_use]
    pub const fn bits(self) -> u32 {
        match self {
            Self::P256 => 3072,
            Self::P384 => 7680,
            Self::P521 => 15360,
            Self::Modp2048 => 2048,
            Self::Modp4096 => 4096,
            Self::Modp1024 => 1024,
        }
    }

    #[must_use]
    pub const fn desc(self) -> &'static str {
        match self {
            Self::P256 => "P-256",
            Self::P384 => "P-384",
            Self::P521 => "P-521",
            Self::Modp2048 => "2048-bit DH",
            Self::Modp4096 => "4096-bit DH",
            Self::Modp1024 => "1024-bit DH",
        }
    }

    #[must_use]
    pub fn for_bits(bits: u32) -> Option<Self> {
        Self::ALL.into_iter().find(|g| g.bits() == bits)
    }

    /// dhpublicnumber with `DomainParameters` `{p, 2, (p - 1) / 2}`, or id-ecPublicKey and the curve.
    #[must_use]
    pub fn algorithm_identifier(self) -> Vec<u8> {
        let (oid, params) = match self {
            Self::P256 => (OID_EC_PUBLIC_KEY, oid_der(OID_P256_CURVE)),
            Self::P384 => (OID_EC_PUBLIC_KEY, oid_der(OID_P384_CURVE)),
            Self::P521 => (OID_EC_PUBLIC_KEY, oid_der(OID_P521_CURVE)),
            Self::Modp2048 | Self::Modp4096 | Self::Modp1024 => {
                let prime = self.prime();
                let ints = [
                    der_unsigned(&prime),
                    der_unsigned(&[2]),
                    der_unsigned(&half(&prime)),
                ];
                (OID_DHPUBLICNUMBER, tlv(0x30, &ints.concat()))
            }
        };
        tlv(0x30, &[oid_der(oid), params].concat())
    }

    fn from_algorithm(oid: &[u8], params: &[u8]) -> Option<Self> {
        if oid == OID_EC_PUBLIC_KEY {
            return match take_tlv(params)? {
                (0x06, OID_P256_CURVE, _) => Some(Self::P256),
                #[cfg(p384_backend = "fiat")]
                (0x06, OID_P384_CURVE, _) => Some(Self::P384),
                #[cfg(not(p384_backend = "fiat"))]
                (0x06, OID_P384_CURVE, _) => None,
                (0x06, OID_P521_CURVE, _) => Some(Self::P521),
                _ => None,
            };
        }
        if oid != OID_DHPUBLICNUMBER {
            return None;
        }
        let (0x30, body, _) = take_tlv(params)? else {
            return None;
        };
        let mut ints = Vec::new();
        let mut rest = body;
        while ints.len() < 3 {
            let (0x02, int, next) = take_tlv(rest)? else {
                return None;
            };
            ints.push(strip_leading_zeros(int));
            rest = next;
        }
        [Self::Modp2048, Self::Modp4096, Self::Modp1024]
            .into_iter()
            .find(|grp| {
                let prime = grp.prime();
                ints[1] == [2] && ints[2] == half(&prime) && ints[0] == prime
            })
    }

    fn prime(self) -> Vec<u8> {
        match self {
            Self::Modp4096 => P4096.to_be_bytes().to_vec(),
            Self::Modp1024 => P1024.to_be_bytes().to_vec(),
            _ => P2048.to_be_bytes().to_vec(),
        }
    }
}

// MIT decode_spki; see docs/parity/a3-preauth.md
#[must_use]
pub fn decode_spki(spki: &[u8]) -> Option<(Option<KxGroup>, Vec<u8>)> {
    let (0x30, body, _) = take_tlv(spki)? else {
        return None;
    };
    let (0x30, alg, rest) = take_tlv(body)? else {
        return None;
    };
    let (0x03, bits, _) = take_tlv(rest)? else {
        return None;
    };
    let (0x06, oid, params) = take_tlv(alg)? else {
        return None;
    };
    let public = bits.strip_prefix(&[0])?.to_vec();
    let group = KxGroup::from_algorithm(oid, params);
    let decodes = match group {
        Some(KxGroup::P256) => p256::PublicKey::from_sec1_bytes(&public).is_ok(),
        #[cfg(p384_backend = "fiat")]
        Some(KxGroup::P384) => p384::PublicKey::from_sec1_bytes(&public).is_ok(),
        #[cfg(not(p384_backend = "fiat"))]
        Some(KxGroup::P384) => false,
        Some(KxGroup::P521) => p521::PublicKey::from_sec1_bytes(&public).is_ok(),
        Some(KxGroup::Modp2048 | KxGroup::Modp4096 | KxGroup::Modp1024) => {
            matches!(take_tlv(&public), Some((0x02, _, rest)) if rest.is_empty())
        }
        None => true,
    };
    decodes.then_some((group, public))
}

// MIT pkinit_create_td_dh_parameters; see docs/parity/a3-preauth.md
#[must_use]
pub fn encode_td_dh_parameters(min_bits: u32) -> Vec<u8> {
    let algs: Vec<u8> = KxGroup::ALL
        .into_iter()
        .filter(|g| g.bits() >= min_bits)
        .flat_map(KxGroup::algorithm_identifier)
        .collect();
    tlv(0x30, &algs)
}

// MIT pkinit_process_td_dh_params; see docs/parity/a3-preauth.md
#[must_use]
pub fn choose_td_group(td: &[u8], min_bits: u32) -> Option<Option<KxGroup>> {
    let (0x30, mut list, _) = take_tlv(td)? else {
        return None;
    };
    let mut algs = Vec::new();
    while !list.is_empty() {
        let (0x30, alg, rest) = take_tlv(list)? else {
            return None;
        };
        let (0x06, oid, params) = take_tlv(alg)? else {
            return None;
        };
        algs.push((oid, params));
        list = rest;
    }
    Some(
        algs.into_iter()
            .filter_map(|(oid, params)| KxGroup::from_algorithm(oid, params))
            .find(|g| g.bits() >= min_bits),
    )
}

// MIT group_desc; see docs/parity/a3-preauth.md
#[must_use]
pub fn group_desc(bits: u32) -> &'static str {
    KxGroup::for_bits(bits).map_or("(unknown)", KxGroup::desc)
}

fn half(n: &[u8]) -> Vec<u8> {
    let mut carry = 0u8;
    let out: Vec<u8> = n
        .iter()
        .map(|&b| {
            let v = (b >> 1) | carry;
            carry = b << 7;
            v
        })
        .collect();
    strip_leading_zeros(&out)
}

// MIT parse_dh_min_bits; see docs/parity/a3-preauth.md
pub fn parse_dh_min_bits(value: Option<&str>) -> Result<u32, String> {
    let Some(s) = value else {
        return Ok(2048);
    };
    match strtol(s) {
        None if s.eq_ignore_ascii_case("P-256") => Ok(3072),
        None if s.eq_ignore_ascii_case("P-384") => Ok(7680),
        None if s.eq_ignore_ascii_case("P-521") => Ok(15360),
        Some(1024) => Ok(1024),
        Some(n) if (1025..=2048).contains(&n) => Ok(2048),
        Some(n) if (2049..=4096).contains(&n) => Ok(4096),
        _ => Err(s.to_owned()),
    }
}

/// C's `strtol(s, &end, 0)`, `None` where it reads no digit.
fn strtol(s: &str) -> Option<i64> {
    let t = s.trim_start_matches([' ', '\t', '\n', '\x0b', '\x0c', '\r']);
    let (neg, t) = match t.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let hex = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .filter(|h| h.starts_with(|c: char| c.is_ascii_hexdigit()));
    let (radix, digits) = match hex {
        Some(h) => (16, h),
        None if t.starts_with('0') => (8, t),
        None => (10, t),
    };
    let run: String = digits.chars().take_while(|c| c.is_digit(radix)).collect();
    if run.is_empty() {
        return None;
    }
    let n = i64::from_str_radix(&run, radix).unwrap_or(i64::MAX);
    Some(if neg { n.saturating_neg() } else { n })
}

/// One exchange's key: the secret, and the public value as its BIT STRING carries it.
pub struct KxKey {
    pub group: KxGroup,
    secret: Zeroizing<Vec<u8>>,
    public: Vec<u8>,
}

macro_rules! ec_public {
    ($c:ident, $secret:expr) => {{
        use $c::elliptic_curve::sec1::ToSec1Point;
        let sk = $c::SecretKey::from_slice($secret).ok()?;
        sk.public_key().to_sec1_point(false).as_bytes().to_vec()
    }};
}

macro_rules! ec_shared {
    ($c:ident, $secret:expr, $peer:expr) => {{
        use $c::elliptic_curve::sec1::ToSec1Point;
        let d = $c::SecretKey::from_slice($secret).ok()?;
        let q = $c::PublicKey::from_sec1_bytes($peer).ok()?;
        let z = (q.to_projective() * *d.to_nonzero_scalar()).to_affine();
        Some(Zeroizing::new(z.to_sec1_point(false).x()?.to_vec()))
    }};
}

impl KxKey {
    #[must_use]
    pub fn generate(group: KxGroup) -> Option<Self> {
        let (len, mask) = match group {
            KxGroup::P256 | KxGroup::Modp2048 | KxGroup::Modp1024 => (32, 0xff),
            KxGroup::P384 | KxGroup::Modp4096 => (48, 0xff),
            KxGroup::P521 => (66, 0x01),
        };
        for _ in 0..8 {
            let mut secret = Zeroizing::new(vec![0u8; len]);
            getrandom::getrandom(&mut secret).ok()?;
            secret[0] &= mask;
            if let Some(key) = Self::from_secret(group, &secret) {
                return Some(key);
            }
        }
        None
    }

    /// The key of a known secret: an exponent, or a scalar the size of the curve's field.
    #[must_use]
    pub fn from_secret(group: KxGroup, secret: &[u8]) -> Option<Self> {
        let public = match group {
            KxGroup::P256 => ec_public!(p256, secret),
            #[cfg(p384_backend = "fiat")]
            KxGroup::P384 => ec_public!(p384, secret),
            #[cfg(not(p384_backend = "fiat"))]
            KxGroup::P384 => return None,
            KxGroup::P521 => ec_public!(p521, secret),
            KxGroup::Modp2048 | KxGroup::Modp4096 | KxGroup::Modp1024 => {
                der_unsigned(&modp_pow(group, &[2], secret)?)
            }
        };
        Some(Self {
            group,
            secret: Zeroizing::new(secret.to_vec()),
            public,
        })
    }

    #[must_use]
    pub fn public(&self) -> &[u8] {
        &self.public
    }

    #[must_use]
    pub fn spki(&self) -> Vec<u8> {
        let bits = tlv(0x03, &[&[0u8][..], &self.public].concat());
        tlv(0x30, &[self.group.algorithm_identifier(), bits].concat())
    }

    // MIT dh_result; see docs/parity/a3-preauth.md
    #[must_use]
    pub fn shared(&self, peer: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        match self.group {
            KxGroup::P256 => ec_shared!(p256, &self.secret, peer),
            #[cfg(p384_backend = "fiat")]
            KxGroup::P384 => ec_shared!(p384, &self.secret, peer),
            #[cfg(not(p384_backend = "fiat"))]
            KxGroup::P384 => None,
            KxGroup::P521 => ec_shared!(p521, &self.secret, peer),
            KxGroup::Modp2048 | KxGroup::Modp4096 | KxGroup::Modp1024 => {
                let (0x02, y, _) = take_tlv(peer)? else {
                    return None;
                };
                let y = strip_leading_zeros(y);
                let mut top = self.group.prime();
                *top.last_mut()? -= 1;
                let below = |a: &[u8], b: &[u8]| (a.len(), a) < (b.len(), b);
                (below(&[1], &y) && below(&y, &top)).then_some(())?;
                modp_pow(self.group, &y, &self.secret)
            }
        }
    }
}

/// `base^exp mod p`, constant time in `exp`, padded to the modulus.
fn modp_pow(group: KxGroup, base: &[u8], exp: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    match group {
        KxGroup::Modp4096 => pow_at(&P4096, base, exp),
        KxGroup::Modp1024 => pow_at(&P1024, base, exp),
        _ => pow_at(&P2048, base, exp),
    }
}

fn pow_at<const L: usize>(modulus: &Uint<L>, base: &[u8], exp: &[u8]) -> Option<Zeroizing<Vec<u8>>>
where
    Uint<L>: Encoding,
{
    let params = FixedMontyParams::new(Odd::new(*modulus).into_option()?);
    let b = Zeroizing::new(FixedMontyForm::new(
        &Zeroizing::new(uint::<L>(base)?),
        &params,
    ));
    let x = Zeroizing::new(uint::<L>(exp)?);
    let bits = u32::try_from(exp.len().checked_mul(8)?).ok()?;
    let out = Zeroizing::new(b.pow_bounded_exp(&x, bits).retrieve());
    Some(Zeroizing::new(out.to_be_bytes().as_ref().to_vec()))
}

fn uint<const L: usize>(v: &[u8]) -> Option<Uint<L>> {
    let mut buf = Zeroizing::new(vec![0u8; L * 8]);
    let start = buf.len().checked_sub(v.len())?;
    buf[start..].copy_from_slice(v);
    Some(Uint::from_be_slice(&buf))
}
