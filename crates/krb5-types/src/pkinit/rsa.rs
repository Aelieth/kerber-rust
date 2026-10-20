//! RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017 §8.2.1): time depends on the key's lengths, not its
//! values (crypto-bigint); the message is blinded, the signature checked before it is returned.

use crypto_bigint::ctutils::CtEq;
use crypto_bigint::modular::{FixedMontyForm, FixedMontyParams};
use crypto_bigint::{
    NonZero, Odd, U512, U1024, U1536, U2048, U3072, U4096, U6144, U8192, U16384, Uint,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use super::take_tlv;

pub(super) const OID_RSA_ENCRYPTION: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

const SHA256_INFO: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

const MAX_PRIMES: usize = 5;

#[derive(Clone)]
struct Prime {
    r: Zeroizing<Vec<u8>>,
    d: Zeroizing<Vec<u8>>,
    t: Zeroizing<Vec<u8>>,
}

#[derive(Clone)]
pub struct RsaKey {
    n: Vec<u8>,
    e: Vec<u8>,
    d: Zeroizing<Vec<u8>>,
    primes: Vec<Prime>,
}

impl std::fmt::Debug for RsaKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RsaKey({} bits, {} primes)",
            self.n.len() * 8,
            self.primes.len()
        )
    }
}

impl Zeroize for RsaKey {
    fn zeroize(&mut self) {
        self.d.zeroize();
        for p in &mut self.primes {
            p.r.zeroize();
            p.d.zeroize();
            p.t.zeroize();
        }
    }
}

impl RsaKey {
    #[must_use]
    pub fn from_pkcs1(der: &[u8]) -> Option<Self> {
        let (0x30, mut rest, _) = take_tlv(der)? else {
            return None;
        };
        let mut ints = Vec::new();
        let mut others = None;
        while !rest.is_empty() {
            let (t, v, next) = take_tlv(rest)?;
            match t {
                0x02 if others.is_none() => ints.push(v),
                0x30 if others.is_none() && ints.len() == 9 => others = Some(v),
                _ => return None,
            }
            rest = next;
        }
        let [version, n, e, d, p, q, dp, dq, qinv] = ints[..] else {
            return None;
        };
        let secret = |v: &[u8]| Zeroizing::new(unsigned(v).to_vec());
        let prime = |r: &[u8], d: &[u8], t: &[u8]| Prime {
            r: secret(r),
            d: secret(d),
            t: secret(t),
        };
        let mut primes = vec![prime(p, dp, &[]), prime(q, dq, qinv)];
        match (version, others) {
            ([0], _) => {}
            ([1], Some(mut seq)) if !seq.is_empty() => {
                while !seq.is_empty() {
                    let (0x30, info, next) = take_tlv(seq)? else {
                        return None;
                    };
                    let (0x02, r, info) = take_tlv(info)? else {
                        return None;
                    };
                    let (0x02, d, info) = take_tlv(info)? else {
                        return None;
                    };
                    let (0x02, t, _) = take_tlv(info)? else {
                        return None;
                    };
                    primes.push(prime(r, d, t));
                    seq = next;
                }
            }
            _ => return None,
        }
        Some(Self {
            n: unsigned(n).to_vec(),
            e: unsigned(e).to_vec(),
            d: secret(d),
            primes,
        })
    }

    #[must_use]
    pub fn from_pkcs8(der: &[u8]) -> Option<Self> {
        let (0x30, info, _) = take_tlv(der)? else {
            return None;
        };
        let (0x02, _, rest) = take_tlv(info)? else {
            return None;
        };
        let (0x30, alg, rest) = take_tlv(rest)? else {
            return None;
        };
        let (0x06, oid, _) = take_tlv(alg)? else {
            return None;
        };
        let (0x04, key, _) = take_tlv(rest)? else {
            return None;
        };
        (oid == OID_RSA_ENCRYPTION).then(|| Self::from_pkcs1(key))?
    }

    #[must_use]
    pub fn sign_sha256(&self, msg: &[u8]) -> Option<Vec<u8>> {
        let k = self.n.len();
        let hash = Sha256::digest(msg);
        let t = k.checked_sub(SHA256_INFO.len() + hash.len())?;
        if t < 11 || self.primes.len() > MAX_PRIMES {
            return None;
        }
        let mut em = vec![0xff; k];
        em[0] = 0x00;
        em[1] = 0x01;
        em[t - 1] = 0x00;
        em[t..t + SHA256_INFO.len()].copy_from_slice(SHA256_INFO);
        em[k - hash.len()..].copy_from_slice(&hash);
        by_width!(k, private_op(self, &em))
    }
}

macro_rules! by_width {
    ($len:expr, $f:ident($($arg:expr),*)) => {
        match $len {
            0..=64 => $f::<{ U512::LIMBS }>($($arg),*),
            65..=128 => $f::<{ U1024::LIMBS }>($($arg),*),
            129..=192 => $f::<{ U1536::LIMBS }>($($arg),*),
            193..=256 => $f::<{ U2048::LIMBS }>($($arg),*),
            257..=384 => $f::<{ U3072::LIMBS }>($($arg),*),
            385..=512 => $f::<{ U4096::LIMBS }>($($arg),*),
            513..=768 => $f::<{ U6144::LIMBS }>($($arg),*),
            769..=1024 => $f::<{ U8192::LIMBS }>($($arg),*),
            _ => $f::<{ U16384::LIMBS }>($($arg),*),
        }
    };
}
use by_width;

fn private_op<const L: usize>(key: &RsaKey, em: &[u8]) -> Option<Vec<u8>> {
    if !odd(&key.n) {
        return None;
    }
    let n = uint::<L>(&key.n)?;
    let e = uint::<L>(&key.e)?;
    let m = uint::<L>(em)?;
    let pn = params(&n)?;
    let e_bits = bits(key.e.len())?;
    let (r, r_inv) = blinding(&n, &pn, key.n.len())?;
    let r_e = Zeroizing::new(FixedMontyForm::new(&r, &pn).pow_bounded_exp(&e, e_bits));
    let blinded = Zeroizing::new(FixedMontyForm::new(&m, &pn).mul(&r_e).retrieve());
    let release = |s_blind: &Uint<L>| {
        let s = FixedMontyForm::new(s_blind, &pn).mul(&r_inv).retrieve();
        let check = FixedMontyForm::new(&s, &pn).pow_bounded_exp(&e, e_bits);
        bool::from(check.retrieve().ct_eq(&m)).then_some(s)
    };
    let s = crt::<L>(key, &blinded)
        .and_then(|s_blind| release(&s_blind))
        .or_else(|| {
            let d = Zeroizing::new(uint::<L>(&key.d)?);
            let c = Zeroizing::new(FixedMontyForm::new(&blinded, &pn));
            let s_blind = Zeroizing::new(c.pow_bounded_exp(&d, bits(key.n.len())?));
            release(&Zeroizing::new(s_blind.retrieve()))
        })?;
    Some(tail(&be_bytes(&s), key.n.len()))
}

fn crt<const L: usize>(key: &RsaKey, c: &Uint<L>) -> Option<Zeroizing<Uint<L>>> {
    let reduce = |v: &Uint<L>, r: &[u8]| {
        let r_nz: Zeroizing<NonZero<Uint<L>>> =
            Zeroizing::new(NonZero::new(uint::<L>(r)?).into_option()?);
        let v_r = Zeroizing::new(v.rem(&r_nz));
        Some(Zeroizing::new(tail(&be_bytes(&v_r), r.len())))
    };
    let mut parts = Vec::with_capacity(key.primes.len());
    for prime in &key.primes {
        let c_r = reduce(c, &prime.r)?;
        parts.push(by_width!(prime.r.len(), pow_at(&c_r, &prime.d, &prime.r))?);
    }
    let mut acc = Zeroizing::new(uint::<L>(&parts[1])?);
    let mut big_r = Zeroizing::new(uint::<L>(&key.primes[1].r)?);
    for i in std::iter::once(0).chain(2..key.primes.len()) {
        let prime = &key.primes[i];
        let t = &key.primes[if i == 0 { 1 } else { i }].t;
        let a = reduce(&acc, &prime.r)?;
        let h = by_width!(prime.r.len(), garner_at(&parts[i], &a, t, &prime.r))?;
        let h = Zeroizing::new(uint::<L>(&h)?);
        let r = Zeroizing::new(uint::<L>(&prime.r)?);
        let step = Zeroizing::new(big_r.wrapping_mul(&h));
        *acc = acc.wrapping_add(&step);
        *big_r = big_r.wrapping_mul(&r);
    }
    Some(acc)
}

fn pow_at<const W: usize>(base: &[u8], exp: &[u8], modulus: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if !odd(modulus) {
        return None;
    }
    let m = Zeroizing::new(uint::<W>(modulus)?);
    let b = Zeroizing::new(uint::<W>(base)?);
    let x = Zeroizing::new(uint::<W>(exp)?);
    let b = Zeroizing::new(FixedMontyForm::new(&b, &Zeroizing::new(params(&m)?)));
    let out = Zeroizing::new(b.pow_bounded_exp(&x, bits(modulus.len())?));
    let out = Zeroizing::new(out.retrieve());
    Some(Zeroizing::new(tail(&be_bytes(&out), modulus.len())))
}

fn garner_at<const W: usize>(
    m: &[u8],
    a: &[u8],
    t: &[u8],
    modulus: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    if !odd(modulus) {
        return None;
    }
    let p = Zeroizing::new(uint::<W>(modulus)?);
    let params = Zeroizing::new(params(&p)?);
    let p_nz = Zeroizing::new(NonZero::new(*p).into_option()?);
    let (m, a) = (Zeroizing::new(uint::<W>(m)?), Zeroizing::new(uint::<W>(a)?));
    // m - a as m + (p - a): FixedMontyForm::sub's Uint::sub_mod compiles to a branch on the borrow.
    let neg_a = Zeroizing::new(p.wrapping_sub(&a));
    let diff = Zeroizing::new(m.add_mod(&neg_a, &p_nz));
    let diff = Zeroizing::new(FixedMontyForm::new(&diff, &params));
    let t = Zeroizing::new(FixedMontyForm::new(&Zeroizing::new(uint::<W>(t)?), &params));
    let h = Zeroizing::new(diff.mul(&t).retrieve());
    Some(Zeroizing::new(tail(&be_bytes(&h), modulus.len())))
}

fn blinding<const L: usize>(
    n: &Uint<L>,
    pn: &FixedMontyParams<L>,
    k: usize,
) -> Option<(Zeroizing<Uint<L>>, Zeroizing<FixedMontyForm<L>>)> {
    let n_nz: NonZero<Uint<L>> = NonZero::new(*n).into_option()?;
    for _ in 0..8 {
        let mut bytes = Zeroizing::new(vec![0u8; L * 8]);
        getrandom::getrandom(&mut bytes[L * 8 - k..]).ok()?;
        let raw = Zeroizing::new(Uint::<L>::from_be_slice(&bytes));
        let r = Zeroizing::new(raw.rem(&n_nz));
        if let Some(inv) = Zeroizing::new(FixedMontyForm::new(&r, pn))
            .invert()
            .into_option()
        {
            return Some((r, Zeroizing::new(inv)));
        }
    }
    None
}

fn params<const L: usize>(modulus: &Uint<L>) -> Option<FixedMontyParams<L>> {
    Odd::new(*modulus).into_option().map(FixedMontyParams::new)
}

fn bits(len: usize) -> Option<u32> {
    u32::try_from(len.checked_mul(8)?).ok()
}

fn odd(v: &[u8]) -> bool {
    v.last().is_some_and(|b| b & 1 == 1)
}

fn uint<const L: usize>(v: &[u8]) -> Option<Uint<L>> {
    let mut buf = Zeroizing::new(vec![0u8; L * 8]);
    let start = buf.len().checked_sub(v.len())?;
    buf[start..].copy_from_slice(v);
    Some(Uint::from_be_slice(&buf))
}

fn be_bytes<const L: usize>(v: &Uint<L>) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        v.as_words()
            .iter()
            .rev()
            .flat_map(|w| w.to_be_bytes())
            .collect(),
    )
}

fn tail(v: &[u8], len: usize) -> Vec<u8> {
    v[v.len() - len..].to_vec()
}

fn unsigned(v: &[u8]) -> &[u8] {
    let skip = v.iter().take_while(|b| **b == 0).count();
    &v[skip.min(v.len().saturating_sub(1))..]
}
