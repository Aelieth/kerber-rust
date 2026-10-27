//! The example TOTP `OtpVerifier` the in-process KDC registers. See the crate README.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use krb5_crypto::string_to_key;
use krb5_kdc::{OtpVerdict, OtpVerifier, OtpVerifyRequest, key_salt, s2k_params};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const SEEDS_ENV: &str = "KERBER_EXAMPLE_TOTP_SEEDS";
pub const STATE_ENV: &str = "KERBER_EXAMPLE_TOTP_STATE";
pub const NAME: &str = "totp";

const STEP_SECS: u64 = 30;
const DIGITS: u32 = 6;

pub trait SeedSource: Send + Sync {
    fn seed_for(&self, principal: &str) -> Option<Zeroizing<Vec<u8>>>;
}

pub struct FileSeeds {
    path: Option<PathBuf>,
}

impl FileSeeds {
    #[must_use]
    pub fn new(path: Option<PathBuf>) -> Self {
        Self { path }
    }

    #[must_use]
    pub fn from_env() -> Self {
        Self::new(std::env::var_os(SEEDS_ENV).map(PathBuf::from))
    }
}

impl SeedSource for FileSeeds {
    fn seed_for(&self, principal: &str) -> Option<Zeroizing<Vec<u8>>> {
        let text = Zeroizing::new(std::fs::read(self.path.as_ref()?).ok()?);
        seed_in(&text, principal.as_bytes()).map(Zeroizing::new)
    }
}

#[derive(Clone, Copy, Default)]
struct Entry {
    last_step: u64,
    failures: u32,
}

struct State {
    path: Option<PathBuf>,
    entries: HashMap<String, Entry>,
}

impl State {
    fn load(path: Option<PathBuf>) -> Self {
        let mut entries = HashMap::new();
        if let Some(p) = &path
            && let Ok(text) = std::fs::read_to_string(p)
        {
            for line in text.lines() {
                let f: Vec<&str> = line.split_whitespace().collect();
                if let [name, step, fails] = f.as_slice()
                    && let (Ok(last_step), Ok(failures)) = (step.parse(), fails.parse())
                {
                    entries.insert(
                        (*name).to_owned(),
                        Entry {
                            last_step,
                            failures,
                        },
                    );
                }
            }
        }
        Self { path, entries }
    }

    fn persist(&self) {
        let Some(p) = &self.path else { return };
        let mut body = String::new();
        for (name, e) in &self.entries {
            let _ = writeln!(body, "{name} {} {}", e.last_step, e.failures);
        }
        let tmp = p.with_extension("tmp");
        let written = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .and_then(|mut f| f.write_all(body.as_bytes()).map(|()| f));
        if let Ok(f) = written {
            drop(f);
            let _ = std::fs::rename(&tmp, p);
        }
    }
}

pub struct TotpVerifier {
    seeds: Box<dyn SeedSource>,
    state: Mutex<State>,
    require_password: bool,
}

impl TotpVerifier {
    #[must_use]
    pub fn new(seeds: Box<dyn SeedSource>, state: Option<PathBuf>, require_password: bool) -> Self {
        Self {
            seeds,
            state: Mutex::new(State::load(state)),
            require_password,
        }
    }

    #[must_use]
    pub fn from_env() -> Self {
        let totp_only = std::env::var_os("KERBER_EXAMPLE_TOTP_ONLY").is_some();
        Self::new(
            Box::new(FileSeeds::from_env()),
            std::env::var_os(STATE_ENV).map(PathBuf::from),
            !totp_only,
        )
    }

    fn split<'a>(&self, value: &'a [u8]) -> Option<(&'a [u8], &'a [u8])> {
        let split = value.len().checked_sub(DIGITS as usize)?;
        let (password, code) = value.split_at(split);
        if !is_six_digits(code) || (self.require_password && password.is_empty()) {
            return None;
        }
        Some((password, code))
    }

    fn password_ok(req: &OtpVerifyRequest, password: &[u8]) -> bool {
        // Only the current (highest-kvno) keys, each with its own salt: an old password kept by
        // `cpw -keepold` must not pass.
        let Some(max_kvno) = req.principal.keys.iter().map(|k| k.kvno).max() else {
            return false;
        };
        req.principal
            .keys
            .iter()
            .filter(|k| k.kvno == max_kvno)
            .any(|k| {
                let salt = key_salt(k, &req.principal.name, &req.principal.realm);
                let params = s2k_params(k.etype);
                string_to_key(k.etype, password, &salt, Some(&params))
                    .is_ok_and(|nk| bool::from(nk.as_bytes().ct_eq(k.key.as_bytes())))
            })
    }

    fn accept(&self, principal: &str, seed: &[u8], code: &[u8], now: u64) -> bool {
        let current = now / STEP_SECS;
        let matched = (current.saturating_sub(1)..=current.saturating_add(1))
            .rev()
            .find(|&step| code_matches(seed, step, code));
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = state.entries.entry(principal.to_owned()).or_default();
        let accepted = matched.is_some_and(|step| step > entry.last_step);
        if let Some(step) = matched.filter(|_| accepted) {
            entry.last_step = step;
            entry.failures = 0;
        } else {
            entry.failures = entry.failures.saturating_add(1);
        }
        state.persist();
        accepted
    }
}

impl OtpVerifier for TotpVerifier {
    fn name(&self) -> &'static str {
        NAME
    }

    fn verify(&self, req: &OtpVerifyRequest) -> OtpVerdict {
        #[cfg(feature = "chaos")]
        if let Some(verdict) = chaos::act(&req.username) {
            return verdict;
        }
        let Some(now) = unix_now() else {
            return OtpVerdict::Reject;
        };
        let Some((password, code)) = self.split(&req.otp_value) else {
            return OtpVerdict::Reject;
        };
        if self.require_password && !Self::password_ok(req, password) {
            return OtpVerdict::Reject;
        }
        let principal = req.principal.id();
        let Some(seed) = self.seeds.seed_for(&principal) else {
            return OtpVerdict::Reject;
        };
        if self.accept(&principal, &seed, code, now) {
            OtpVerdict::Accept
        } else {
            OtpVerdict::Reject
        }
    }
}

fn unix_now() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
}

fn is_six_digits(otp: &[u8]) -> bool {
    otp.len() == DIGITS as usize && otp.iter().all(u8::is_ascii_digit)
}

fn code_matches(seed: &[u8], step: u64, otp: &[u8]) -> bool {
    hotp(seed, step).is_some_and(|code| format!("{code:06}").as_bytes().ct_eq(otp).into())
}

fn hotp(key: &[u8], counter: u64) -> Option<u32> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).ok()?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(*digest.last()? & 0x0f);
    let window: [u8; 4] = digest.get(offset..offset + 4)?.try_into().ok()?;
    let code = u32::from_be_bytes(window) & 0x7fff_ffff;
    code.checked_rem(10u32.checked_pow(DIGITS)?)
}

fn seed_in(text: &[u8], principal: &[u8]) -> Option<Vec<u8>> {
    let seed = text.split(|&c| c == b'\n').find_map(|line| {
        let fields: Vec<&[u8]> = line
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty())
            .collect();
        let [name, seed] = fields.as_slice() else {
            return None;
        };
        (*name == principal).then_some(*seed)
    })?;
    base32_decode(seed)
}

fn base32_decode(text: &[u8]) -> Option<Vec<u8>> {
    let mut body = text;
    while let Some((&b'=', rest)) = body.split_last() {
        body = rest;
    }
    let mut out = Vec::with_capacity(body.len() * 5 / 8);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &c in body {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        acc = (acc << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
            acc &= (1 << bits) - 1;
        }
    }
    (!out.is_empty()).then_some(out)
}

#[cfg(feature = "chaos")]
mod chaos {
    use super::OtpVerdict;

    pub fn act(username: &[u8]) -> Option<OtpVerdict> {
        let rest = username.strip_prefix(b"chaos:")?;
        if rest == b"hang" {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        } else if let Some(ms) = rest.strip_prefix(b"slow:") {
            let ms = std::str::from_utf8(ms).ok().and_then(|s| s.parse().ok());
            std::thread::sleep(std::time::Duration::from_millis(ms.unwrap_or(0)));
            Some(OtpVerdict::Reject)
        } else if rest == b"panic" {
            panic!("chaos: the verifier panicked")
        } else if rest == b"error" {
            Some(OtpVerdict::Error("chaos: the verifier failed".to_owned()))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"12345678901234567890";
    const KEY_BASE32: &[u8] = b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn appendix_b_sha1_vectors_at_their_low_six_digits() {
        for (time, want) in [
            (59, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ] {
            let code = hotp(KEY, time / STEP_SECS).expect("a code");
            assert_eq!(format!("{code:06}"), want[2..], "time {time}");
        }
    }

    #[test]
    fn appendix_d_hotp_vectors_at_six_digits() {
        let want = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, want) in (0u64..).zip(want) {
            let code = hotp(KEY, counter).expect("a code");
            assert_eq!(format!("{code:06}"), want, "counter {counter}");
        }
    }

    #[test]
    fn base32_decodes_the_rfc4648_vectors() {
        assert_eq!(base32_decode(b"MY======"), Some(b"f".to_vec()));
        assert_eq!(base32_decode(b"MZXQ===="), Some(b"fo".to_vec()));
        assert_eq!(base32_decode(b"MZXW6==="), Some(b"foo".to_vec()));
        assert_eq!(base32_decode(b"MZXW6YQ="), Some(b"foob".to_vec()));
        assert_eq!(base32_decode(b"MZXW6YTB"), Some(b"fooba".to_vec()));
        assert_eq!(base32_decode(b"MZXW6YTBOI======"), Some(b"foobar".to_vec()));
        assert_eq!(base32_decode(b"mzxw6ytboi"), Some(b"foobar".to_vec()));
        assert_eq!(base32_decode(KEY_BASE32), Some(KEY.to_vec()));
    }

    #[test]
    fn a_reused_code_is_refused_for_its_user_and_step() {
        let v = TotpVerifier::new(Box::new(FileSeeds::new(None)), None, false);
        let now = 1_111_111_115;
        let code = format!("{:06}", hotp(KEY, now / STEP_SECS).expect("a code"));
        assert!(v.accept("alice", KEY, code.as_bytes(), now));
        assert!(!v.accept("alice", KEY, code.as_bytes(), now + 1));
        assert!(v.accept("bob", KEY, code.as_bytes(), now + 1));
    }
}
