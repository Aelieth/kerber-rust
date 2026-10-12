//! The RFC 6238 TOTP verifier of this example: HMAC-SHA1 truncated to six digits (RFC 4226) on a
//! 30-second step. The step before, the step itself and the step after are accepted. An accepted
//! code is remembered for 90 seconds per user and step, which lasts past every second in which
//! that code is accepted, so a reuse is refused.
//!
//! A user's seed is read on each request from the seeds file that `KERBER_EXAMPLE_TOTP_SEEDS`
//! names: one `<username> <base32 seed>` line per user, the username matched as the token carries
//! it. No seed or code is ever logged.

use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use krb5_kdc::{OtpVerdict, OtpVerifier, OtpVerifyRequest};
use sha1::Sha1;
use subtle::ConstantTimeEq;

/// The environment variable that names the seeds file.
pub const SEEDS_ENV: &str = "KERBER_EXAMPLE_TOTP_SEEDS";

/// The token type that selects this verifier: a token of `[{"type":"totp"}]`.
pub const NAME: &str = "totp";

/// The RFC 6238 time step, in seconds.
const STEP_SECS: u64 = 30;

/// The digits of a code.
const DIGITS: u32 = 6;

/// How long an accepted code is remembered, in seconds.
const REPLAY_SECS: u64 = 90;

/// One accepted code: whose it was, its time step, and the Unix second its memory ends.
struct UsedCode {
    username: Vec<u8>,
    step: u64,
    expires: u64,
}

/// The TOTP verifier: the seeds file's path, and the codes accepted within the last 90 seconds.
/// It holds no seed; each request reads the one it needs.
pub struct TotpVerifier {
    name: &'static str,
    seeds: Option<PathBuf>,
    used: Mutex<Vec<UsedCode>>,
}

impl TotpVerifier {
    /// A verifier that reads its seeds from `seeds`. `None` refuses every code.
    #[must_use]
    pub fn new(seeds: Option<PathBuf>) -> Self {
        Self {
            name: NAME,
            seeds,
            used: Mutex::new(Vec::new()),
        }
    }

    /// A verifier whose seeds file is the one `KERBER_EXAMPLE_TOTP_SEEDS` names. Unset, it refuses
    /// every code.
    #[must_use]
    pub fn from_env() -> Self {
        Self::new(std::env::var_os(SEEDS_ENV).map(PathBuf::from))
    }

    /// The seed of `username` in the seeds file, when the file reads and has a line for it.
    fn seed_for(&self, username: &[u8]) -> Option<Vec<u8>> {
        let text = std::fs::read(self.seeds.as_ref()?).ok()?;
        seed_in(&text, username)
    }

    /// Whether `otp` is an acceptable code of `username` at `now` (Unix seconds).
    fn decide(&self, username: &[u8], otp: &[u8], now: u64) -> bool {
        self.seed_for(username)
            .is_some_and(|seed| self.accept(&seed, username, otp, now))
    }

    /// Whether `otp` is the code of `seed` for a step in the window around `now` that `username`
    /// has not used. An accepted code is then remembered.
    fn accept(&self, seed: &[u8], username: &[u8], otp: &[u8], now: u64) -> bool {
        if !is_six_digits(otp) {
            return false;
        }
        let current = now / STEP_SECS;
        let matched: Vec<u64> = (current.saturating_sub(1)..=current.saturating_add(1))
            .filter(|&step| code_matches(seed, step, otp))
            .collect();
        let mut used = self.used.lock().unwrap_or_else(PoisonError::into_inner);
        used.retain(|code| code.expires > now);
        let fresh = matched.into_iter().find(|&step| {
            !used
                .iter()
                .any(|code| code.step == step && code.username == username)
        });
        let Some(step) = fresh else {
            return false;
        };
        used.push(UsedCode {
            username: username.to_vec(),
            step,
            expires: now.saturating_add(REPLAY_SECS),
        });
        true
    }
}

impl OtpVerifier for TotpVerifier {
    fn name(&self) -> &'static str {
        self.name
    }

    fn verify(&self, req: &OtpVerifyRequest<'_>) -> OtpVerdict {
        let accepted = unix_now().is_some_and(|now| self.decide(req.username, req.otp_value, now));
        if accepted {
            OtpVerdict::Accept
        } else {
            OtpVerdict::Reject
        }
    }
}

/// The current time as Unix seconds, or `None` when the clock is before the epoch.
fn unix_now() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
}

/// Exactly six ASCII digits: the only form a code takes.
fn is_six_digits(otp: &[u8]) -> bool {
    otp.len() == 6 && otp.iter().all(u8::is_ascii_digit)
}

/// Whether `otp` is the six-digit code of `seed` at `step`, compared in constant time.
fn code_matches(seed: &[u8], step: u64, otp: &[u8]) -> bool {
    hotp(seed, step, DIGITS).is_some_and(|code| format!("{code:06}").as_bytes().ct_eq(otp).into())
}

/// RFC 4226 HOTP: the `digits`-digit code of `counter` under `key`, from HMAC-SHA1 and dynamic
/// truncation. `None` when the modulus does not fit a `u32`.
fn hotp(key: &[u8], counter: u64, digits: u32) -> Option<u32> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).ok()?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(*digest.last()? & 0x0f);
    let window: [u8; 4] = digest.get(offset..offset + 4)?.try_into().ok()?;
    let code = u32::from_be_bytes(window) & 0x7fff_ffff;
    code.checked_rem(10u32.checked_pow(digits)?)
}

/// The seed of `username` in a seeds file: the second field of the first line whose two fields
/// are `username` and the seed, decoded from base32. `None` when no line names the user, or the
/// seed is not base32.
fn seed_in(text: &[u8], username: &[u8]) -> Option<Vec<u8>> {
    let seed = text.split(|&c| c == b'\n').find_map(|line| {
        let fields: Vec<&[u8]> = line
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty())
            .collect();
        let [name, seed] = fields.as_slice() else {
            return None;
        };
        (*name == username).then_some(*seed)
    })?;
    base32_decode(seed)
}

/// RFC 4648 base32, in either case, with any `=` padding dropped. `None` for any other octet, and
/// for no octets at all.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The RFC 6238 Appendix B SHA1 secret, the ASCII of "12345678901234567890", and its base32.
    const KEY: &[u8] = b"12345678901234567890";
    const KEY_BASE32: &[u8] = b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    /// RFC 6238 Appendix B: a time, and the eight-digit SHA1 TOTP at that time.
    const APPENDIX_B: [(u64, &str); 6] = [
        (59, "94287082"),
        (1_111_111_109, "07081804"),
        (1_111_111_111, "14050471"),
        (1_234_567_890, "89005924"),
        (2_000_000_000, "69279037"),
        (20_000_000_000, "65353130"),
    ];

    /// RFC 4226 Appendix D: the six-digit HOTP of counters 0 to 9 under the same secret.
    const APPENDIX_D: [&str; 10] = [
        "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
        "520489",
    ];

    /// Step 37037037 starts at time 1111111110. `NOW` is five seconds into it.
    const STEP: u64 = 37_037_037;
    const NOW: u64 = 1_111_111_115;

    /// The six-digit code of `KEY` at `step`.
    fn code(step: u64) -> String {
        let code = hotp(KEY, step, DIGITS).expect("six digits");
        format!("{code:06}")
    }

    /// Whether `username` is accepted with the code of `step`, at `now`.
    fn accepted(v: &TotpVerifier, username: &[u8], step: u64, now: u64) -> bool {
        v.accept(KEY, username, code(step).as_bytes(), now)
    }

    #[test]
    fn appendix_b_sha1_vectors_at_eight_digits() {
        for (time, want) in APPENDIX_B {
            let code = hotp(KEY, time / STEP_SECS, 8).expect("eight digits");
            assert_eq!(format!("{code:08}"), want, "time {time}");
        }
    }

    #[test]
    fn six_digits_are_the_low_six_of_the_eight() {
        for (time, want) in APPENDIX_B {
            let code = hotp(KEY, time / STEP_SECS, 6).expect("six digits");
            assert_eq!(format!("{code:06}"), want[2..], "time {time}");
        }
    }

    #[test]
    fn appendix_d_hotp_vectors_at_six_digits() {
        for (counter, want) in APPENDIX_D.into_iter().enumerate() {
            let counter = u64::try_from(counter).expect("a small counter");
            let code = hotp(KEY, counter, 6).expect("six digits");
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
    fn base32_refuses_no_octets_and_other_octets() {
        assert_eq!(base32_decode(b""), None);
        assert_eq!(base32_decode(b"===="), None);
        assert_eq!(base32_decode(b"MZ1W"), None);
        assert_eq!(base32_decode(b"MZ W"), None);
    }

    #[test]
    fn a_seeds_line_names_the_user_and_its_seed() {
        let text = b"alice@R GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\r\nbob MZXW6YTBOI======\n";
        assert_eq!(seed_in(text, b"alice@R"), Some(KEY.to_vec()));
        assert_eq!(seed_in(text, b"bob"), Some(b"foobar".to_vec()));
        assert_eq!(seed_in(text, b"carol"), None);
        // The name is matched whole, as written.
        assert_eq!(seed_in(text, b"alice"), None);
        // The first line for a name is its seed.
        let twice = b"x MZXW6YTBOI======\nx GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n";
        assert_eq!(seed_in(twice, b"x"), Some(b"foobar".to_vec()));
        // A line of three fields names no one.
        assert_eq!(seed_in(b"x a b\n", b"x"), None);
        // A seed that is not base32 refuses its user.
        assert_eq!(seed_in(b"dave 1NVALID\n", b"dave"), None);
    }

    #[test]
    fn the_window_is_the_step_before_the_step_and_the_step_after() {
        let v = TotpVerifier::new(None);
        for (step, want) in [
            (STEP - 2, false),
            (STEP - 1, true),
            (STEP, true),
            (STEP + 1, true),
            (STEP + 2, false),
        ] {
            assert_eq!(accepted(&v, b"alice", step, NOW), want, "step {step}");
        }
    }

    #[test]
    fn a_reused_code_is_refused_for_its_user_and_step() {
        let v = TotpVerifier::new(None);
        assert!(accepted(&v, b"alice", STEP, NOW));
        assert!(!accepted(&v, b"alice", STEP, NOW + 1));
        // Another user's memory is their own, even at the same step.
        assert!(accepted(&v, b"bob", STEP, NOW + 1));
    }

    #[test]
    fn the_memory_outlives_every_second_the_code_is_accepted() {
        let v = TotpVerifier::new(None);
        // The first second the code is accepted, then the last one: the memory still holds.
        assert!(accepted(&v, b"alice", STEP, (STEP - 1) * STEP_SECS));
        assert!(!accepted(&v, b"alice", STEP, (STEP + 2) * STEP_SECS - 1));
        // The second after that, the window has moved past the code.
        assert!(!accepted(&v, b"alice", STEP, (STEP + 2) * STEP_SECS));
    }

    #[test]
    fn a_value_that_is_not_six_ascii_digits_is_refused() {
        let v = TotpVerifier::new(None);
        let good = code(STEP);
        for bad in [
            "", "12345", "1234567", "05047", " 050471", "050471 ", "05047a", "+50471",
        ] {
            assert!(!v.accept(KEY, b"alice", bad.as_bytes(), NOW), "{bad:?}");
        }
        // None of them was remembered, so the code itself is still good.
        assert!(v.accept(KEY, b"alice", good.as_bytes(), NOW));
    }

    #[test]
    fn no_seeds_file_refuses_every_user() {
        let otp = code(STEP);
        assert!(!TotpVerifier::new(None).decide(b"alice", otp.as_bytes(), NOW));
        let missing = PathBuf::from("/nonexistent/krb5-otp-kdc-example/seeds");
        assert!(!TotpVerifier::new(Some(missing)).decide(b"alice", otp.as_bytes(), NOW));
        // A directory is no seeds file: it does not read.
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        assert!(!TotpVerifier::new(Some(dir)).decide(b"alice", otp.as_bytes(), NOW));
    }

    #[test]
    fn it_serves_the_totp_token_type() {
        assert_eq!(TotpVerifier::new(None).name(), "totp");
    }
}
