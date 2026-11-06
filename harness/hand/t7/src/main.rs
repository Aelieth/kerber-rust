//! Constant-time timing harness for the crypto of `krb5-crypto` and the PKINIT code of
//! `krb5-types`: dudect, fixed against random.
//!
//! A measurement tool, not a test. For each op two classes of samples are interleaved in random
//! order. Class Left uses one FIXED secret, chosen once. Class Right uses a RANDOM secret, fresh
//! for each sample. Everything that is not secret is the same in both classes. Every input is
//! prepared outside the timed region and only the op itself is timed. Welch's t is then taken
//! with dudect-bencher's percentile cropping, and the largest |t| over its tests is reported.
//!
//! Only the public API of `krb5-crypto` and `krb5_types::pkinit` is used, so this one source
//! builds against every tree that has it (the `pk` feature, on by default, is the PKINIT ops).
//! See README.md.

use std::collections::BTreeMap;
use std::fs;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dudect_bencher::rand::{Rng, SeedableRng};
use dudect_bencher::{BenchRng, Class};
use krb5_crypto::{
    checksum, decrypt, encrypt_with_confounder, p256_generate, p256_shared, spake_keygen,
    spake_result, string_to_key, verify_checksum_keyed, EncryptionType, Error, KeyUsage,
    ProtocolKey, SpakeGroup,
};
#[cfg(feature = "pk")]
use krb5_types::pkinit::KxGroup;

/// Samples per op (both classes together) unless `--samples` says otherwise.
const DEFAULT_SAMPLES: usize = 1_000_000;
/// Samples prepared, timed and added to the statistics at a time. The percentile cut-offs are
/// taken from the first batch only, as dudect-bencher does with its first call.
const BATCH: usize = 20_000;
/// An op runs untimed for this long, and for at least one pass over `WARMUP_INPUTS` inputs,
/// before it is timed. The pass also checks that the op does what the timing assumes. An op that
/// takes a long time a call (RSA-8192) does not run all the inputs: the pass ends once
/// `WARMUP_PASS_MAX` has gone and `WARMUP_MIN_CHECKED` inputs, of both classes, are checked.
const WARMUP_TIME: Duration = Duration::from_millis(30);
const WARMUP_INPUTS: usize = 256;
const WARMUP_PASS_MAX: Duration = Duration::from_secs(2);
const WARMUP_MIN_CHECKED: usize = 8;
/// max |t| below this is a pass.
const PASS_T: f64 = 4.5;
/// An op stops early once max |t| is above this, unless `--no-early-stop`.
const STOP_T: f64 = 10.0;
/// The most distinct counts a `--verbose` histogram lists (the most frequent ones, in order).
const HIST_SHOWN: usize = 24;
/// PBKDF2 iterations of `s2k-aes256`: the smallest count `string_to_key` accepts (the default
/// for aes256-cts-hmac-sha1-96 is 4096). The code path is the same, the samples are fast.
const S2K_ITERATIONS: u32 = 4096;
/// The fixed plaintext (and checksummed message) is this long.
const PLAINTEXT_LEN: usize = 64;
/// The fixed key usage of every encrypt, decrypt and checksum.
const KEY_USAGE: u32 = 2;

/// The `Cargo.lock` this binary was built with, and the workspace manifest of the tree it was
/// built from. Both are read when the binary is compiled; the header prints what they say, and
/// warns when `tree` no longer holds the manifest that was built.
const BUILT_LOCK: &str = include_str!("../Cargo.lock");
const BUILT_TREE_MANIFEST: &str = include_str!("../../../../Cargo.toml");

// ------------------------------------------------------------------------------------------
// Statistics: a port of dudect-bencher 0.7.0 `src/stats.rs` (MIT OR Apache-2.0)
// ------------------------------------------------------------------------------------------

/// Welch's t-test with percentile cropping, as dudect-bencher computes it. That crate keeps this
/// module private, and the timings of its `CtRunner` private too, so it is reproduced here line
/// by line (`--crosscheck` runs the library on the same data and compares). 101 tests are kept:
/// the first on all samples, and one for each of 100 percentile cut-offs of the first batch, on
/// the samples below the cut-off; the cut-offs are the percentiles `f(k) = 1 - 0.5^(10k/100)`,
/// k = 1..100. The result is the test with the largest |t|.
mod stats {
    use std::cmp;

    #[derive(Copy, Clone, Debug, Default)]
    struct CtTest {
        means: (f64, f64),
        sq_diffs: (f64, f64),
        sizes: (usize, usize),
    }

    pub struct Stats {
        tests: Vec<CtTest>,
        percentiles: Vec<f64>,
    }

    impl Stats {
        pub fn new() -> Self {
            Self {
                tests: vec![CtTest::default(); 101],
                percentiles: Vec::new(),
            }
        }

        /// Adds one batch of runtimes (in ns). The first batch also sets the cut-offs.
        pub fn update(&mut self, left: &[u64], right: &[u64]) {
            if self.percentiles.is_empty() {
                let mut all = left.to_vec();
                all.extend_from_slice(right);
                self.percentiles = prepare_percentiles(&all);
            }
            let left: Vec<f64> = left.iter().map(|&n| n as f64).collect();
            let right: Vec<f64> = right.iter().map(|&n| n as f64).collect();

            for &x in left.iter() {
                update_test_left(&mut self.tests[0], x);
            }
            for &x in right.iter() {
                update_test_right(&mut self.tests[0], x);
            }
            for (test, &pct) in self.tests.iter_mut().skip(1).zip(self.percentiles.iter()) {
                for &x in left.iter().filter(|&&x| x < pct) {
                    update_test_left(test, x);
                }
                for &x in right.iter().filter(|&&x| x < pct) {
                    update_test_right(test, x);
                }
            }
        }

        /// The means of the two classes over all samples (the first test), in ns.
        pub fn means(&self) -> (f64, f64) {
            self.tests[0].means
        }

        /// The (signed) t of the test with the largest |t|, and the number of samples in that
        /// test. Negative t: Left (the fixed secret) is the faster class.
        pub fn max_t(&self) -> (f64, usize) {
            let max_test = self
                .tests
                .iter()
                .max_by(|&x, &y| local_cmp(compute_t(x).abs(), compute_t(y).abs()))
                .expect("101 tests");
            (compute_t(max_test), max_test.sizes.0 + max_test.sizes.1)
        }
    }

    // NaNs are smaller than everything
    fn local_cmp(x: f64, y: f64) -> cmp::Ordering {
        use std::cmp::Ordering::{Equal, Greater, Less};
        if y.is_nan() {
            Greater
        } else if x.is_nan() || x < y {
            Less
        } else if x == y {
            Equal
        } else {
            Greater
        }
    }

    /// The `pct` percentile of a sorted sample-set, by linear interpolation.
    fn percentile_of_sorted(sorted_samples: &[f64], pct: f64) -> f64 {
        assert!(!sorted_samples.is_empty());
        if sorted_samples.len() == 1 {
            return sorted_samples[0];
        }
        let zero = 0f64;
        assert!(zero <= pct);
        let hundred = 100f64;
        assert!(pct <= hundred);
        let length = (sorted_samples.len() - 1) as f64;
        let rank = (pct / hundred) * length;
        let lrank = rank.floor();
        let d = rank - lrank;
        let n = lrank as usize;
        let lo = sorted_samples[n];
        let hi = sorted_samples[n + 1];
        lo + (hi - lo) * d
    }

    /// The percentiles at f(1), f(2), ..., f(100) of the runtime distribution, where
    /// `f(k) = 1 - 0.5^(10k / 100)`.
    fn prepare_percentiles(durations: &[u64]) -> Vec<f64> {
        let sorted: Vec<f64> = {
            let mut v = durations.to_vec();
            v.sort();
            v.into_iter().map(|d| d as f64).collect()
        };
        (0..100)
            .map(|i| {
                let pct = {
                    let exp = f64::from(10 * (i + 1)) / 100f64;
                    1f64 - 0.5f64.powf(exp)
                };
                percentile_of_sorted(&sorted, 100f64 * pct)
            })
            .collect()
    }

    fn compute_t(test: &CtTest) -> f64 {
        let &CtTest {
            means,
            sq_diffs,
            sizes,
        } = test;
        let num = means.0 - means.1;
        let n0 = sizes.0 as f64;
        let n1 = sizes.1 as f64;
        let var0 = sq_diffs.0 / (n0 - 1f64);
        let var1 = sq_diffs.1 / (n1 - 1f64);
        let den = (var0 / n0 + var1 / n1).sqrt();
        num / den
    }

    fn update_test_left(test: &mut CtTest, datum: f64) {
        test.sizes.0 += 1;
        let diff = datum - test.means.0;
        test.means.0 += diff / (test.sizes.0 as f64);
        test.sq_diffs.0 += diff * (datum - test.means.0);
    }

    fn update_test_right(test: &mut CtTest, datum: f64) {
        test.sizes.1 += 1;
        let diff = datum - test.means.1;
        test.means.1 += diff / (test.sizes.1 as f64);
        test.sq_diffs.1 += diff * (datum - test.means.1);
    }
}

use stats::Stats;

// ------------------------------------------------------------------------------------------
// The sampling loop
// ------------------------------------------------------------------------------------------

struct Cfg {
    samples: usize,
    seed: u64,
    verbose: bool,
    /// What a sample measures: wall time (ns), or one perf counter of this thread (`--count`).
    count: Count,
    stop_t: f64,
}

#[derive(Clone, Copy)]
enum Count {
    Time,
    /// A hardware counter of the calling thread, user mode only: (name, perf type, perf config,
    /// and a second counter of the same type, read in one group with it and subtracted).
    Perf(&'static str, u32, u64, Option<u64>),
}

impl Count {
    fn name(self) -> &'static str {
        match self {
            Count::Time => "time",
            Count::Perf(name, ..) => name,
        }
    }
}

/// The clock a sample reads before and after the op.
trait Clock {
    type Mark: Copy;
    fn mark() -> Self::Mark;
    fn units(start: Self::Mark, end: Self::Mark) -> u64;
}

/// Wall time in ns, as dudect-bencher's `run_one` reads it.
struct Wall;

impl Clock for Wall {
    type Mark = Instant;
    #[inline(always)]
    fn mark() -> Instant {
        Instant::now()
    }
    fn units(start: Instant, end: Instant) -> u64 {
        u64::try_from(end.duration_since(start).as_nanos()).unwrap_or(u64::MAX)
    }
}

/// The perf counter `--count` opened (`perf::open`), read with `read(2)`.
struct Counter;

impl Clock for Counter {
    type Mark = u64;
    #[inline(always)]
    fn mark() -> u64 {
        perf::read()
    }
    fn units(start: u64, end: u64) -> u64 {
        end.wrapping_sub(start)
    }
}

/// One perf_event_open counter of this thread, user mode only (exclude_kernel, exclude_hv), so a
/// sample counts what the op itself executes. Cycles do not move with the clock rate, so a
/// difference in them is a difference in the work; instructions and branches are exact.
mod perf {
    use std::sync::OnceLock;

    static FD: OnceLock<i32> = OnceLock::new();
    /// Whether FD leads a group of two, whose second count is subtracted from its first.
    static GROUP: OnceLock<bool> = OnceLock::new();

    #[repr(C)]
    struct Attr {
        kind: u32,
        size: u32,
        config: u64,
        sample: u64,
        sample_type: u64,
        read_format: u64,
        flags: u64,
        rest: [u64; 10],
    }

    fn open_one(kind: u32, config: u64, read_format: u64, group: i32) -> Result<i32, String> {
        let mut attr = Attr {
            kind,
            size: 128,
            config,
            sample: 0,
            sample_type: 0,
            read_format,
            flags: (1 << 5) | (1 << 6),
            rest: [0; 10],
        };
        // SAFETY: attr is a perf_event_attr of the size it names; pid 0 and cpu -1 are this
        // thread, group -1 or an open leader's fd.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &mut attr as *mut Attr,
                0,
                -1,
                group,
                0,
            )
        };
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            return Err(format!("perf_event_open: {e}"));
        }
        i32::try_from(fd).map_err(|_| "perf_event_open: fd".to_string())
    }

    /// Opens `config`, and with `minus` a second counter in its group (PERF_FORMAT_GROUP), so that
    /// one read gives both counts at the same instant.
    pub fn open(kind: u32, config: u64, minus: Option<u64>) -> Result<(), String> {
        let fd = open_one(kind, config, if minus.is_some() { 1 << 3 } else { 0 }, -1)?;
        if let Some(second) = minus {
            open_one(kind, second, 0, fd)?;
        }
        let twice = || "perf counter opened twice".to_string();
        GROUP.set(minus.is_some()).map_err(|_| twice())?;
        FD.set(fd).map_err(|_| twice())
    }

    #[inline(always)]
    pub fn read() -> u64 {
        let fd = *FD.get().expect("perf::open runs before any sample");
        if *GROUP.get().expect("perf::open runs before any sample") {
            // The group's layout: the number of counters, then each value.
            let mut v = [0u64; 3];
            // SAFETY: reads the 24-byte group value of an open perf group leader into v.
            unsafe { libc::read(fd, v.as_mut_ptr().cast(), 24) };
            return v[1].wrapping_sub(v[2]);
        }
        let mut v = 0u64;
        // SAFETY: reads the 8-byte counter value of an open perf fd into v.
        unsafe { libc::read(fd, (&mut v as *mut u64).cast(), 8) };
        v
    }
}

struct Measured {
    /// Timed samples taken, both classes together.
    samples: usize,
    /// The signed t of the test with the largest |t|.
    max_t: f64,
}

fn is_left(class: Class) -> bool {
    matches!(class, Class::Left)
}

fn class_name(class: Class) -> &'static str {
    if is_left(class) {
        "Left (fixed)"
    } else {
        "Right (random)"
    }
}

/// Times `op` on inputs from `prepare`, Left against Right, until `cfg.samples` samples are
/// taken or |t| is above `STOP_T`.
///
/// `prepare(class, rng)` builds the input of ONE sample: the fixed secret for `Left`, a fresh
/// random one for `Right`. It runs outside the timed region, a batch at a time, with the classes
/// of the batch drawn in random order. `check(class, &result)` must hold for every result in the
/// warm-up pass, which guards against timing a call that fails at once.
fn measure<I, R>(
    name: &str,
    cfg: &Cfg,
    rng: &mut BenchRng,
    prepare: impl FnMut(Class, &mut BenchRng) -> I,
    op: impl Fn(&I) -> R,
    check: impl Fn(Class, &R) -> bool,
) -> Result<Measured, String> {
    match cfg.count {
        Count::Time => measure_with::<Wall, I, R, false>(name, cfg, rng, prepare, op, check),
        Count::Perf(..) => measure_with::<Counter, I, R, false>(name, cfg, rng, prepare, op, check),
    }
}

/// `measure`, and `check` must hold for every TIMED sample too: it is called after the second
/// clock read, with the result still alive, and a sample that fails it aborts the op. Here the
/// result is dropped after that clock read and not before it, so this is for an op whose result
/// owns nothing to free.
fn measure_each<I, R>(
    name: &str,
    cfg: &Cfg,
    rng: &mut BenchRng,
    prepare: impl FnMut(Class, &mut BenchRng) -> I,
    op: impl Fn(&I) -> R,
    check: impl Fn(Class, &R) -> bool,
) -> Result<Measured, String> {
    match cfg.count {
        Count::Time => measure_with::<Wall, I, R, true>(name, cfg, rng, prepare, op, check),
        Count::Perf(..) => measure_with::<Counter, I, R, true>(name, cfg, rng, prepare, op, check),
    }
}

fn measure_with<C: Clock, I, R, const EACH: bool>(
    name: &str,
    cfg: &Cfg,
    rng: &mut BenchRng,
    mut prepare: impl FnMut(Class, &mut BenchRng) -> I,
    op: impl Fn(&I) -> R,
    check: impl Fn(Class, &R) -> bool,
) -> Result<Measured, String> {
    // Warm up, and check the op on both classes.
    let mut warm = Vec::with_capacity(WARMUP_INPUTS);
    for i in 0..WARMUP_INPUTS {
        let class = if i % 2 == 0 {
            Class::Left
        } else {
            Class::Right
        };
        warm.push((class, prepare(class, rng)));
    }
    let started = Instant::now();
    let mut i = 0;
    let mut checking = true;
    while checking || started.elapsed() < WARMUP_TIME {
        let (class, input) = &warm[i % warm.len()];
        let result = op(input);
        if checking && !check(*class, &result) {
            return Err(format!(
                "{name}: the op gave an unexpected result on a {} sample, so it would not be \
                 timing what it should",
                class_name(*class)
            ));
        }
        black_box(result);
        i += 1;
        if checking
            && (i == warm.len()
                || (i >= WARMUP_MIN_CHECKED && started.elapsed() >= WARMUP_PASS_MAX))
        {
            checking = false;
        }
    }
    drop(warm);

    let mut stats = Stats::new();
    let mut done = 0;
    let mut max_t = f64::NAN;
    // Each class's per-sample counts, for `--verbose` with a `--count` counter: the fixed input's
    // own spread (interrupts, REP strings) against the random inputs' spread.
    let hist = cfg.verbose && matches!(cfg.count, Count::Perf(..));
    let mut hists = [BTreeMap::<u64, u64>::new(), BTreeMap::new()];
    while done < cfg.samples {
        let m = (cfg.samples - done).min(BATCH);

        // Random order of the two classes, and every input, outside the timed region.
        let mut classes = Vec::with_capacity(m);
        let mut inputs = Vec::with_capacity(m);
        for _ in 0..m {
            let class = if rng.next_u32() & 1 == 0 {
                Class::Left
            } else {
                Class::Right
            };
            classes.push(class);
            inputs.push(prepare(class, rng));
        }

        // Time the op alone: two clock reads around it, as dudect-bencher's `run_one`.
        let mut left = Vec::with_capacity(m);
        let mut right = Vec::with_capacity(m);
        for (k, (class, input)) in classes.iter().zip(inputs.iter()).enumerate() {
            let start = C::mark();
            let end;
            if EACH {
                let result = black_box(op(black_box(input)));
                end = C::mark();
                if !check(*class, &result) {
                    return Err(format!(
                        "{name}: the op gave an unexpected result on a {} sample (timed sample \
                         {}), so the op is aborted",
                        class_name(*class),
                        done + k + 1
                    ));
                }
            } else {
                black_box(op(black_box(input)));
                end = C::mark();
            }
            let ns = C::units(start, end);
            if is_left(*class) {
                left.push(ns);
            } else {
                right.push(ns);
            }
        }
        drop(inputs);

        if hist {
            for (h, v) in hists.iter_mut().zip([&left, &right]) {
                for &x in v {
                    *h.entry(x).or_insert(0) += 1;
                }
            }
        }
        stats.update(&left, &right);
        done += m;
        max_t = stats.max_t().0;
        if max_t.is_nan() {
            // No spread in either class (an exact counter): equal counts are no difference,
            // unequal ones as big a difference as there is.
            let (left, right) = stats.means();
            max_t = if left == right {
                0.0
            } else {
                f64::INFINITY.copysign(right - left)
            };
        }
        if cfg.verbose {
            // How big the difference is, not only how sure: the means of all samples so far, and
            // the medians of this batch, in ns.
            let (mean_left, mean_right) = stats.means();
            let median = |v: &mut Vec<u64>| {
                v.sort_unstable();
                v.get(v.len() / 2).copied().unwrap_or(0)
            };
            let (med_left, med_right) = (median(&mut left), median(&mut right));
            eprintln!(
                "  {name}: n={done} max_t={max_t:.2} \
                 mean_ns left={mean_left:.0} right={mean_right:.0} \
                 median_ns left={med_left} right={med_right}"
            );
        }
        if max_t.abs() > cfg.stop_t {
            if cfg.verbose {
                eprintln!("  {name}: stopped early, |t| is above {}", cfg.stop_t);
            }
            break;
        }
    }
    if hist {
        for (h, class) in hists.iter().zip([Class::Left, Class::Right]) {
            eprintln!("  {name}: {} {}", class_name(class), histogram(h));
        }
    }
    Ok(Measured {
        samples: done,
        max_t,
    })
}

/// `<count>x<samples>` for each distinct count, in order; past `HIST_SHOWN` of them, only the most
/// frequent.
fn histogram(h: &BTreeMap<u64, u64>) -> String {
    let (Some(lo), Some(hi)) = (h.keys().next(), h.keys().next_back()) else {
        return "no samples".to_string();
    };
    let mut shown: Vec<(u64, u64)> = h.iter().map(|(&c, &n)| (c, n)).collect();
    if shown.len() > HIST_SHOWN {
        shown.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        shown.truncate(HIST_SHOWN);
        shown.sort_unstable();
    }
    let list: Vec<String> = shown.iter().map(|(c, n)| format!("{c}x{n}")).collect();
    let more = if h.len() > HIST_SHOWN {
        " (most frequent only)"
    } else {
        ""
    };
    format!("{} distinct, {lo}..{hi}: {}{more}", h.len(), list.join(" "))
}

// ------------------------------------------------------------------------------------------
// Inputs
// ------------------------------------------------------------------------------------------

fn random_bytes(len: usize, rng: &mut BenchRng) -> Vec<u8> {
    let mut b = vec![0u8; len];
    rng.fill_bytes(&mut b);
    b
}

fn random_confounder(rng: &mut BenchRng) -> [u8; 16] {
    let mut b = [0u8; 16];
    rng.fill_bytes(&mut b);
    b
}

/// 16 bytes of printable ASCII (0x20..=0x7e).
fn random_password(rng: &mut BenchRng) -> [u8; 16] {
    let mut b = [0u8; 16];
    for c in &mut b {
        *c = 0x20 + u8::try_from(rng.next_u32() % 95).unwrap_or(0);
    }
    b
}

/// The fixed, public plaintext (or message): not a secret, the same in both classes.
fn plaintext() -> [u8; PLAINTEXT_LEN] {
    std::array::from_fn(|i| u8::try_from(i).unwrap_or(0))
}

fn usage() -> KeyUsage {
    KeyUsage::new(KEY_USAGE).expect("a nonzero key usage")
}

/// Fresh random raw key bytes, valid for the etype (DES3 needs odd parity and no weak key, which
/// only `ProtocolKey::random` makes). Right takes this for every sample; Left takes it once.
fn random_key_bytes(etype: EncryptionType, rng: &mut BenchRng) -> Vec<u8> {
    if etype == EncryptionType::Des3CbcSha1 {
        ProtocolKey::random(etype)
            .expect("a random DES3 key")
            .as_bytes()
            .to_vec()
    } else {
        random_bytes(etype.key_len(), rng)
    }
}

/// The key of one sample: the fixed key for Left, a fresh random one for Right. Both are built
/// from a fresh `Vec` of the raw bytes, so that the classes differ in the key alone.
fn sample_key(
    etype: EncryptionType,
    class: Class,
    fixed: &[u8],
    rng: &mut BenchRng,
) -> ProtocolKey {
    let bytes = if is_left(class) {
        fixed.to_vec()
    } else {
        random_key_bytes(etype, rng)
    };
    ProtocolKey::from_bytes(etype, &bytes).expect("a key")
}

// ------------------------------------------------------------------------------------------
// The ops
// ------------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Kind {
    Encrypt(EncryptionType),
    Decrypt(EncryptionType),
    ChecksumVerify,
    StringToKeyAes256,
    SpakeResult(SpakeGroup),
    EcdhP256,
    /// One RSA key from the kats, a fixed message against random messages.
    #[cfg(feature = "pk")]
    RsaMsg(pk::RsaPick),
    /// Two RSA keys from the kats, random messages for both.
    #[cfg(feature = "pk")]
    RsaKeys(pk::RsaPick),
    /// PKINIT's key exchange on one group: `KxKey::shared`.
    #[cfg(feature = "pk")]
    Kx(KxGroup),
    /// ECDSA with SHA-256 through `IdentityKey`.
    #[cfg(feature = "pk")]
    Ecdsa(pk::EcCurve),
    /// ECDSA on a brainpool curve with the nonce given: `hazmat::sign_prehashed(d, k, z)`.
    #[cfg(feature = "pk")]
    EcdsaK(pk::EcCurve),
    /// One crypto-bigint primitive of the RSA private op, alone, at a width in limbs.
    #[cfg(feature = "pk")]
    Prim(pk::Prim, usize),
}

struct OpDef {
    name: &'static str,
    kind: Kind,
    report_only: bool,
}

const fn op(name: &'static str, kind: Kind) -> OpDef {
    OpDef {
        name,
        kind,
        report_only: false,
    }
}

const fn report_only(name: &'static str, kind: Kind) -> OpDef {
    OpDef {
        name,
        kind,
        report_only: true,
    }
}

type E = EncryptionType;

/// Every op, in the order they run when no `--op` is given.
const OPS: &[OpDef] = &[
    op("aes128-sha1-enc", Kind::Encrypt(E::Aes128CtsHmacSha196)),
    op("aes128-sha1-dec", Kind::Decrypt(E::Aes128CtsHmacSha196)),
    op("aes256-sha1-enc", Kind::Encrypt(E::Aes256CtsHmacSha196)),
    op("aes256-sha1-dec", Kind::Decrypt(E::Aes256CtsHmacSha196)),
    op(
        "aes128-sha256-enc",
        Kind::Encrypt(E::Aes128CtsHmacSha256128),
    ),
    op(
        "aes128-sha256-dec",
        Kind::Decrypt(E::Aes128CtsHmacSha256128),
    ),
    op(
        "aes256-sha384-enc",
        Kind::Encrypt(E::Aes256CtsHmacSha384192),
    ),
    op(
        "aes256-sha384-dec",
        Kind::Decrypt(E::Aes256CtsHmacSha384192),
    ),
    op("cksum-verify", Kind::ChecksumVerify),
    op("s2k-aes256", Kind::StringToKeyAes256),
    op("spake-p256", Kind::SpakeResult(SpakeGroup::P256)),
    op("spake-ed25519", Kind::SpakeResult(SpakeGroup::Edwards25519)),
    op("ecdh-p256", Kind::EcdhP256),
    #[cfg(feature = "pk")]
    op("rsa-2048-msg", Kind::RsaMsg(pk::RsaPick::Bits2048)),
    #[cfg(feature = "pk")]
    op("rsa-2048-key", Kind::RsaKeys(pk::RsaPick::Bits2048)),
    #[cfg(feature = "pk")]
    op("rsa-8192-msg", Kind::RsaMsg(pk::RsaPick::Bits8192)),
    #[cfg(feature = "pk")]
    op("rsa-2048-3p-msg", Kind::RsaMsg(pk::RsaPick::Bits2048P3)),
    #[cfg(feature = "pk")]
    op("modp1024", Kind::Kx(KxGroup::Modp1024)),
    #[cfg(feature = "pk")]
    op("modp2048", Kind::Kx(KxGroup::Modp2048)),
    #[cfg(feature = "pk")]
    op("modp4096", Kind::Kx(KxGroup::Modp4096)),
    #[cfg(feature = "pk")]
    op("ecdh-p256-pk", Kind::Kx(KxGroup::P256)),
    #[cfg(feature = "pk")]
    op("ecdh-p384", Kind::Kx(KxGroup::P384)),
    #[cfg(feature = "pk")]
    op("ecdh-p521", Kind::Kx(KxGroup::P521)),
    #[cfg(feature = "pk")]
    op("ecdsa-p224", Kind::Ecdsa(pk::P224)),
    #[cfg(feature = "pk")]
    op("ecdsa-p256", Kind::Ecdsa(pk::P256)),
    #[cfg(feature = "pk")]
    op("ecdsa-p384", Kind::Ecdsa(pk::P384)),
    #[cfg(feature = "pk")]
    op("ecdsa-p521", Kind::Ecdsa(pk::P521)),
    #[cfg(feature = "pk")]
    op("ecdsa-secp256k1", Kind::Ecdsa(pk::K256)),
    #[cfg(feature = "pk")]
    report_only("ecdsa-bp256r1", Kind::Ecdsa(pk::BP256R1)),
    #[cfg(feature = "pk")]
    report_only("ecdsa-bp256t1", Kind::Ecdsa(pk::BP256T1)),
    #[cfg(feature = "pk")]
    report_only("ecdsa-bp384r1", Kind::Ecdsa(pk::BP384R1)),
    #[cfg(feature = "pk")]
    report_only("ecdsa-bp384t1", Kind::Ecdsa(pk::BP384T1)),
    #[cfg(feature = "pk")]
    report_only("ecdsa-bp512r1", Kind::Ecdsa(pk::BP512R1)),
    #[cfg(feature = "pk")]
    report_only("ecdsa-bp512t1", Kind::Ecdsa(pk::BP512T1)),
    #[cfg(feature = "pk")]
    op("ecdsa-bp256r1-k", Kind::EcdsaK(pk::BP256R1)),
    #[cfg(feature = "pk")]
    op("ecdsa-bp256t1-k", Kind::EcdsaK(pk::BP256T1)),
    #[cfg(feature = "pk")]
    op("ecdsa-bp384r1-k", Kind::EcdsaK(pk::BP384R1)),
    #[cfg(feature = "pk")]
    op("ecdsa-bp384t1-k", Kind::EcdsaK(pk::BP384T1)),
    #[cfg(feature = "pk")]
    op("ecdsa-bp512r1-k", Kind::EcdsaK(pk::BP512R1)),
    #[cfg(feature = "pk")]
    op("ecdsa-bp512t1-k", Kind::EcdsaK(pk::BP512T1)),
    report_only("des3-enc", Kind::Encrypt(E::Des3CbcSha1)),
    report_only("des3-dec", Kind::Decrypt(E::Des3CbcSha1)),
    report_only("rc4-enc", Kind::Encrypt(E::Rc4Hmac)),
    report_only("rc4-dec", Kind::Decrypt(E::Rc4Hmac)),
    report_only("cam128-enc", Kind::Encrypt(E::Camellia128CtsCmac)),
    report_only("cam128-dec", Kind::Decrypt(E::Camellia128CtsCmac)),
    report_only("cam256-enc", Kind::Encrypt(E::Camellia256CtsCmac)),
    report_only("cam256-dec", Kind::Decrypt(E::Camellia256CtsCmac)),
];

/// `cb-<name>-<limbs>` for each width the RSA private op runs at (RSA-1024 to 8192, primes and n).
#[cfg(feature = "pk")]
macro_rules! prim_ops {
    ($($prim:ident $name:literal),*) => {
        &[$(
            op(concat!("cb-", $name, "-8"), Kind::Prim(pk::Prim::$prim, 8)),
            op(concat!("cb-", $name, "-16"), Kind::Prim(pk::Prim::$prim, 16)),
            op(concat!("cb-", $name, "-24"), Kind::Prim(pk::Prim::$prim, 24)),
            op(concat!("cb-", $name, "-32"), Kind::Prim(pk::Prim::$prim, 32)),
            op(concat!("cb-", $name, "-48"), Kind::Prim(pk::Prim::$prim, 48)),
            op(concat!("cb-", $name, "-64"), Kind::Prim(pk::Prim::$prim, 64)),
            op(concat!("cb-", $name, "-96"), Kind::Prim(pk::Prim::$prim, 96)),
            op(concat!("cb-", $name, "-128"), Kind::Prim(pk::Prim::$prim, 128)),
        )*]
    };
}

/// Ops that run only when `--op` names them: the RSA private op's primitives, one at a time.
#[cfg(feature = "pk")]
const ON_DEMAND: &[OpDef] = prim_ops!(
    Sub "sub", Garner "garner", Pow "pow", Invert "invert", Rem "rem", Params "params", New "new",
    Retrieve "retrieve"
);
#[cfg(not(feature = "pk"))]
const ON_DEMAND: &[OpDef] = &[];

fn all_ops() -> impl Iterator<Item = &'static OpDef> {
    OPS.iter().chain(ON_DEMAND)
}

fn run_op(def: &OpDef, cfg: &Cfg, rng: &mut BenchRng) -> Result<Measured, String> {
    match def.kind {
        Kind::Encrypt(etype) => bench_encrypt(def.name, etype, cfg, rng),
        Kind::Decrypt(etype) => bench_decrypt(def.name, etype, cfg, rng),
        Kind::ChecksumVerify => bench_checksum_verify(def.name, cfg, rng),
        Kind::StringToKeyAes256 => bench_string_to_key(def.name, cfg, rng),
        Kind::SpakeResult(group) => bench_spake_result(def.name, group, cfg, rng),
        Kind::EcdhP256 => bench_ecdh_p256(def.name, cfg, rng),
        #[cfg(feature = "pk")]
        Kind::RsaMsg(pick) => pk::bench_rsa_msg(def.name, pick, cfg, rng),
        #[cfg(feature = "pk")]
        Kind::RsaKeys(pick) => pk::bench_rsa_keys(def.name, pick, cfg, rng),
        #[cfg(feature = "pk")]
        Kind::Kx(group) => pk::bench_kx(def.name, group, cfg, rng),
        #[cfg(feature = "pk")]
        Kind::Ecdsa(curve) => pk::bench_ecdsa(def.name, curve, cfg, rng),
        #[cfg(feature = "pk")]
        Kind::EcdsaK(curve) => pk::bench_ecdsa_k(def.name, curve, cfg, rng),
        #[cfg(feature = "pk")]
        Kind::Prim(prim, limbs) => pk::bench_prim(def.name, prim, limbs, cfg, rng),
    }
}

/// Secret: the key. `encrypt_with_confounder` is used rather than `encrypt` so that the
/// confounder is drawn here, outside the timed region, and not by a `getrandom` call inside it;
/// it is random for every sample in both classes, as `encrypt` would draw it.
fn bench_encrypt(
    name: &str,
    etype: EncryptionType,
    cfg: &Cfg,
    rng: &mut BenchRng,
) -> Result<Measured, String> {
    struct Input {
        key: ProtocolKey,
        confounder: [u8; 16],
    }
    let usage = usage();
    let pt = plaintext();
    let fixed = random_key_bytes(etype, rng);
    measure(
        name,
        cfg,
        rng,
        |class, rng| Input {
            key: sample_key(etype, class, &fixed, rng),
            confounder: random_confounder(rng),
        },
        |i| encrypt_with_confounder(&i.key, usage, &i.confounder, &pt),
        |_, r| r.is_ok(),
    )
}

/// Secret: the key. Each sample's ciphertext is made beforehand with that sample's key (and a
/// random confounder, so the ciphertexts of both classes look alike).
fn bench_decrypt(
    name: &str,
    etype: EncryptionType,
    cfg: &Cfg,
    rng: &mut BenchRng,
) -> Result<Measured, String> {
    struct Input {
        key: ProtocolKey,
        ciphertext: Vec<u8>,
    }
    let usage = usage();
    let pt = plaintext();
    let fixed = random_key_bytes(etype, rng);
    measure(
        name,
        cfg,
        rng,
        |class, rng| {
            let key = sample_key(etype, class, &fixed, rng);
            let ciphertext = encrypt_with_confounder(&key, usage, &random_confounder(rng), &pt)
                .expect("encrypt");
            Input { key, ciphertext }
        },
        |i| decrypt(&i.key, usage, &i.ciphertext),
        |_, r| matches!(r, Ok(p) if p.as_slice() == pt.as_slice()),
    )
}

/// Secret: where the compared checksum first differs from the correct one. One fixed key and
/// message, and EVERY sample is rejected (a sample that is accepted aborts the op), so the accept
/// and reject paths are not what is compared. Left is one fixed wrong hmac-sha1-96-aes256
/// checksum, chosen once: the correct one with its last byte flipped (xor 0x01), which agrees
/// with it everywhere but at the end. Right is random bytes of the same length, fresh for each
/// sample, which differ from the correct one at the first byte 255 times in 256. A compare that
/// stops at the first mismatch is slower for Left.
fn bench_checksum_verify(name: &str, cfg: &Cfg, rng: &mut BenchRng) -> Result<Measured, String> {
    let etype = EncryptionType::Aes256CtsHmacSha196;
    let cksumtype = etype.checksum_type();
    let usage = usage();
    let msg = plaintext();
    let key = ProtocolKey::from_bytes(etype, &random_bytes(etype.key_len(), rng)).expect("key");
    let good = checksum(&key, usage, &msg).map_err(|e| format!("{name}: checksum: {e}"))?;
    let mut wrong = good.clone();
    if let Some(last) = wrong.last_mut() {
        *last ^= 0x01;
    }
    measure_each(
        name,
        cfg,
        rng,
        |class, rng| {
            if is_left(class) {
                wrong.clone()
            } else {
                random_bytes(good.len(), rng)
            }
        },
        |mac| verify_checksum_keyed(&key, usage, &msg, cksumtype, mac),
        |_, r| matches!(r, Err(Error::Integrity)),
    )
}

/// Secret: the password, 16 bytes of printable ASCII. Fixed salt, and `S2K_ITERATIONS`.
fn bench_string_to_key(name: &str, cfg: &Cfg, rng: &mut BenchRng) -> Result<Measured, String> {
    let etype = EncryptionType::Aes256CtsHmacSha196;
    let salt = b"KERBER.TESTtiminguser";
    let params = S2K_ITERATIONS.to_be_bytes();
    let fixed = random_password(rng);
    measure(
        name,
        cfg,
        rng,
        |class, rng| {
            if is_left(class) {
                fixed
            } else {
                random_password(rng)
            }
        },
        |password| string_to_key(etype, password, salt, Some(&params[..])),
        |_, r| r.is_ok(),
    )
}

/// Secret: the private scalar of our side, in `spake_result` (the scalar multiplication of the
/// peer's element). Fixed w and fixed peer public. Both classes take their private value from
/// the crate's own `spake_keygen`, so it is valid and shaped as in use for the group.
fn bench_spake_result(
    name: &str,
    group: SpakeGroup,
    cfg: &Cfg,
    rng: &mut BenchRng,
) -> Result<Measured, String> {
    let w = random_bytes(group.mult_len(), rng);
    let (_peer_private, peer_public) =
        spake_keygen(group, &w, true).map_err(|e| format!("{name}: peer keygen: {e}"))?;
    let (fixed, _) = spake_keygen(group, &w, false).map_err(|e| format!("{name}: keygen: {e}"))?;
    let fixed = fixed.to_vec();
    measure(
        name,
        cfg,
        rng,
        |class, _| {
            if is_left(class) {
                fixed.clone()
            } else {
                spake_keygen(group, &w, false).expect("keygen").0.to_vec()
            }
        },
        |ourpriv| spake_result(group, &w, ourpriv, &peer_public, false),
        |_, r| r.is_ok(),
    )
}

/// Secret: the 32-byte P-256 scalar, in `p256_shared` (PKINIT ECDH). Fixed peer public. Both
/// classes take the scalar from `p256_generate`.
fn bench_ecdh_p256(name: &str, cfg: &Cfg, rng: &mut BenchRng) -> Result<Measured, String> {
    let peer = p256_generate().map_err(|e| format!("{name}: peer keygen: {e}"))?;
    let peer_public = peer.public.clone();
    let fixed = p256_generate()
        .map_err(|e| format!("{name}: keygen: {e}"))?
        .secret;
    measure(
        name,
        cfg,
        rng,
        |class, _| {
            if is_left(class) {
                fixed
            } else {
                p256_generate().expect("keygen").secret
            }
        },
        |secret| p256_shared(secret, &peer_public),
        |_, r| r.is_ok(),
    )
}

// ------------------------------------------------------------------------------------------
// The PKINIT ops: krb5_types::pkinit
// ------------------------------------------------------------------------------------------

/// The ops of the PKINIT code of krb5-types (RSA signing, the key exchange on MIT's six groups,
/// ECDSA with SHA-256), which a tree has once it carries the PK chain.
#[cfg(feature = "pk")]
mod pk {
    use dudect_bencher::rand::Rng;
    use dudect_bencher::BenchRng;
    use krb5_types::pkinit::{IdentityKey, KxGroup, KxKey, RsaKey};

    use crypto_bigint::modular::{FixedMontyForm, FixedMontyParams};
    use crypto_bigint::{Odd, Uint};
    use dudect_bencher::Class;

    use super::{is_left, measure, plaintext, random_bytes, Cfg, Measured};

    /// The RSA private keys of the tree's own test data (`crates/krb5-types/tests/data`), read
    /// when the binary is built: OpenSSL's, of several sizes and prime counts (and two 2048-bit
    /// keys with a wrong CRT value, which are not used), and Wycheproof's, of 2048, 3072 and 4096
    /// bits, some of them with e = 3.
    const KAT_OPENSSL: &str =
        include_str!("../../../../crates/krb5-types/tests/data/openssl-rsa-pkcs1-sha256.kat");
    const KAT_WYCHEPROOF: &str =
        include_str!("../../../../crates/krb5-types/tests/data/wycheproof-rsa-pkcs1-sha256.kat");

    /// Which RSA key or keys of the kats an op takes.
    #[derive(Clone, Copy)]
    pub enum RsaPick {
        /// 2048 bits, two primes, from Wycheproof's kat: for `-msg` its key with e = 65537, for
        /// `-key` its two keys with e = 3. (OpenSSL's kat has no sound key of this size and prime
        /// count: its two 2048-bit two-prime keys have a wrong CRT value.)
        Bits2048,
        /// 8192 bits, two primes: the one key of OpenSSL's kat.
        Bits8192,
        /// 2048 bits, three primes: the one key of OpenSSL's kat.
        Bits2048P3,
    }

    struct KatKey {
        der: Vec<u8>,
        /// Bits of the modulus, the public exponent, and the number of primes.
        bits: usize,
        e: u64,
        primes: usize,
        /// The message and the signature of the key's first test case in the kat.
        tc: Option<(Vec<u8>, Vec<u8>)>,
    }

    fn hex(s: &str) -> Option<Vec<u8>> {
        if s == "-" {
            return Some(Vec::new());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
            .collect()
    }

    /// One DER element: its tag, its body, and what follows it.
    fn der(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
        let tag = *b.first()?;
        let first = *b.get(1)?;
        let (len, at) = if first < 0x80 {
            (usize::from(first), 2)
        } else {
            let n = usize::from(first & 0x7f);
            let digits = b.get(2..2 + n)?;
            let len = digits.iter().try_fold(0usize, |acc, &d| {
                acc.checked_mul(256)?.checked_add(usize::from(d))
            })?;
            (len, 2 + n)
        };
        let end = at.checked_add(len)?;
        Some((tag, b.get(at..end)?, b.get(end..)?))
    }

    /// The bits of the modulus, the public exponent and the number of primes of a PKCS#8 RSA key.
    fn rsa_shape(pkcs8: &[u8]) -> Option<(usize, u64, usize)> {
        let (0x30, info, _) = der(pkcs8)? else {
            return None;
        };
        let (0x02, _, rest) = der(info)? else {
            return None;
        };
        let (0x30, _, rest) = der(rest)? else {
            return None;
        };
        let (0x04, key, _) = der(rest)? else {
            return None;
        };
        let (0x30, mut rest, _) = der(key)? else {
            return None;
        };
        let mut ints = Vec::new();
        let mut others = 0;
        while !rest.is_empty() {
            let (tag, body, next) = der(rest)?;
            match tag {
                0x02 => ints.push(body),
                0x30 => {
                    let mut infos = body;
                    while !infos.is_empty() {
                        infos = der(infos)?.2;
                        others += 1;
                    }
                }
                _ => return None,
            }
            rest = next;
        }
        let [_version, n, e, ..] = ints[..] else {
            return None;
        };
        let n = &n[n.iter().take_while(|b| **b == 0).count()..];
        let bits = n.len() * 8 - usize::try_from(n.first()?.leading_zeros()).ok()?;
        let e = e.iter().try_fold(0u64, |acc, &d| {
            acc.checked_mul(256)?.checked_add(u64::from(d))
        })?;
        Some((bits, e, 2 + others))
    }

    /// The keys of a kat in file order, each with the first test case after it, as the vectors
    /// test of krb5-types (`tests/rsa_sign_vectors.rs`) reads the file.
    fn parse_kat(text: &str) -> Result<Vec<KatKey>, String> {
        let mut keys: Vec<KatKey> = Vec::new();
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            match line.split(' ').collect::<Vec<_>>()[..] {
                ["key", key] => {
                    let der = hex(key).ok_or("a key of a kat is not hex")?;
                    let (bits, e, primes) =
                        rsa_shape(&der).ok_or("a key of a kat is not a PKCS#8 RSA key")?;
                    keys.push(KatKey {
                        der,
                        bits,
                        e,
                        primes,
                        tc: None,
                    });
                }
                ["tc", _, msg, sig] => {
                    if let Some(key) = keys.last_mut().filter(|k| k.tc.is_none()) {
                        let msg = hex(msg).ok_or("a message of a kat is not hex")?;
                        let sig = hex(sig).ok_or("a signature of a kat is not hex")?;
                        key.tc = Some((msg, sig));
                    }
                }
                ["refuse", ..] => {}
                _ => return Err(format!("a line of a kat is not understood: {line}")),
            }
        }
        Ok(keys)
    }

    /// The key or keys an op takes from the kats, and the length of a signature. Each key must
    /// reproduce the signature its kat gives for its first test case.
    fn rsa_keys(name: &str, pick: RsaPick, pair: bool) -> Result<(Vec<RsaKey>, usize), String> {
        let (kat, bits, primes, e, count) = match (pick, pair) {
            (RsaPick::Bits2048, false) => (KAT_WYCHEPROOF, 2048, 2, 65537, 1),
            (RsaPick::Bits2048, true) => (KAT_WYCHEPROOF, 2048, 2, 3, 2),
            (RsaPick::Bits8192, false) => (KAT_OPENSSL, 8192, 2, 65537, 1),
            (RsaPick::Bits2048P3, false) => (KAT_OPENSSL, 2048, 3, 65537, 1),
            (RsaPick::Bits8192 | RsaPick::Bits2048P3, true) => {
                return Err(format!(
                    "{name}: the kat has one key of this size and prime count"
                ));
            }
        };
        let found: Vec<KatKey> = parse_kat(kat)?
            .into_iter()
            .filter(|k| k.bits == bits && k.primes == primes && k.e == e)
            .take(count)
            .collect();
        if found.len() < count {
            return Err(format!(
                "{name}: the kat has {} key(s) of {bits} bits, {primes} primes and e = {e}, not \
                 {count}",
                found.len()
            ));
        }
        let mut keys = Vec::new();
        for kat_key in &found {
            let key = RsaKey::from_pkcs8(&kat_key.der)
                .ok_or_else(|| format!("{name}: a key of the kat does not load"))?;
            if let Some((msg, sig)) = &kat_key.tc {
                if key.sign_sha256(msg).as_deref() != Some(sig.as_slice()) {
                    return Err(format!(
                        "{name}: a key of the kat does not reproduce the signature of the kat"
                    ));
                }
            }
            keys.push(key);
        }
        Ok((keys, bits.div_ceil(8)))
    }

    fn random_msg(rng: &mut BenchRng) -> [u8; 32] {
        let mut m = [0u8; 32];
        rng.fill_bytes(&mut m);
        m
    }

    /// One key. The message is the only thing that differs: Left signs one fixed message, Right
    /// a fresh random one for each sample, both of 32 bytes.
    pub fn bench_rsa_msg(
        name: &str,
        pick: RsaPick,
        cfg: &Cfg,
        rng: &mut BenchRng,
    ) -> Result<Measured, String> {
        let (keys, len) = rsa_keys(name, pick, false)?;
        let key = &keys[0];
        let fixed = random_msg(rng);
        measure(
            name,
            cfg,
            rng,
            |class, rng| {
                if is_left(class) {
                    fixed
                } else {
                    random_msg(rng)
                }
            },
            |msg| key.sign_sha256(msg),
            |_, r| r.as_ref().is_some_and(|s| s.len() == len),
        )
    }

    /// Secret: the key. Two keys of the same size and prime count; Left signs with the first,
    /// Right with the second, and both sign fresh random messages of 32 bytes.
    pub fn bench_rsa_keys(
        name: &str,
        pick: RsaPick,
        cfg: &Cfg,
        rng: &mut BenchRng,
    ) -> Result<Measured, String> {
        let (keys, len) = rsa_keys(name, pick, true)?;
        measure(
            name,
            cfg,
            rng,
            |class, rng| {
                let key = if is_left(class) { &keys[0] } else { &keys[1] };
                (key, random_msg(rng))
            },
            |(key, msg)| key.sign_sha256(msg),
            |_, r| r.as_ref().is_some_and(|s| s.len() == len),
        )
    }

    /// The length of the secret `KxKey::generate` draws for a group, and the mask it applies to
    /// the first byte (kx.rs).
    fn kx_shape(group: KxGroup) -> (usize, u8) {
        match group {
            KxGroup::P256 | KxGroup::Modp2048 | KxGroup::Modp1024 => (32, 0xff),
            KxGroup::P384 | KxGroup::Modp4096 => (48, 0xff),
            KxGroup::P521 => (66, 0x01),
        }
    }

    /// A secret drawn as `KxKey::generate` draws it, and its key: drawn again until
    /// `KxKey::from_secret` takes it (it refuses a scalar that is zero or not below the order).
    fn random_kx(group: KxGroup, rng: &mut BenchRng) -> Option<(Vec<u8>, KxKey)> {
        let (len, mask) = kx_shape(group);
        (0..64).find_map(|_| {
            let mut secret = random_bytes(len, rng);
            secret[0] &= mask;
            KxKey::from_secret(group, &secret).map(|key| (secret, key))
        })
    }

    /// Secret: the exponent, or the scalar, of the key; `shared` is the timed call. The peer
    /// public value is fixed, from another key. Every sample's key is built with `from_secret`
    /// outside the timer, which costs an exponentiation or a scalar multiplication.
    pub fn bench_kx(
        name: &str,
        group: KxGroup,
        cfg: &Cfg,
        rng: &mut BenchRng,
    ) -> Result<Measured, String> {
        let (fixed, _) =
            random_kx(group, rng).ok_or_else(|| format!("{name}: no secret was taken"))?;
        let (_, other) =
            random_kx(group, rng).ok_or_else(|| format!("{name}: no secret was taken"))?;
        let peer = other.public().to_vec();
        measure(
            name,
            cfg,
            rng,
            |class, rng| {
                if is_left(class) {
                    KxKey::from_secret(group, &fixed).expect("the fixed secret")
                } else {
                    random_kx(group, rng).expect("a secret").1
                }
            },
            |key| key.shared(&peer),
            |_, r| r.is_some(),
        )
    }

    /// An ECDSA curve: its OID (the body), the length of its scalar, and the mask of the first
    /// byte of a random one.
    #[derive(Clone, Copy)]
    pub struct EcCurve {
        oid: &'static [u8],
        len: usize,
        mask: u8,
    }

    pub const P224: EcCurve = EcCurve {
        oid: &[0x2b, 0x81, 0x04, 0x00, 0x21],
        len: 28,
        mask: 0xff,
    };
    pub const P256: EcCurve = EcCurve {
        oid: &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        len: 32,
        mask: 0xff,
    };
    pub const P384: EcCurve = EcCurve {
        oid: &[0x2b, 0x81, 0x04, 0x00, 0x22],
        len: 48,
        mask: 0xff,
    };
    pub const P521: EcCurve = EcCurve {
        oid: &[0x2b, 0x81, 0x04, 0x00, 0x23],
        len: 66,
        mask: 0x01,
    };
    pub const K256: EcCurve = EcCurve {
        oid: &[0x2b, 0x81, 0x04, 0x00, 0x0a],
        len: 32,
        mask: 0xff,
    };
    pub const BP256R1: EcCurve = EcCurve {
        oid: &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07],
        len: 32,
        mask: 0xff,
    };
    pub const BP256T1: EcCurve = EcCurve {
        oid: &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x08],
        len: 32,
        mask: 0xff,
    };
    pub const BP384R1: EcCurve = EcCurve {
        oid: &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b],
        len: 48,
        mask: 0xff,
    };
    pub const BP384T1: EcCurve = EcCurve {
        oid: &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0c],
        len: 48,
        mask: 0xff,
    };
    pub const BP512R1: EcCurve = EcCurve {
        oid: &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d],
        len: 64,
        mask: 0xff,
    };
    pub const BP512T1: EcCurve = EcCurve {
        oid: &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0e],
        len: 64,
        mask: 0xff,
    };

    /// A DER element.
    fn wrap(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match u8::try_from(body.len()) {
            Ok(n) if n < 0x80 => out.push(n),
            Ok(n) => out.extend_from_slice(&[0x81, n]),
            Err(_) => {
                let n = u16::try_from(body.len()).expect("a short element");
                out.push(0x82);
                out.extend_from_slice(&n.to_be_bytes());
            }
        }
        out.extend_from_slice(body);
        out
    }

    /// The PKCS#8 PrivateKeyInfo (RFC 5958) of an ECPrivateKey (RFC 5915) that holds the scalar
    /// alone: its public key is optional.
    fn ec_pkcs8(curve: EcCurve, scalar: &[u8]) -> Vec<u8> {
        const ID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
        let private = wrap(0x30, &[wrap(0x02, &[1]), wrap(0x04, scalar)].concat());
        let algorithm = wrap(
            0x30,
            &[wrap(0x06, ID_EC_PUBLIC_KEY), wrap(0x06, curve.oid)].concat(),
        );
        wrap(
            0x30,
            &[wrap(0x02, &[0]), algorithm, wrap(0x04, &private)].concat(),
        )
    }

    /// A PKCS#8 key of a random scalar, and its `IdentityKey`: drawn again until
    /// `IdentityKey::from_pkcs8` takes it (it refuses a scalar that is zero or not below the
    /// order).
    fn random_identity(curve: EcCurve, rng: &mut BenchRng) -> Option<(Vec<u8>, IdentityKey)> {
        (0..64).find_map(|_| {
            let mut scalar = random_bytes(curve.len, rng);
            scalar[0] &= curve.mask;
            let der = ec_pkcs8(curve, &scalar);
            IdentityKey::from_pkcs8(&der).map(|key| (der, key))
        })
    }

    /// The signing of krb5-types' `p*_sign` without its DER: `SigningKey::from_bytes`, then
    /// `sign_prehash`, returning the fixed-size (r, s). DER's length follows the public signature,
    /// so in the timer it makes every RFC 6979 curve's classes differ in work that says nothing
    /// about the key. P-521 is not here: our signer draws a random nonce in both classes.
    fn sign_bare(curve: &EcCurve, scalar: &[u8], hash: &[u8; 32]) -> bool {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        macro_rules! sign {
            ($c:ident, $n:literal) => {{
                let Ok(k) = <&[u8; $n]>::try_from(scalar) else {
                    return false;
                };
                let Ok(sk) = $c::ecdsa::SigningKey::from_bytes(k.into()) else {
                    return false;
                };
                let sig: Option<$c::ecdsa::Signature> = sk.sign_prehash(hash).ok();
                std::hint::black_box(sig).is_some()
            }};
        }
        // The brainpool curves, as krb5-types' `ecdsa_sign!` signs on them.
        macro_rules! sign_c {
            ($c:ty, $n:literal) => {{
                let Ok(k) = <&[u8; $n]>::try_from(scalar) else {
                    return false;
                };
                let Ok(sk) = ecdsa::SigningKey::<$c>::from_bytes(k.into()) else {
                    return false;
                };
                let sig: Option<ecdsa::Signature<$c>> = sk.sign_prehash(hash).ok();
                std::hint::black_box(sig).is_some()
            }};
        }
        match curve.oid {
            o if o == P224.oid => sign!(p224, 28),
            o if o == P256.oid => sign!(p256, 32),
            o if o == P384.oid => sign!(p384, 48),
            o if o == K256.oid => sign!(k256, 32),
            o if o == BP256R1.oid => sign_c!(bp256::r1::BrainpoolP256r1, 32),
            o if o == BP256T1.oid => sign_c!(bp256::t1::BrainpoolP256t1, 32),
            o if o == BP384R1.oid => sign_c!(bp384::r1::BrainpoolP384r1, 48),
            o if o == BP384T1.oid => sign_c!(bp384::t1::BrainpoolP384t1, 48),
            o if o == BP512R1.oid => sign_c!(krb5_brainpool::p512::r1::BrainpoolP512r1, 64),
            o if o == BP512T1.oid => sign_c!(krb5_brainpool::p512::t1::BrainpoolP512t1, 64),
            _ => false,
        }
    }

    /// A random scalar the curve takes as a key (`IdentityKey::from_pkcs8` checks it).
    fn random_scalar(curve: &EcCurve, rng: &mut BenchRng) -> Option<Vec<u8>> {
        (0..64).find_map(|_| {
            let mut scalar = random_bytes(curve.len, rng);
            scalar[0] &= curve.mask;
            IdentityKey::from_pkcs8(&ec_pkcs8(*curve, &scalar)).map(|_| scalar)
        })
    }

    /// Secret: the private key. P-224, P-256, P-384, secp256k1 and brainpool time `sign_bare`
    /// (above) on a raw scalar; P-521 times `IdentityKey::sign_sha256`. Left is one fixed key (a
    /// random scalar chosen once) and Right a fresh random key for each sample. The message is
    /// fixed.
    /// A crypto-bigint 0.7 primitive that the RSA private op (`pkinit/rsa.rs`) runs on secret
    /// values, timed alone: the op's blinding makes its inner values random in both classes, so a
    /// branch on them shows only here. Left is one input, Right a fresh one for each sample.
    #[derive(Clone, Copy)]
    pub enum Prim {
        /// `FixedMontyForm::sub`, which Garner's step took before it stopped (the branch it had).
        Sub,
        /// Garner's step as `garner_at` takes it: `add_mod(m, p - a)`, into Montgomery form,
        /// times t.
        Garner,
        /// `pow_bounded_exp`, its base and full-width exponent secret (c^dp mod p).
        Pow,
        /// `invert` (the blinding factor's inverse mod n).
        Invert,
        /// `Uint::rem`, both values secret (c mod p; the blinding factor mod n).
        Rem,
        /// `FixedMontyParams::new` on a secret modulus (each prime).
        Params,
        /// `FixedMontyForm::new` (into Montgomery form).
        New,
        /// `FixedMontyForm::retrieve` (out of Montgomery form).
        Retrieve,
    }

    pub fn bench_prim(
        name: &str,
        prim: Prim,
        limbs: usize,
        cfg: &Cfg,
        rng: &mut BenchRng,
    ) -> Result<Measured, String> {
        match limbs {
            8 => prim_at::<8>(name, prim, cfg, rng),
            16 => prim_at::<16>(name, prim, cfg, rng),
            24 => prim_at::<24>(name, prim, cfg, rng),
            32 => prim_at::<32>(name, prim, cfg, rng),
            48 => prim_at::<48>(name, prim, cfg, rng),
            64 => prim_at::<64>(name, prim, cfg, rng),
            96 => prim_at::<96>(name, prim, cfg, rng),
            128 => prim_at::<128>(name, prim, cfg, rng),
            _ => Err(format!("{name}: no width of {limbs} limbs")),
        }
    }

    fn words<const W: usize>(rng: &mut BenchRng) -> [u64; W] {
        std::array::from_fn(|_| rng.next_u64())
    }

    /// A value below every modulus `modulus` makes: its top two bits clear.
    fn below<const W: usize>(rng: &mut BenchRng) -> Uint<W> {
        let mut w = words::<W>(rng);
        w[W - 1] >>= 2;
        Uint::from_words(w)
    }

    /// An odd modulus with its top two bits set, as an RSA prime or modulus has them.
    fn modulus<const W: usize>(rng: &mut BenchRng) -> Odd<Uint<W>> {
        let mut w = words::<W>(rng);
        w[0] |= 1;
        w[W - 1] |= 3 << 62;
        Odd::new(Uint::from_words(w))
            .into_option()
            .expect("an odd value")
    }

    /// Left's one input, or a fresh one for Right.
    fn pick<T>(class: Class, fixed: T, fresh: impl FnOnce() -> T) -> T {
        if is_left(class) {
            fixed
        } else {
            fresh()
        }
    }

    fn any<R>(_: Class, _: &R) -> bool {
        true
    }

    fn prim_at<const W: usize>(
        name: &str,
        prim: Prim,
        cfg: &Cfg,
        rng: &mut BenchRng,
    ) -> Result<Measured, String> {
        let p = modulus::<W>(rng);
        let (pu, p_nz) = (*p.as_ref(), *p.as_nz_ref());
        let params = FixedMontyParams::new(p);
        let monty = |rng: &mut BenchRng| FixedMontyForm::new(&below::<W>(rng), &params);
        match prim {
            Prim::Sub => {
                let fixed = (monty(rng), monty(rng));
                let prep = |c, rng: &mut BenchRng| pick(c, fixed, || (monty(rng), monty(rng)));
                measure(name, cfg, rng, prep, |(a, b)| a.sub(b), any)
            }
            Prim::Garner => {
                let t = monty(rng);
                let fixed = (below::<W>(rng), below::<W>(rng));
                let prep = |c, rng: &mut BenchRng| pick(c, fixed, || (below(rng), below(rng)));
                let op = |(m, a): &(Uint<W>, Uint<W>)| {
                    let d = m.add_mod(&pu.wrapping_sub(a), &p_nz);
                    FixedMontyForm::new(&d, &params).mul(&t).retrieve()
                };
                measure(name, cfg, rng, prep, op, any)
            }
            Prim::Pow => {
                let fixed = (monty(rng), below::<W>(rng));
                let prep = |c, rng: &mut BenchRng| pick(c, fixed, || (monty(rng), below(rng)));
                let bits = u32::try_from(W * 64).expect("a width");
                let op = |(b, e): &(FixedMontyForm<W>, Uint<W>)| b.pow_bounded_exp(e, bits);
                measure(name, cfg, rng, prep, op, any)
            }
            Prim::Invert => {
                let fixed = monty(rng);
                let prep = |c, rng: &mut BenchRng| pick(c, fixed, || monty(rng));
                measure(name, cfg, rng, prep, |x| x.invert(), any)
            }
            Prim::Rem => {
                let fresh = |rng: &mut BenchRng| {
                    let m = modulus::<W>(rng);
                    (Uint::<W>::from_words(words(rng)), *m.as_nz_ref())
                };
                let fixed = fresh(rng);
                let prep = |c, rng: &mut BenchRng| pick(c, fixed, || fresh(rng));
                measure(name, cfg, rng, prep, |(x, m)| x.rem(m), any)
            }
            Prim::Params => {
                let fixed = modulus::<W>(rng);
                let prep = |c, rng: &mut BenchRng| pick(c, fixed, || modulus(rng));
                measure(name, cfg, rng, prep, |m| FixedMontyParams::new(*m), any)
            }
            Prim::New => {
                let fixed = below::<W>(rng);
                let prep = |c, rng: &mut BenchRng| pick(c, fixed, || below(rng));
                let op = |x: &Uint<W>| FixedMontyForm::new(x, &params);
                measure(name, cfg, rng, prep, op, any)
            }
            Prim::Retrieve => {
                let fixed = monty(rng);
                let prep = |c, rng: &mut BenchRng| pick(c, fixed, || monty(rng));
                measure(name, cfg, rng, prep, |x| x.retrieve(), any)
            }
        }
    }

    /// Secret: the private key d and the nonce k, fixed in Left and fresh in Right. RFC 6979
    /// draws k again while it is at or above n, about a third of the time on a brainpool order,
    /// so `ecdsa-bp*` differ per class by whole HMAC-DRBG rounds; this times the arithmetic alone.
    pub fn bench_ecdsa_k(
        name: &str,
        curve: EcCurve,
        cfg: &Cfg,
        rng: &mut BenchRng,
    ) -> Result<Measured, String> {
        macro_rules! bench {
            ($c:ty) => {{
                type Nz = ecdsa::elliptic_curve::NonZeroScalar<$c>;
                let nz = |rng: &mut BenchRng| -> Option<Nz> {
                    (0..64).find_map(|_| {
                        let b = random_bytes(curve.len, rng);
                        let repr =
                            ecdsa::elliptic_curve::FieldBytes::<$c>::try_from(&b[..]).ok()?;
                        Nz::from_repr(repr).into_option()
                    })
                };
                let fixed = nz(rng)
                    .zip(nz(rng))
                    .ok_or_else(|| format!("{name}: no scalar was taken"))?;
                let hash = [0x42u8; 32];
                measure(
                    name,
                    cfg,
                    rng,
                    |class, rng| {
                        if is_left(class) {
                            fixed
                        } else {
                            nz(rng).zip(nz(rng)).expect("a scalar")
                        }
                    },
                    |(d, k)| ecdsa::hazmat::sign_prehashed::<$c>(d, k, &hash).is_ok(),
                    |_, ok| *ok,
                )
            }};
        }
        match curve.oid {
            o if o == BP256R1.oid => bench!(bp256::r1::BrainpoolP256r1),
            o if o == BP256T1.oid => bench!(bp256::t1::BrainpoolP256t1),
            o if o == BP384R1.oid => bench!(bp384::r1::BrainpoolP384r1),
            o if o == BP384T1.oid => bench!(bp384::t1::BrainpoolP384t1),
            o if o == BP512R1.oid => bench!(krb5_brainpool::p512::r1::BrainpoolP512r1),
            o if o == BP512T1.oid => bench!(krb5_brainpool::p512::t1::BrainpoolP512t1),
            _ => Err(format!("{name}: not a brainpool curve")),
        }
    }

    pub fn bench_ecdsa(
        name: &str,
        curve: EcCurve,
        cfg: &Cfg,
        rng: &mut BenchRng,
    ) -> Result<Measured, String> {
        if curve.oid != P521.oid {
            let fixed =
                random_scalar(&curve, rng).ok_or_else(|| format!("{name}: no key was taken"))?;
            let hash = [0x42u8; 32];
            return measure(
                name,
                cfg,
                rng,
                |class, rng| {
                    if is_left(class) {
                        fixed.clone()
                    } else {
                        random_scalar(&curve, rng).expect("a key")
                    }
                },
                |scalar| sign_bare(&curve, scalar, &hash),
                |_, ok| *ok,
            );
        }
        let (fixed, _) =
            random_identity(curve, rng).ok_or_else(|| format!("{name}: no key was taken"))?;
        let msg = plaintext();
        measure(
            name,
            cfg,
            rng,
            |class, rng| {
                if is_left(class) {
                    IdentityKey::from_pkcs8(&fixed).expect("the fixed key")
                } else {
                    random_identity(curve, rng).expect("a key").1
                }
            },
            |key| key.sign_sha256(&msg),
            |_, r| r.is_some(),
        )
    }
}

// ------------------------------------------------------------------------------------------
// Header
// ------------------------------------------------------------------------------------------

/// The checkout this package sits in (harness/hand/t7).
fn tree_path() -> Option<PathBuf> {
    Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.."))
        .filter(|p| p.join("Cargo.toml").exists())
}

/// A git command's trimmed stdout in `tree`, read-only (no optional locks).
fn git(tree: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .arg("-C")
        .arg(tree)
        .args(args)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// `tree=<target of the symlink> rev=<git HEAD> dirty=<yes|no|unknown>`, and a warning if the
/// tree is no longer the one this binary was built from.
fn tree_lines() -> Vec<String> {
    let Some(tree) = tree_path() else {
        return vec!["tree=(none) rev=unknown dirty=unknown".to_string()];
    };
    let target = match fs::read_link(&tree) {
        Ok(t) => t.display().to_string(),
        Err(_) => fs::canonicalize(&tree)
            .map_or_else(|_| tree.display().to_string(), |p| p.display().to_string()),
    };
    let rev = git(&tree, &["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    let dirty = match git(&tree, &["status", "--porcelain", "--untracked-files=no"]) {
        Some(s) if s.is_empty() => "no",
        Some(_) => "yes",
        None => "unknown",
    };
    let mut lines = vec![format!("tree={target} rev={rev} dirty={dirty}")];
    if fs::read_to_string(tree.join("Cargo.toml")).ok().as_deref() != Some(BUILT_TREE_MANIFEST) {
        lines.push(
            "WARNING: the workspace manifest of `tree` is not the one this binary was built \
             from: rebuild (see README.md) before trusting these numbers"
                .to_string(),
        );
    }
    lines
}

/// `name=version` of the crypto crates in the lock the binary was built with, in lock order.
fn crate_versions() -> String {
    const NAMES: &[&str] = &[
        "krb5-crypto",
        "aes",
        "camellia",
        "cmac",
        "des",
        "rc4",
        "hmac",
        "sha1",
        "sha2",
        "md-5",
        "md4",
        "pbkdf2",
        "p256",
        "curve25519-dalek",
        "subtle",
        "krb5-types",
        "crypto-bigint",
        "p224",
        "p384",
        "p521",
        "k256",
        "ecdsa",
        "bp256",
        "bp384",
        "krb5-brainpool",
        "primefield",
        "primeorder",
    ];
    let mut out = Vec::new();
    let mut current: Option<&str> = None;
    for line in BUILT_LOCK.lines() {
        if let Some(n) = line.strip_prefix("name = \"") {
            current = n.strip_suffix('"');
        } else if let Some(v) = line.strip_prefix("version = \"") {
            if let (Some(n), Some(v)) = (current, v.strip_suffix('"')) {
                if NAMES.contains(&n) {
                    out.push(format!("{n}={v}"));
                }
            }
        }
    }
    out.join(" ")
}

/// The CPUs this process may run on (`taskset -c 2` makes it `2`).
/// The CPU's vendor_id from /proc/cpuinfo ("AuthenticAMD", "GenuineIntel"), or "".
fn cpu_vendor() -> String {
    fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|c| {
            c.lines().find_map(|l| {
                l.strip_prefix("vendor_id")
                    .map(|v| v.trim_start_matches([' ', '\t', ':']).to_string())
            })
        })
        .unwrap_or_default()
}

fn cpus_allowed() -> String {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("Cpus_allowed_list:")
                    .map(|v| v.trim().to_string())
            })
        })
        .unwrap_or_else(|| "unknown".to_string())
}

// ------------------------------------------------------------------------------------------
// Cross-check of the statistics against the library
// ------------------------------------------------------------------------------------------

/// The raw runtimes are private in dudect-bencher, so its statistics cannot be run on data of
/// ours. Instead the library is run on a synthetic op (its own timing, its own statistics) with
/// its CSV dump of the runtimes on, and the port is run on that dump: the two `max t` must agree
/// in every printed digit. Two ops are run: one whose classes do the same work, so that t is
/// noise and the largest |t| is at some cropped test, and one whose Right class does a little
/// more. The library runs in a child process because it prints to stdout.
const CROSSCHECK_CSV: &str = "timing-crosscheck.csv";
const CROSSCHECK_EXTRA: [u64; 2] = [0, 4];

fn crosscheck_library_child(extra: u64) -> Result<(), String> {
    use dudect_bencher::ctbench::{
        run_benches_console, BenchFn, BenchMetadata, BenchName, BenchOpts,
    };
    use dudect_bencher::CtRunner;

    fn work(seed: u64, rounds: u64) -> u64 {
        (0..rounds).fold(black_box(seed), |a, i| {
            a.wrapping_mul(6364136223846793005).wrapping_add(i)
        })
    }
    // `BenchFn` is a plain fn pointer, so the extra rounds come in through a static.
    static EXTRA: AtomicU64 = AtomicU64::new(0);
    // Left and Right strictly alternate: the dump pairs them up. Right does `EXTRA` more rounds.
    fn synthetic(runner: &mut CtRunner, rng: &mut BenchRng) {
        let seed = rng.next_u64() | 1;
        // The round counts are opaque, or the compiler would fold the rounds into a constant.
        let left = black_box(48);
        let right = black_box(48 + EXTRA.load(Ordering::Relaxed));
        for _ in 0..20_000 {
            runner.run_one(Class::Left, || work(seed, left));
            runner.run_one(Class::Right, || work(seed, right));
        }
    }
    EXTRA.store(extra, Ordering::Relaxed);
    let benchfn: BenchFn = synthetic;
    let opts = BenchOpts {
        continuous: false,
        filter: None,
        file_out: Some(PathBuf::from(CROSSCHECK_CSV)),
    };
    let benches = vec![BenchMetadata {
        name: BenchName("crosscheck"),
        seed: Some(0xC0FFEE),
        benchfn,
    }];
    run_benches_console(opts, benches).map_err(|e| e.to_string())
}

fn crosscheck_one(extra: u64) -> Result<bool, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let out = Command::new(exe)
        .arg("--crosscheck-library")
        .arg(extra.to_string())
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "library run failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let library = String::from_utf8_lossy(&out.stdout).to_string();
    let library_line = library
        .lines()
        .find(|l| l.contains("max t = "))
        .ok_or("no result line from the library")?
        .to_string();

    // The dump: a header, then Left and Right rows alternating ("name,0,ns", class not kept).
    let csv = fs::read_to_string(CROSSCHECK_CSV).map_err(|e| e.to_string())?;
    let _ = fs::remove_file(CROSSCHECK_CSV);
    let (mut left, mut right) = (Vec::new(), Vec::new());
    for (i, row) in csv.lines().skip(1).filter(|l| !l.is_empty()).enumerate() {
        let ns: u64 = row
            .rsplit(',')
            .next()
            .and_then(|v| v.parse().ok())
            .ok_or("bad row in the dump")?;
        let side = if i % 2 == 0 { &mut left } else { &mut right };
        side.push(ns);
    }
    let mut stats = Stats::new();
    stats.update(&left, &right);
    let (max_t, n) = stats.max_t();
    let max_tau = max_t / (n as f64).sqrt();
    let port = format!(
        "n == {:+0.3}M, max t = {:+0.5}, max tau = {:+0.5}, (5/tau)^2 = {}",
        (n as f64) / 1_000_000f64,
        max_t,
        max_tau,
        (5f64 / max_tau).powi(2) as usize
    );
    println!("library: {library_line}");
    println!("port   : bench crosscheck ... : {port}");
    let same = library_line.ends_with(&port);
    println!(
        "crosscheck extra={extra} {} ({} left, {} right samples)",
        if same { "MATCH" } else { "MISMATCH" },
        left.len(),
        right.len()
    );
    Ok(same)
}

fn crosscheck() -> Result<bool, String> {
    let mut all = true;
    for extra in CROSSCHECK_EXTRA {
        all &= crosscheck_one(extra)?;
    }
    Ok(all)
}

// ------------------------------------------------------------------------------------------
// Command line
// ------------------------------------------------------------------------------------------

const USAGE: &str = "\
usage: timing [--samples N] [--op NAME]... [--seed S] [--count EVENT] [--no-early-stop] [--verbose]
       timing --list | --crosscheck | --help

  --samples N      samples per op, both classes together (default 1000000)
  --op NAME        run this op (repeatable, run in the order given); NAME* runs every op whose
                   name starts with NAME; default: every op but the cb-* ones
  --seed S         seed of the class order and of the harness's random inputs (default: random)
  --count EVENT    what a sample measures: time (ns, the default), or this thread's user-mode
                   cycles, instructions or branches (perf_event_open), or nearbranches (AMD
                   Zen: branches less far transfers, so no interrupt is counted)
  --no-early-stop  take every sample, whatever |t| reaches
  --verbose        progress after every batch, on stderr; with --count, each class's
                   per-sample counts at the end of each op
  --list        print the op names, in run order
  --crosscheck  check the t-test of this tool against dudect-bencher's own";

enum Cmd {
    Run { cfg: Cfg, ops: Vec<&'static OpDef> },
    List,
    Crosscheck,
    CrosscheckLibrary(u64),
    Help,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Cmd, String> {
    let mut samples = DEFAULT_SAMPLES;
    let mut seed = None;
    let mut verbose = false;
    let mut count = Count::Time;
    let mut stop_t = STOP_T;
    let mut names: Vec<String> = Vec::new();
    while let Some(arg) = args.next() {
        let mut value = |what: &str| args.next().ok_or_else(|| format!("{arg} needs {what}"));
        match arg.as_str() {
            "--samples" => {
                let v = value("a count")?;
                samples = v
                    .replace('_', "")
                    .parse()
                    .map_err(|_| format!("--samples: not a count: {v}"))?;
                if samples < 2 {
                    return Err("--samples must be at least 2".to_string());
                }
            }
            "--op" => names.push(value("an op name")?),
            "--seed" => {
                let v = value("a number")?;
                seed = Some(
                    match v.strip_prefix("0x") {
                        Some(hex) => u64::from_str_radix(hex, 16),
                        None => v.parse(),
                    }
                    .map_err(|_| format!("--seed: not a number: {v}"))?,
                );
            }
            "--count" => {
                count = match value("an event")?.as_str() {
                    "time" => Count::Time,
                    "cycles" => Count::Perf("cycles", 0, 0, None),
                    "instructions" => Count::Perf("instructions", 0, 1, None),
                    "branches" => Count::Perf("branches", 0, 4, None),
                    // AMD Zen's raw events: retired branches (0xC2), which count each interrupt,
                    // less retired far control transfers (0xC6), the interrupts among them.
                    "nearbranches" if cpu_vendor() == "AuthenticAMD" => {
                        Count::Perf("nearbranches", 4, 0xc2, Some(0xc6))
                    }
                    "nearbranches" => {
                        return Err("--count nearbranches: AMD Zen's events only".to_string())
                    }
                    other => return Err(format!("--count: unknown event: {other}")),
                };
            }
            "--no-early-stop" => stop_t = f64::INFINITY,
            "--verbose" | "-v" => verbose = true,
            "--list" => return Ok(Cmd::List),
            "--crosscheck" => return Ok(Cmd::Crosscheck),
            "--crosscheck-library" => {
                let v = value("a number")?;
                return Ok(Cmd::CrosscheckLibrary(
                    v.parse().map_err(|_| format!("not a number: {v}"))?,
                ));
            }
            "--help" | "-h" => return Ok(Cmd::Help),
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    let mut ops: Vec<&'static OpDef> = Vec::new();
    if names.is_empty() {
        ops.extend(OPS.iter());
    }
    for name in &names {
        let found: Vec<&'static OpDef> = match name.strip_suffix('*') {
            Some(prefix) => all_ops().filter(|d| d.name.starts_with(prefix)).collect(),
            None => all_ops().filter(|d| d.name == name).collect(),
        };
        if found.is_empty() {
            return Err(format!("unknown op: {name} (see --list)"));
        }
        for def in found {
            if !ops.iter().any(|d| d.name == def.name) {
                ops.push(def);
            }
        }
    }
    let seed = seed.unwrap_or_else(|| dudect_bencher::rand::rng().next_u64());
    Ok(Cmd::Run {
        cfg: Cfg {
            samples,
            seed,
            verbose,
            count,
            stop_t,
        },
        ops,
    })
}

/// The seed of one op's generator: the run seed and the op name, so that an op's inputs do not
/// depend on which other ops ran.
fn op_seed(seed: u64, name: &str) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325_u64;
    for b in name.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    seed ^ h
}

fn verdict(def: &OpDef, max_t: f64) -> &'static str {
    if def.report_only {
        "report-only"
    } else if max_t.is_finite() && max_t.abs() < PASS_T {
        "pass"
    } else {
        "FAIL"
    }
}

fn main() -> ExitCode {
    let (cfg, ops) = match parse_args(std::env::args().skip(1)) {
        Ok(Cmd::Run { cfg, ops }) => (cfg, ops),
        Ok(Cmd::List) => {
            for def in all_ops() {
                println!(
                    "{}{}",
                    def.name,
                    if def.report_only {
                        " (report-only)"
                    } else if ON_DEMAND.iter().any(|d| d.name == def.name) {
                        " (only when named)"
                    } else {
                        ""
                    }
                );
            }
            return ExitCode::SUCCESS;
        }
        Ok(Cmd::Help) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Ok(Cmd::CrosscheckLibrary(extra)) => {
            return match crosscheck_library_child(extra) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("timing: {e}");
                    ExitCode::from(2)
                }
            };
        }
        Ok(Cmd::Crosscheck) => {
            return match crosscheck() {
                Ok(true) => ExitCode::SUCCESS,
                Ok(false) => ExitCode::from(1),
                Err(e) => {
                    eprintln!("timing: crosscheck: {e}");
                    ExitCode::from(2)
                }
            };
        }
        Err(e) => {
            eprintln!("timing: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    for line in tree_lines() {
        println!("{line}");
    }
    println!("crates {}", crate_versions());
    if let Count::Perf(_, kind, config, minus) = cfg.count {
        if let Err(e) = perf::open(kind, config, minus) {
            eprintln!("timing: --count {}: {e}", cfg.count.name());
            return ExitCode::from(2);
        }
    }
    println!(
        "run samples={} batch={BATCH} seed={:#018x} cpus={} s2k_iterations={S2K_ITERATIONS} \
         count={} pass=|t|<{PASS_T} stop=|t|>{}",
        cfg.samples,
        cfg.seed,
        cpus_allowed(),
        cfg.count.name(),
        cfg.stop_t
    );

    let mut failed = false;
    for def in ops {
        let mut rng = BenchRng::seed_from_u64(op_seed(cfg.seed, def.name));
        match run_op(def, &cfg, &mut rng) {
            Ok(m) => println!(
                "op={} samples={} max_t={:.2} verdict={}",
                def.name,
                m.samples,
                m.max_t,
                verdict(def, m.max_t)
            ),
            Err(e) => {
                eprintln!("timing: {e}");
                println!("op={} samples=0 max_t=NaN verdict=ERROR", def.name);
                failed = true;
            }
        }
    }
    if failed {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}
