//! `krb5_string_to_deltat` (`x-deltat.y`).

const MAX: i32 = i32::MAX;
const MIN: i32 = i32::MIN;
const DAY: i32 = 24 * 3600;
const HOUR: i32 = 3600;
const MAX_DAY: i32 = MAX / DAY;
const MIN_DAY: i32 = MIN / DAY;
const MAX_HOUR: i32 = MAX / HOUR;
const MIN_HOUR: i32 = MIN / HOUR;
const MAX_MIN: i32 = MAX / 60;
const MIN_MIN: i32 = MIN / 60;

/// Rejected by `krb5_string_to_deltat` (`KRB5_DELTAT_BADFORMAT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeltatError;

/// Parse a MIT deltat to `krb5_deltat` seconds.
///
/// # Errors
///
/// A form `t_deltat.c` rejects, including int32 overflow.
pub fn parse(s: &str) -> Result<i32, DeltatError> {
    let b = s.as_bytes();
    let mut i = 0;
    let v = deltat(b, &mut i)?;
    skip_ws(b, &mut i);
    if i != b.len() {
        return Err(DeltatError);
    }
    Ok(v)
}

fn skip_ws(b: &[u8], i: &mut usize) {
    while *i < b.len() && matches!(b[*i], b' ' | b'\t' | b'\n') {
        *i += 1;
    }
}

fn peek(b: &[u8], i: usize) -> Option<u8> {
    b.get(i).copied()
}

fn num(b: &[u8], i: &mut usize) -> Result<i32, DeltatError> {
    skip_ws(b, i);
    let neg = if peek(b, *i) == Some(b'-') {
        *i += 1;
        true
    } else {
        false
    };
    if !peek(b, *i).is_some_and(|c| c.is_ascii_digit()) {
        return Err(DeltatError);
    }
    let mut n: i64 = 0;
    while peek(b, *i).is_some_and(|c| c.is_ascii_digit()) {
        let d = i64::from(b[*i] - b'0');
        if n > i64::from(MAX) / 10 {
            return Err(DeltatError);
        }
        n *= 10;
        if n > i64::from(MAX) - d {
            return Err(DeltatError);
        }
        n += d;
        *i += 1;
    }
    let v = i32::try_from(n).map_err(|_| DeltatError)?;
    if neg {
        v.checked_neg().ok_or(DeltatError)
    } else {
        Ok(v)
    }
}

fn tok_num(b: &[u8], i: &mut usize) -> Result<i32, DeltatError> {
    if !peek(b, *i).is_some_and(|c| c.is_ascii_digit()) {
        return Err(DeltatError);
    }
    let start = *i;
    let mut n: i32 = 0;
    while peek(b, *i).is_some_and(|c| c.is_ascii_digit()) {
        n = n.checked_mul(10).ok_or(DeltatError)?;
        n = n.checked_add(i32::from(b[*i] - b'0')).ok_or(DeltatError)?;
        *i += 1;
        if *i - start > 2 {
            return Err(DeltatError);
        }
    }
    Ok(n)
}

fn eat(b: &[u8], i: &mut usize, c: u8) -> bool {
    if peek(b, *i) == Some(c) {
        *i += 1;
        true
    } else {
        false
    }
}

fn sum(a: i32, b: i32) -> Result<i32, DeltatError> {
    a.checked_add(b).ok_or(DeltatError)
}

fn dhms(d: i32, h: i32, m: i32, s: i32) -> Result<i32, DeltatError> {
    if !(MIN_DAY..=MAX_DAY).contains(&d)
        || !(MIN_HOUR..=MAX_HOUR).contains(&h)
        || !(MIN_MIN..=MAX_MIN).contains(&m)
    {
        return Err(DeltatError);
    }
    let mut out = d.checked_mul(DAY).ok_or(DeltatError)?;
    out = sum(out, h.checked_mul(HOUR).ok_or(DeltatError)?)?;
    out = sum(out, m.checked_mul(60).ok_or(DeltatError)?)?;
    sum(out, s)
}

fn opt_s(b: &[u8], i: &mut usize) -> i32 {
    let save = *i;
    skip_ws(b, i);
    if *i >= b.len() {
        return 0;
    }
    match num(b, i) {
        Ok(n) if eat(b, i, b's') => n,
        _ => {
            *i = save;
            skip_ws(b, i);
            0
        }
    }
}

fn opt_ms(b: &[u8], i: &mut usize) -> Result<i32, DeltatError> {
    let save = *i;
    match num(b, i) {
        Ok(n) if eat(b, i, b'm') => {
            let s = opt_s(b, i);
            sum(n.checked_mul(60).ok_or(DeltatError)?, s)
        }
        _ => {
            *i = save;
            Ok(opt_s(b, i))
        }
    }
}

fn opt_hms(b: &[u8], i: &mut usize) -> Result<i32, DeltatError> {
    let save = *i;
    match num(b, i) {
        Ok(n) if eat(b, i, b'h') => {
            let ms = opt_ms(b, i)?;
            sum(n.checked_mul(HOUR).ok_or(DeltatError)?, ms)
        }
        _ => {
            *i = save;
            opt_ms(b, i)
        }
    }
}

fn deltat(b: &[u8], i: &mut usize) -> Result<i32, DeltatError> {
    let n = num(b, i)?;
    if eat(b, i, b'd') {
        let rest = opt_hms(b, i)?;
        if !(MIN_DAY..=MAX_DAY).contains(&n) {
            return Err(DeltatError);
        }
        return sum(n.checked_mul(DAY).ok_or(DeltatError)?, rest);
    }
    {
        let save = *i;
        if eat(b, i, b'-') {
            if let Ok(h) = tok_num(b, i)
                && eat(b, i, b':')
                && let Ok(m) = tok_num(b, i)
                && eat(b, i, b':')
                && let Ok(s) = tok_num(b, i)
            {
                return dhms(n, h, m, s);
            }
            *i = save;
        }
    }
    if eat(b, i, b'h') {
        let rest = opt_ms(b, i)?;
        return dhms(0, n, 0, rest);
    }
    if eat(b, i, b'm') {
        let rest = opt_s(b, i);
        return dhms(0, 0, n, rest);
    }
    if eat(b, i, b's') {
        return dhms(0, 0, 0, n);
    }
    if eat(b, i, b':') {
        let m = tok_num(b, i)?;
        if eat(b, i, b':') {
            let s = tok_num(b, i)?;
            return dhms(0, n, m, s);
        }
        return dhms(0, n, m, 0);
    }
    dhms(0, 0, 0, n)
}

#[cfg(test)]
#[allow(clippy::unreadable_literal)]
mod tests {
    use super::*;
    const D: i32 = 24 * 3600;
    const H: i32 = 3600;
    const M: i32 = 60;

    fn good(s: &str, v: i32) {
        assert_eq!(parse(s), Ok(v), "GOOD {s}");
    }
    fn bad(s: &str) {
        assert!(parse(s).is_err(), "BAD {s} -> {:?}", parse(s));
    }

    #[test]
    fn t_deltat_c_vectors() {
        good("3d", 3 * D);
        good("3h", 3 * H);
        good("3m", 3 * M);
        good("3s", 3);
        bad("3dd");
        good("3d4m    42s", 3 * D + 4 * M + 42);
        good("3d-1h", 3 * D - H);
        good("3d -1h", 3 * D - H);
        good("3d4h5m6s", 3 * D + 4 * H + 5 * M + 6);
        bad("3d4m5h");
        good("12345s", 12345);
        good("1m 12345s", M + 12345);
        good("1m12345s", M + 12345);
        good("3d 0m", 3 * D);
        good("3d 0m  ", 3 * D);
        good("3d \n\t 0m  ", 3 * D);
        good("42-13:42:47", 42 * D + 13 * H + 42 * M + 47);
        bad("3: 4");
        bad("13:0003");
        good("12:34", 12 * H + 34 * M);
        good("1:02:03", H + 2 * M + 3);
        bad("3:-4");
        good("3:4", 3 * H + 4 * M);
        good("42", 42);
        bad("1-2");
        good("2147483647s", 2147483647);
        bad("2147483648s");
        good("24855d", 24855 * D);
        bad("24856d");
        bad("24855d 100000000h");
        good("24855d 3h", 24855 * D + 3 * H);
        bad("24855d 4h");
        good("24855d 11647s", 24855 * D + 11647);
        bad("24855d 11648s");
        good("24855d 194m 7s", 24855 * D + 194 * M + 7);
        bad("24855d 194m 8s");
        bad("24855d 195m");
        bad("24855d 19500000000m");
        good("24855d 3h 14m 7s", 24855 * D + 3 * H + 14 * M + 7);
        bad("24855d 3h 14m 8s");
        good("596523h", 596523 * H);
        bad("596524h");
        good("596523h 847s", 596523 * H + 847);
        bad("596523h 848s");
        good("596523h 14m 7s", 596523 * H + 14 * M + 7);
        bad("596523h 14m 8s");
        good("35791394m", 35791394 * M);
        good("35791394m7s", 35791394 * M + 7);
        bad("35791394m8s");
        good("-2147483647s", -2147483647);
        good("-24855d", -24855 * D);
        bad("-24856d");
        bad("-24855d -100000000h");
        good("-24855d -3h", -24855 * D - 3 * H);
        bad("-24855d -4h");
        good("-24855d -11647s", -24855 * D - 11647);
        bad("-24855d -11649s");
        good("-24855d -194m -7s", -24855 * D - 194 * M - 7);
        bad("-24855d -194m -9s");
        bad("-24855d -195m");
        bad("-24855d -19500000000m");
        good("-24855d -3h -14m -7s", -24855 * D - 3 * H - 14 * M - 7);
        bad("-24855d -3h -14m -9s");
        good("-596523h", -596523 * H);
        bad("-596524h");
        good("-596523h -847s", -596523 * H - 847);
        good("-596523h -848s", -596523 * H - 848);
        bad("-596523h -849s");
        good("-596523h -14m -8s", -596523 * H - 14 * M - 8);
        bad("-596523h -14m -9s");
        good("-35791394m", -35791394 * M);
        good("-35791394m7s", -35791394 * M + 7);
        bad("-35791394m-9s");
    }
}
