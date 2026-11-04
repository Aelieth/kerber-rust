use regex_automata::meta::Regex;
use std::fmt::Write as _;

const REG_BADPAT: i32 = 2;
const REG_ECOLLATE: i32 = 3;
const REG_ECTYPE: i32 = 4;
const REG_EESCAPE: i32 = 5;
const REG_ESUBREG: i32 = 6;
const REG_EBRACK: i32 = 7;
const REG_EPAREN: i32 = 8;
const REG_EBRACE: i32 = 9;
const REG_BADBR: i32 = 10;
const REG_ERANGE: i32 = 11;
const REG_ESPACE: i32 = 12;
const REG_BADRPT: i32 = 13;
const REG_ESIZE: i32 = 15;

const DUP_MAX: i64 = 0x7fff;

pub struct Ere(Option<(Regex, Regex)>);

impl Ere {
    pub fn new(pattern: &[u8]) -> Result<Self, i32> {
        let mut p = Parser {
            pat: pattern,
            pos: 0,
            nsub: 0,
            done: 0,
            backref: false,
        };
        let out = p.reg_exp(0)?;
        if p.backref {
            return Ok(Self(None));
        }
        let syntax = regex_automata::util::syntax::Config::new()
            .unicode(false)
            .utf8(false);
        let build = |p: &str| {
            Regex::builder()
                .configure(Regex::config().utf8_empty(false))
                .syntax(syntax)
                .build(p)
                .map_err(|_| REG_ESPACE)
        };
        Ok(Self(Some((
            build(&out)?,
            build(&format!(r"\A(?:{out})\z"))?,
        ))))
    }

    #[must_use]
    pub fn is_match(&self, subject: &[u8]) -> Option<bool> {
        self.0.as_ref().map(|(re, _)| re.is_match(subject))
    }

    #[must_use]
    pub fn is_whole_match(&self, subject: &[u8]) -> Option<bool> {
        self.0.as_ref().map(|(_, whole)| whole.is_match(subject))
    }
}

#[must_use]
pub fn regerror(code: i32) -> &'static str {
    match code {
        0 => "Success",
        1 => "No match",
        REG_ECOLLATE => "Invalid collation character",
        REG_ECTYPE => "Invalid character class name",
        REG_EESCAPE => "Trailing backslash",
        REG_ESUBREG => "Invalid back reference",
        REG_EBRACK => "Unmatched [, [^, [:, [., or [=",
        REG_EPAREN => "Unmatched ( or \\(",
        REG_EBRACE => "Unmatched \\{",
        REG_BADBR => "Invalid content of \\{\\}",
        REG_ERANGE => "Invalid range end",
        REG_ESPACE => "Memory exhausted",
        REG_BADRPT => "Invalid preceding regular expression",
        14 => "Premature end of regular expression",
        REG_ESIZE => "Regular expression too big",
        16 => "Unmatched ) or \\)",
        _ => "Invalid regular expression",
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tok {
    Char(u8),
    Alt,
    Star,
    Plus,
    Quest,
    OpenDup,
    CloseDup,
    Open,
    Close,
    Bracket,
    Period,
    Anchor(&'static str),
    Word(bool),
    Space(bool),
    BackRef(u8),
    BackSlash,
    End,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BTok {
    Char(u8),
    OpenColl,
    OpenEquiv,
    OpenClass,
    Range,
    Close,
    NonMatch,
    End,
}

enum Elem {
    Byte(u8),
    Coll(Vec<u8>),
    Equiv(Vec<u8>),
    Class(Vec<u8>),
}

struct Parser<'a> {
    pat: &'a [u8],
    pos: usize,
    nsub: u32,
    done: u32,
    backref: bool,
}

type Set = [bool; 256];

impl Parser<'_> {
    fn peek(&self) -> (Tok, usize, u8) {
        let Some(&c) = self.pat.get(self.pos) else {
            return (Tok::End, 0, 0);
        };
        if c == b'\\' {
            let Some(&c2) = self.pat.get(self.pos + 1) else {
                return (Tok::BackSlash, 1, c);
            };
            let t = match c2 {
                b'1'..=b'9' => Tok::BackRef(c2 - b'1'),
                b'<' => Tok::Anchor(r"\b{start}"),
                b'>' => Tok::Anchor(r"\b{end}"),
                b'b' => Tok::Anchor(r"\b"),
                b'B' => Tok::Anchor(r"\B"),
                b'`' => Tok::Anchor(r"\A"),
                b'\'' => Tok::Anchor(r"\z"),
                b'w' => Tok::Word(false),
                b'W' => Tok::Word(true),
                b's' => Tok::Space(false),
                b'S' => Tok::Space(true),
                _ => Tok::Char(c2),
            };
            return (t, 2, c2);
        }
        let t = match c {
            b'|' => Tok::Alt,
            b'*' => Tok::Star,
            b'+' => Tok::Plus,
            b'?' => Tok::Quest,
            b'{' => Tok::OpenDup,
            b'}' => Tok::CloseDup,
            b'(' => Tok::Open,
            b')' => Tok::Close,
            b'[' => Tok::Bracket,
            b'.' => Tok::Period,
            b'^' => Tok::Anchor(r"\A"),
            b'$' => Tok::Anchor(r"\z"),
            _ => Tok::Char(c),
        };
        (t, 1, c)
    }

    fn tok(&self) -> Tok {
        self.peek().0
    }

    fn skip(&mut self) {
        self.pos += self.peek().1;
    }

    fn reg_exp(&mut self, nest: u32) -> Result<String, i32> {
        let initial = self.done;
        let mut out = self.branch(nest)?;
        while self.tok() == Tok::Alt {
            self.skip();
            out.push('|');
            let t = self.tok();
            if t != Tok::Alt && t != Tok::End && (nest == 0 || t != Tok::Close) {
                let accumulated = self.done;
                self.done = initial;
                out += &self.branch(nest)?;
                self.done |= accumulated;
            }
        }
        Ok(out)
    }

    fn branch(&mut self, nest: u32) -> Result<String, i32> {
        let mut out = self.expression(nest)?;
        loop {
            let t = self.tok();
            if t == Tok::Alt || t == Tok::End || (nest > 0 && t == Tok::Close) {
                return Ok(out);
            }
            out += &self.expression(nest)?;
        }
    }

    fn expression(&mut self, nest: u32) -> Result<String, i32> {
        let (t, len, c) = self.peek();
        let mut atom = match t {
            Tok::Char(b) => {
                self.pos += len;
                lit(b)
            }
            Tok::Close | Tok::CloseDup => {
                self.pos += len;
                lit(c)
            }
            Tok::Open => self.sub_exp(nest + 1)?,
            Tok::Bracket => self.bracket()?,
            Tok::BackRef(n) => {
                if self.done & (1 << n) == 0 {
                    return Err(REG_ESUBREG);
                }
                self.backref = true;
                self.pos += len;
                String::new()
            }
            Tok::Star | Tok::Plus | Tok::Quest | Tok::OpenDup => return Err(REG_BADRPT),
            Tok::Anchor(a) => {
                self.pos += len;
                return Ok(a.to_owned());
            }
            Tok::Period => {
                self.pos += len;
                let mut set = [true; 256];
                set[0] = false;
                class(&set)
            }
            Tok::Word(neg) => {
                self.pos += len;
                class(&named(b"alnum", neg, b"_"))
            }
            Tok::Space(neg) => {
                self.pos += len;
                class(&named(b"space", neg, b""))
            }
            Tok::Alt | Tok::End => return Ok(String::new()),
            Tok::BackSlash => return Err(REG_EESCAPE),
        };
        while let Some(rep) = self.dup_op()? {
            atom = format!("(?:{atom}){rep}");
        }
        Ok(atom)
    }

    fn sub_exp(&mut self, nest: u32) -> Result<String, i32> {
        let n = self.nsub;
        self.nsub += 1;
        self.skip();
        let inner = if self.tok() == Tok::Close {
            String::new()
        } else {
            let inner = self.reg_exp(nest)?;
            if self.tok() != Tok::Close {
                return Err(REG_EPAREN);
            }
            inner
        };
        self.skip();
        if n < 9 {
            self.done |= 1 << n;
        }
        Ok(format!("(?:{inner})"))
    }

    fn dup_op(&mut self) -> Result<Option<String>, i32> {
        let rep = match self.tok() {
            Tok::Star => "*".to_owned(),
            Tok::Plus => "+".to_owned(),
            Tok::Quest => "?".to_owned(),
            Tok::OpenDup => {
                self.skip();
                let (mut start, mut last) = self.fetch_number();
                if start == -1 {
                    if last == Tok::Char(b',') {
                        start = 0;
                    } else {
                        return Err(REG_BADBR);
                    }
                }
                let mut end = -2;
                if start != -2 {
                    end = match last {
                        Tok::CloseDup => start,
                        Tok::Char(b',') => {
                            let (e, t) = self.fetch_number();
                            last = t;
                            e
                        }
                        _ => -2,
                    };
                }
                if start == -2 || end == -2 {
                    return Err(if last == Tok::End {
                        REG_EBRACE
                    } else {
                        REG_BADBR
                    });
                }
                if (end != -1 && start > end) || last != Tok::CloseDup {
                    return Err(REG_BADBR);
                }
                if DUP_MAX < if end == -1 { start } else { end } {
                    return Err(REG_ESIZE);
                }
                return Ok(Some(if end == -1 {
                    format!("{{{start},}}")
                } else {
                    format!("{{{start},{end}}}")
                }));
            }
            _ => return Ok(None),
        };
        self.skip();
        Ok(Some(rep))
    }

    fn fetch_number(&mut self) -> (i64, Tok) {
        let mut num: i64 = -1;
        loop {
            let (t, len, _) = self.peek();
            if t == Tok::End {
                return (-2, t);
            }
            self.pos += len;
            if t == Tok::CloseDup || t == Tok::Char(b',') {
                return (num, t);
            }
            num = match t {
                Tok::Char(d) if d.is_ascii_digit() && num != -2 => {
                    let d = i64::from(d - b'0');
                    if num == -1 {
                        d
                    } else {
                        (num * 10 + d).min(DUP_MAX + 1)
                    }
                }
                _ => -2,
            };
        }
    }

    fn peek_bracket(&self) -> (BTok, usize) {
        let Some(&c) = self.pat.get(self.pos) else {
            return (BTok::End, 0);
        };
        if c == b'[' {
            return match self.pat.get(self.pos + 1) {
                Some(b'.') => (BTok::OpenColl, 2),
                Some(b'=') => (BTok::OpenEquiv, 2),
                Some(b':') => (BTok::OpenClass, 2),
                _ => (BTok::Char(c), 1),
            };
        }
        let t = match c {
            b'-' => BTok::Range,
            b']' => BTok::Close,
            b'^' => BTok::NonMatch,
            _ => BTok::Char(c),
        };
        (t, 1)
    }

    fn bracket(&mut self) -> Result<String, i32> {
        self.pos += 1;
        let mut set: Set = [false; 256];
        let (mut t, mut len) = self.peek_bracket();
        if t == BTok::End {
            return Err(REG_BADPAT);
        }
        let non_match = t == BTok::NonMatch;
        if non_match {
            self.pos += len;
            (t, len) = self.peek_bracket();
            if t == BTok::End {
                return Err(REG_BADPAT);
            }
        }
        if t == BTok::Close {
            t = BTok::Char(b']');
        }
        let mut first = true;
        loop {
            let start = self.bracket_element(t, len, first)?;
            first = false;
            (t, len) = self.peek_bracket();
            let mut range_end = None;
            if !matches!(start, Elem::Class(_) | Elem::Equiv(_)) {
                if t == BTok::End {
                    return Err(REG_EBRACK);
                }
                if t == BTok::Range {
                    self.pos += len;
                    let (t2, len2) = self.peek_bracket();
                    if t2 == BTok::End {
                        return Err(REG_EBRACK);
                    }
                    if t2 == BTok::Close {
                        self.pos -= len;
                        t = BTok::Char(b'-');
                    } else {
                        range_end = Some(self.bracket_element(t2, len2, true)?);
                        (t, len) = self.peek_bracket();
                    }
                }
            }
            match range_end {
                Some(end) => {
                    let (lo, hi) = (range_point(&start)?, range_point(&end)?);
                    if lo > hi {
                        return Err(REG_ERANGE);
                    }
                    for b in lo..=hi {
                        set[usize::from(b)] = true;
                    }
                }
                None => add_element(&mut set, &start)?,
            }
            if t == BTok::End {
                return Err(REG_EBRACK);
            }
            if t == BTok::Close {
                self.pos += len;
                break;
            }
        }
        if non_match {
            for b in &mut set {
                *b = !*b;
            }
        }
        Ok(class(&set))
    }

    fn bracket_element(&mut self, t: BTok, len: usize, accept_hyphen: bool) -> Result<Elem, i32> {
        let c = self.pat.get(self.pos).copied().unwrap_or_default();
        self.pos += len;
        match t {
            BTok::OpenColl => self.bracket_symbol(b'.').map(Elem::Coll),
            BTok::OpenEquiv => self.bracket_symbol(b'=').map(Elem::Equiv),
            BTok::OpenClass => self.bracket_symbol(b':').map(Elem::Class),
            BTok::Range if !accept_hyphen && self.peek_bracket().0 != BTok::Close => {
                Err(REG_ERANGE)
            }
            BTok::Char(b) => Ok(Elem::Byte(b)),
            _ => Ok(Elem::Byte(c)),
        }
    }

    fn bracket_symbol(&mut self, delim: u8) -> Result<Vec<u8>, i32> {
        let mut name = Vec::new();
        loop {
            if name.len() >= 32 || self.pos >= self.pat.len() {
                return Err(REG_EBRACK);
            }
            let ch = self.pat[self.pos];
            self.pos += 1;
            if self.pos >= self.pat.len() {
                return Err(REG_EBRACK);
            }
            if ch == delim && self.pat[self.pos] == b']' {
                self.pos += 1;
                return Ok(name);
            }
            name.push(ch);
        }
    }
}

fn range_point(e: &Elem) -> Result<u8, i32> {
    match e {
        Elem::Byte(b) => Ok(*b),
        Elem::Coll(name) if name.len() == 1 => Ok(name[0]),
        Elem::Coll(_) => Err(REG_ECOLLATE),
        Elem::Equiv(_) | Elem::Class(_) => Err(REG_ERANGE),
    }
}

fn add_element(set: &mut Set, e: &Elem) -> Result<(), i32> {
    match e {
        Elem::Byte(b) => set[usize::from(*b)] = true,
        Elem::Coll(name) | Elem::Equiv(name) => match name.as_slice() {
            [b] => set[usize::from(*b)] = true,
            _ => return Err(REG_ECOLLATE),
        },
        Elem::Class(name) => {
            let class = char_class(name).ok_or(REG_ECTYPE)?;
            for (b, on) in set.iter_mut().enumerate() {
                *on |= u8::try_from(b).is_ok_and(class);
            }
        }
    }
    Ok(())
}

fn char_class(name: &[u8]) -> Option<fn(u8) -> bool> {
    Some(match name {
        b"alpha" => |b: u8| b.is_ascii_alphabetic(),
        b"upper" => |b: u8| b.is_ascii_uppercase(),
        b"lower" => |b: u8| b.is_ascii_lowercase(),
        b"digit" => |b: u8| b.is_ascii_digit(),
        b"xdigit" => |b: u8| b.is_ascii_hexdigit(),
        b"space" => |b: u8| matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r'),
        b"print" => |b: u8| (0x20..0x7f).contains(&b),
        b"punct" => |b: u8| b.is_ascii_punctuation(),
        b"graph" => |b: u8| b.is_ascii_graphic(),
        b"cntrl" => |b: u8| b.is_ascii_control(),
        b"blank" => |b: u8| b == b' ' || b == b'\t',
        b"alnum" => |b: u8| b.is_ascii_alphanumeric(),
        _ => return None,
    })
}

fn named(name: &[u8], neg: bool, extra: &[u8]) -> Set {
    let mut set: Set = [false; 256];
    let _ = add_element(&mut set, &Elem::Class(name.to_vec()));
    for &b in extra {
        set[usize::from(b)] = true;
    }
    if neg {
        for b in &mut set {
            *b = !*b;
        }
    }
    set
}

fn lit(b: u8) -> String {
    format!(r"\x{b:02X}")
}

fn class(set: &Set) -> String {
    let mut out = String::from("[");
    let mut b = 0;
    while b < 256 {
        if !set[b] {
            b += 1;
            continue;
        }
        let lo = b;
        while b < 256 && set[b] {
            b += 1;
        }
        let _ = write!(out, r"\x{lo:02X}");
        if b - 1 > lo {
            let _ = write!(out, r"-\x{:02X}", b - 1);
        }
    }
    if out.len() == 1 {
        return r"\b\B".to_owned();
    }
    out.push(']');
    out
}
