// MIT: `MAX_DECODE_DEPTH` (util/support/json.c:78-78)
// 63 containers may nest and the 64th is an error.
const MAX_DEPTH: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    /// An integer in the signed 64-bit range.
    Number(i64),
    String(Vec<u8>),
    Array(Vec<Value>),
    Object(Vec<(Vec<u8>, Value)>),
}

impl Value {
    #[must_use]
    pub fn member(&self, key: &str) -> Option<&Value> {
        match self {
            Self::Object(members) => members
                .iter()
                .find(|(k, _)| k.as_slice() == key.as_bytes())
                .map(|(_, v)| v),
            _ => None,
        }
    }

    // MIT: `k5_json_object_set` (util/support/json.c:426-469)
    // An existing key is overwritten in place, a new one appended.
    pub fn set(&mut self, key: &str, value: Value) {
        if let Self::Object(members) = self {
            set_member(members, key.as_bytes().to_vec(), Some(value));
        }
    }

    #[must_use]
    pub fn as_cstr(&self) -> Option<&[u8]> {
        match self {
            Self::String(s) => Some(s.split(|&b| b == 0).next().unwrap_or_default()),
            _ => None,
        }
    }
}

struct Decoder<'a> {
    s: &'a [u8],
    p: usize,
    depth: usize,
}

impl Decoder<'_> {
    fn at(&self, i: usize) -> u8 {
        self.s.get(i).copied().unwrap_or(0)
    }

    fn cur(&self) -> u8 {
        self.at(self.p)
    }

    // MIT: `white_spaces` (util/support/json.c:715-725)
    fn skip_ws(&mut self) -> bool {
        while matches!(self.cur(), b' ' | b'\t' | b'\r' | b'\n') {
            self.p += 1;
        }
        self.cur() != 0
    }

    fn eat(&mut self, lit: &[u8]) -> bool {
        let next = lit
            .iter()
            .enumerate()
            .all(|(i, &c)| self.at(self.p + i) == c);
        if next {
            self.p += lit.len();
        }
        next
    }

    fn enter(&mut self) -> Result<(), ()> {
        let left = self.depth;
        self.depth = left.saturating_sub(1);
        if left <= 1 { Err(()) } else { Ok(()) }
    }

    // MIT: `parse_value` (util/support/json.c:1002-1069)
    // `Ok(None)` is MIT's NULL, which a malformed nested array leaves behind with no error.
    fn parse_value(&mut self) -> Result<Option<Value>, ()> {
        if !self.skip_ws() {
            return Err(());
        }
        match self.cur() {
            b'"' => Ok(Some(Value::String(self.parse_string()?))),
            b'{' => {
                self.enter()?;
                let members = self.parse_object()?;
                self.depth += 1;
                Ok(Some(Value::Object(members)))
            }
            b'[' => {
                self.enter()?;
                let parsed = self.parse_array();
                self.depth += 1;
                Ok(parsed.ok().map(Value::Array))
            }
            b'-' | b'0'..=b'9' => Ok(Some(Value::Number(self.parse_number()?))),
            _ => {
                if self.eat(b"null") {
                    Ok(Some(Value::Null))
                } else if self.eat(b"true") {
                    Ok(Some(Value::Bool(true)))
                } else if self.eat(b"false") {
                    Ok(Some(Value::Bool(false)))
                } else {
                    Err(())
                }
            }
        }
    }

    // MIT: `parse_number` (util/support/json.c:755-785)
    // An optional `-` and digits, which
    /// must be an integer in the signed 64-bit range. A leading zero is allowed.
    // MIT: `parse_number` (util/support/json.c:774-781)
    /// The digits must fit the signed 64-bit range.
    fn parse_number(&mut self) -> Result<i64, ()> {
        let negative = self.cur() == b'-';
        if negative {
            self.p += 1;
        }
        if !self.cur().is_ascii_digit() {
            return Err(());
        }
        let mut number: u64 = 0;
        while self.cur().is_ascii_digit() {
            let digit = u64::from(self.cur() - b'0');
            number = number
                .checked_mul(10)
                .and_then(|n| n.checked_add(digit))
                .ok_or(())?;
            self.p += 1;
        }
        let limit = if negative {
            1u64 << 63
        } else {
            (1u64 << 63) - 1
        };
        if number > limit {
            return Err(());
        }
        let magnitude = i128::from(number);
        i64::try_from(if negative { -magnitude } else { magnitude }).map_err(|_| ())
    }

    // MIT: `parse_string` (util/support/json.c:789-851)
    fn parse_string(&mut self) -> Result<Vec<u8>, ()> {
        if self.cur() != b'"' {
            return Err(());
        }
        self.p += 1;
        let start = self.p;
        let end = loop {
            match self.cur() {
                0 => return Err(()),
                b'\\' => {
                    self.p += 1;
                    if self.cur() == 0 {
                        return Err(());
                    }
                }
                b'"' => {
                    let end = self.p;
                    self.p += 1;
                    break end;
                }
                _ => {}
            }
            self.p += 1;
        };
        let mut out = Vec::new();
        let mut q = start;
        while q < end {
            let c = self.at(q);
            if c != b'\\' {
                out.push(c);
                q += 1;
                continue;
            }
            q += 1;
            if self.at(q) == b'u' && (1..=4).all(|i| is_hex_digit(self.at(q + i))) {
                let code = (1..=4).fold(0u32, |acc, i| (acc << 4) | hexval(self.at(q + i)));
                out.push(u8::try_from(code).map_err(|_| ())?);
                q += 5;
            } else {
                out.push(match self.at(q) {
                    b'"' => b'"',
                    b'\\' => b'\\',
                    b'/' => b'/',
                    b'b' => 0x08,
                    b'f' => 0x0c,
                    b'n' => 0x0a,
                    b'r' => 0x0d,
                    b't' => 0x09,
                    _ => return Err(()),
                });
                q += 1;
            }
        }
        if let Some(z) = out.iter().position(|&b| b == 0) {
            out.truncate(z);
        }
        Ok(out)
    }

    // MIT: `parse_object_association` (util/support/json.c:855-887)
    fn parse_member(&mut self, members: &mut Vec<(Vec<u8>, Value)>) -> Result<(), ()> {
        let key = self.parse_string()?;
        if !self.skip_ws() || self.cur() != b':' {
            return Err(());
        }
        self.p += 1;
        if !self.skip_ws() {
            return Err(());
        }
        let value = self.parse_value()?;
        set_member(members, key, value);
        Ok(())
    }

    // MIT: `parse_object` (util/support/json.c:891-935)
    fn parse_object(&mut self) -> Result<Vec<(Vec<u8>, Value)>, ()> {
        if self.cur() != b'{' {
            return Err(());
        }
        self.p += 1;
        if !self.skip_ws() {
            return Err(());
        }
        let mut members = Vec::new();
        if self.cur() != b'}' {
            loop {
                self.parse_member(&mut members)?;
                if !self.skip_ws() {
                    return Err(());
                }
                if self.cur() == b'}' {
                    break;
                }
                if self.cur() != b',' {
                    return Err(());
                }
                self.p += 1;
                if !self.skip_ws() {
                    return Err(());
                }
            }
        }
        self.p += 1;
        Ok(members)
    }

    // MIT: `parse_array` (util/support/json.c:954-998)
    fn parse_array(&mut self) -> Result<Vec<Value>, ()> {
        if self.cur() != b'[' {
            return Err(());
        }
        self.p += 1;
        if !self.skip_ws() {
            return Err(());
        }
        let mut items = Vec::new();
        if self.cur() != b']' {
            loop {
                // MIT: `parse_array_item` (util/support/json.c:939-950)
                // A NULL is passed on as an element.
                // MIT: `k5_json_array_add` (util/support/json.c:246-246)
                // A NULL is stored as the element.
                items.push(self.parse_value()?.unwrap_or(Value::Null));
                if !self.skip_ws() {
                    return Err(());
                }
                if self.cur() == b']' {
                    break;
                }
                if self.cur() != b',' {
                    return Err(());
                }
                self.p += 1;
                if !self.skip_ws() {
                    return Err(());
                }
            }
        }
        self.p += 1;
        Ok(items)
    }
}

fn hexval(c: u8) -> u32 {
    if c.is_ascii_digit() {
        u32::from(c - b'0')
    } else {
        u32::from(c - b'A') + 10
    }
}

// MIT: `is_hex_digit` (util/support/json.c:736-739)
// A lowercase letter is not a hex digit here.
fn is_hex_digit(c: u8) -> bool {
    c.is_ascii_digit() || (b'A'..=b'F').contains(&c)
}

fn set_member(members: &mut Vec<(Vec<u8>, Value)>, key: Vec<u8>, value: Option<Value>) {
    let at = members.iter().position(|(k, _)| *k == key);
    match (at, value) {
        (Some(i), None) => {
            members.remove(i);
        }
        (Some(i), Some(v)) => {
            members[i].1 = v;
        }
        (None, Some(v)) => members.push((key, v)),
        (None, None) => {}
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonError;

/// Decodes the text as one JSON value, which must be all of the text before its first NUL.
// MIT: `k5_json_decode` (util/support/json.c:1072-1090)
// A top-level NULL is an error here, since MIT crashes on it.
pub fn decode(input: &[u8]) -> Result<Value, JsonError> {
    let s = input.split(|&b| b == 0).next().unwrap_or_default();
    let mut d = Decoder {
        s,
        p: 0,
        depth: MAX_DEPTH,
    };
    let value = d.parse_value().map_err(|()| JsonError)?;
    if d.skip_ws() {
        return Err(JsonError);
    }
    value.ok_or(JsonError)
}

// MIT: `encode_value` (util/support/json.c:630-684)
// MIT: `encode_string` (util/support/json.c:584-606)
#[must_use]
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

fn encode_string(s: &[u8], out: &mut Vec<u8>) {
    out.push(b'"');
    for &b in s.split(|&b| b == 0).next().unwrap_or_default() {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            8 => out.extend_from_slice(b"\\b"),
            12 => out.extend_from_slice(b"\\f"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            1..=31 => out.extend_from_slice(format!("\\u00{b:02X}").as_bytes()),
            _ => out.push(b),
        }
    }
    out.push(b'"');
}

fn encode_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => encode_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i != 0 {
                    out.push(b',');
                }
                encode_into(item, out);
            }
            out.push(b']');
        }
        Value::Object(members) => {
            out.push(b'{');
            for (i, (key, v)) in members.iter().enumerate() {
                if i != 0 {
                    out.push(b',');
                }
                encode_string(key, out);
                out.push(b':');
                encode_into(v, out);
            }
            out.push(b'}');
        }
    }
}
