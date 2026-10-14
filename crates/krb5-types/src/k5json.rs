//! MIT's JSON decoder, the decode half of `util/support/json.c`, port for port, so that every
//! input gets MIT's verdict. This is the tree's one port of that reader. MIT reads the text as a
//! C string, so its text ends at the first NUL.
//!
//! Two of MIT's behaviours are kept in the port's own form. A malformed nested array that MIT's
//! `parse_value` drops is a `Null` element here, and a member whose value is such a dropped array
//! is removed from its object. The one input that MIT crashes on, a malformed top-level array, is
//! an error here.

/// MIT `MAX_DECODE_DEPTH` (`util/support/json.c:78-78`): the depth budget a parse starts with, so
/// that 63 containers may nest and the 64th is an error.
const MAX_DEPTH: usize = 64;

/// A decoded JSON value.
#[derive(Debug, PartialEq, Eq)]
pub enum Value {
    /// The `null` literal.
    Null,
    /// A `true` or `false` literal.
    Bool(bool),
    /// An integer in the signed 64-bit range.
    Number(i64),
    /// A string: its octets, each `\uXXXX` escape one octet, cut at the first NUL.
    String(Vec<u8>),
    /// An array, in order.
    Array(Vec<Value>),
    /// An object: each key once. A later member with a key that is there overwrites its value in
    /// place, and a member whose value is a dropped nested array removes its key.
    Object(Vec<(Vec<u8>, Value)>),
}

impl Value {
    /// The value of member `key` when this is an object that has it.
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

    /// Sets member `key` of an object: a key that is there keeps its place and takes the new value,
    /// and a new key is added last. A value that is not an object is left as it is.
    /// MIT `k5_json_object_set` (`util/support/json.c:426-469`): an existing key is overwritten in place, a new one appended.
    pub fn set(&mut self, key: &str, value: Value) {
        if let Self::Object(members) = self {
            set_member(members, key.as_bytes().to_vec(), Some(value));
        }
    }

    /// The octets of a string up to its first NUL, as C code reads it; `None` for any other value.
    #[must_use]
    pub fn as_cstr(&self) -> Option<&[u8]> {
        match self {
            Self::String(s) => Some(s.split(|&b| b == 0).next().unwrap_or_default()),
            _ => None,
        }
    }
}

/// MIT's `struct decode_ctx`: the string, the octet being read, and the depth budget left.
struct Decoder<'a> {
    /// The string, cut at its first NUL: a C string, as MIT reads it.
    s: &'a [u8],
    /// The octet to read next (MIT `ctx->p`).
    p: usize,
    /// The containers that may still open (MIT `ctx->depth`).
    depth: usize,
}

impl Decoder<'_> {
    /// The octet at `i`, and NUL past the end, as a C string reads.
    fn at(&self, i: usize) -> u8 {
        self.s.get(i).copied().unwrap_or(0)
    }

    /// The octet to read next (MIT `*ctx->p`).
    fn cur(&self) -> u8 {
        self.at(self.p)
    }

    /// MIT `white_spaces` (`util/support/json.c:715-725`): skips the white space, and reports
    /// whether anything is left to read after it.
    fn skip_ws(&mut self) -> bool {
        while matches!(self.cur(), b' ' | b'\t' | b'\r' | b'\n') {
            self.p += 1;
        }
        self.cur() != 0
    }

    /// Reads `lit` if it is next, as MIT's `strncmp` does on the C string.
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

    /// One container's step into the depth budget (MIT `ctx->depth--`). The container fails when the
    /// budget is at its last level. MIT's counter would wrap from 0; a budget of 0 fails here.
    fn enter(&mut self) -> Result<(), ()> {
        let left = self.depth;
        self.depth = left.saturating_sub(1);
        if left <= 1 { Err(()) } else { Ok(()) }
    }

    /// MIT `parse_value` (`util/support/json.c:1002-1069`): one value. `Ok(None)` is MIT's NULL,
    /// which a malformed nested array leaves behind with no error.
    /// MIT `parse_value` (`util/support/json.c:1035-1040`): a `[` whose array fails is a NULL value, since the array's error is ignored.
    /// MIT `parse_value` (`util/support/json.c:1068-1068`): the value is returned as success, so the NULL is no error.
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

    /// MIT `parse_number` (`util/support/json.c:755-785`): an optional `-` and digits, which
    /// must be an integer in the signed 64-bit range. A leading zero is allowed.
    /// MIT `parse_number` (`util/support/json.c:774-781`): the digits must fit the signed 64-bit range.
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
        // The magnitude is at most 2^63, so the signed value is in the i64 range.
        let magnitude = i128::from(number);
        i64::try_from(if negative { -magnitude } else { magnitude }).map_err(|_| ())
    }

    /// MIT `parse_string` (`util/support/json.c:789-851`): a quoted string, whose escapes are
    /// decoded into octets. The string ends at the first NUL, as a C string does.
    /// MIT `parse_string` (`util/support/json.c:821-831`): `\uXXXX` takes four uppercase hex digits, and a code above 0xff is an error.
    /// MIT `parse_string` (`util/support/json.c:835-840`): any other escape is one of the quoted set, and anything else is an error.
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

    /// MIT `parse_object_association` (`util/support/json.c:855-887`): one `key: value` member,
    /// set into `members`.
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

    /// MIT `parse_object` (`util/support/json.c:891-935`): members separated by commas, between
    /// braces. A malformed member fails the object.
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

    /// MIT `parse_array` (`util/support/json.c:954-998`): values separated by commas, between
    /// brackets. A malformed element fails the array.
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
                // MIT `parse_array_item` (`util/support/json.c:939-950`): a NULL is passed on as an element.
                // MIT `k5_json_array_add` (`util/support/json.c:246-246`): a NULL is stored as the element.
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

/// The octet of a hex digit that `is_hex_digit` accepts.
fn hexval(c: u8) -> u32 {
    if c.is_ascii_digit() {
        u32::from(c - b'0')
    } else {
        u32::from(c - b'A') + 10
    }
}

/// MIT `is_hex_digit` (`util/support/json.c:736-739`): a decimal digit or an uppercase letter from A
/// to F. A lowercase letter is not a hex digit here.
fn is_hex_digit(c: u8) -> bool {
    c.is_ascii_digit() || (b'A'..=b'F').contains(&c)
}

/// MIT `k5_json_object_set` (`util/support/json.c:427-469`): a value sets its key, in place when
/// the key is there. A NULL value removes the key, and a NULL for a key that is not there is
/// nothing.
/// MIT `k5_json_object_set` (`util/support/json.c:435-436`): a NULL value removes the key.
/// MIT `k5_json_object_set` (`util/support/json.c:442-443`): a value overwrites its key in place.
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

/// The error of a decode that MIT's `k5_json_decode` fails: the text is not one JSON value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonError;

/// Decodes the text as one JSON value, which must be all of the text before its first NUL.
///
/// MIT `k5_json_decode` (`util/support/json.c:1072-1090`): a value with something after it is an
/// error. A top-level NULL is also an error here, since MIT crashes on it.
/// MIT `k5_json_decode` (`util/support/json.c:1084-1086`): anything left after the value is EINVAL.
///
/// # Errors
///
/// [`JsonError`] when the text is not one JSON value, as MIT's reader would fail it.
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

/// Encodes a value as compact JSON: no whitespace, members in their order, strings quoted.
/// MIT `encode_value` (`util/support/json.c:630-684`): an object's members are written in order,
/// and a number in decimal.
/// MIT `encode_string` (`util/support/json.c:584-606`): `"`, `\` and the control characters are
/// escaped; `/` and bytes above 0x7F are written as they are.
#[must_use]
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

/// Writes a string quoted, cut at its first NUL as MIT's C string is.
/// MIT `encode_string` (`util/support/json.c:584-606`): the control characters become `\b`, `\f`,
/// `\n`, `\r`, `\t`, or `\u00XX` with upper-case hex.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_is_compact_ordered_and_mits_quoting() {
        let mut object = Value::Object(Vec::new());
        object.set("vendor", Value::String(b"A\"B/\x01".to_vec()));
        object.set("n", Value::Number(-7));
        object.set("vendor", Value::String(b"V".to_vec()));
        assert_eq!(encode(&object), br#"{"vendor":"V","n":-7}"#);
        let quoted = Value::String(b"A\"B\\/\x01\x08\x7f\xc3".to_vec());
        assert_eq!(encode(&quoted), b"\"A\\\"B\\\\/\\u0001\\b\x7f\xc3\"");
        let cut = Value::String(b"ab\0cd".to_vec());
        assert_eq!(encode(&cut), b"\"ab\"");
        assert_eq!(
            encode(&Value::Array(vec![Value::Bool(true), Value::Null])),
            b"[true,null]"
        );
    }

    #[test]
    fn decode_follows_mit() {
        assert_eq!(
            decode(br#" {"a" : [1, true, null, "x\u0041"]} "#).unwrap(),
            Value::Object(vec![(
                b"a".to_vec(),
                Value::Array(vec![
                    Value::Number(1),
                    Value::Bool(true),
                    Value::Null,
                    Value::String(b"xA".to_vec()),
                ]),
            )])
        );
        assert_eq!(
            decode(b"-9223372036854775808").unwrap(),
            Value::Number(i64::MIN)
        );
        assert_eq!(
            decode(b"9223372036854775807").unwrap(),
            Value::Number(i64::MAX)
        );
        for bad in [
            &b"1.5"[..],
            b"1e3",
            b"+1",
            b"9223372036854775808",
            b"[1,",
            b"[",
            b"{\"a\":1",
            b"1 2",
            b"\"\\u0100\"",
            b"\"\\u00ff\" x",
            b"\"\\u00ff\\u0041",
        ] {
            assert!(decode(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        assert!(decode(b"01").is_ok());
        assert_eq!(decode(b"\"\\u00FF\"").unwrap(), Value::String(vec![0xff]));
        assert!(
            decode(b"\"\\u00ff\"").is_err(),
            "lower-case hex is not MIT's"
        );
        // The text ends at its first NUL, so this string is unterminated.
        assert!(decode(b"\"ab\0cd\"").is_err());
        assert_eq!(
            decode(b"[1]\0 junk").unwrap(),
            Value::Array(vec![Value::Number(1)])
        );
    }
}
