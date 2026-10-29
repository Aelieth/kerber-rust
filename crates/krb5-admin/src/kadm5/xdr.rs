use krb5_crypto::EncryptionType;
use krb5_types::PrincipalName;

use crate::Error;

#[allow(clippy::cast_possible_truncation)]
pub(super) fn xdr_tl_type(wire: u32) -> i32 {
    i32::from(wire as i16)
}

pub(super) struct XdrR<'a> {
    pub(super) b: &'a [u8],
    pub(super) i: usize,
}

impl<'a> XdrR<'a> {
    pub(super) fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }

    fn need(&self, n: usize) -> Result<(), Error> {
        if self.i.saturating_add(n) > self.b.len() {
            Err(Error::GarbageArgs)
        } else {
            Ok(())
        }
    }

    pub(super) fn u32(&mut self) -> Result<u32, Error> {
        self.need(4)?;
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&self.b[self.i..self.i + 4]);
        self.i += 4;
        Ok(u32::from_be_bytes(buf))
    }

    pub(super) fn bool(&mut self) -> Result<bool, Error> {
        Ok(self.u32()? != 0)
    }

    pub(super) fn rest(&self) -> &[u8] {
        self.b.get(self.i..).unwrap_or(&[])
    }

    pub(super) fn opaque(&mut self) -> Result<Vec<u8>, Error> {
        let n = self.u32()? as usize;
        self.need(n)?;
        let v = self.b[self.i..self.i + n].to_vec();
        self.i += n;
        let pad = (4 - (n % 4)) % 4;
        self.i = self.i.saturating_add(pad).min(self.b.len());
        Ok(v)
    }

    /// Not UTF-8 (passwords). Count includes the NUL.
    pub(super) fn cstring_bytes(&mut self) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, Error> {
        let n = self.u32()? as usize;
        if n == 0 {
            return Ok(None);
        }
        self.need(n)?;
        let raw = &self.b[self.i..self.i + n];
        self.i += n;
        let pad = (4 - (n % 4)) % 4;
        self.i = self.i.saturating_add(pad).min(self.b.len());
        let end = raw.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        Ok(Some(zeroize::Zeroizing::new(raw[..end].to_vec())))
    }

    pub(super) fn nullstring(&mut self) -> Result<Option<String>, Error> {
        let Some(raw) = self.cstring_bytes()? else {
            return Ok(None);
        };
        let s = std::str::from_utf8(&raw).map_err(|e| Error::Inner(e.to_string()))?;
        Ok(Some(s.to_owned()))
    }

    pub(super) fn principal(&mut self) -> Result<PrincipalName, Error> {
        Ok(self.principal_realm()?.0)
    }

    pub(super) fn principal_realm(&mut self) -> Result<(PrincipalName, String), Error> {
        let s = self
            .nullstring()?
            .ok_or_else(|| Error::Inner("null principal".into()))?;
        krb5_types::principal_from_unparsed(&s, "").map_err(|e| Error::Inner(e.to_string()))
    }

    pub(super) fn i32_pairs(&mut self) -> Result<Vec<(i32, i32)>, Error> {
        let n = self.u32()?;
        let mut out = Vec::new();
        for _ in 0..n {
            out.push((self.u32()?.cast_signed(), self.u32()?.cast_signed()));
        }
        Ok(out)
    }

    pub(super) fn key_salt_tuples(&mut self) -> Result<Vec<EncryptionType>, Error> {
        let n = self.u32()?;
        let mut out = Vec::new();
        for _ in 0..n {
            let et = i32::try_from(self.u32()?).unwrap_or(i32::MAX);
            let _salttype = self.u32()?;
            let e = EncryptionType::known(et)
                .map_err(|_| Error::Inner("Invalid key/salt tuples".into()))?;
            // `known` as MIT kadmind; `from_iana` stays stricter.
            if e.is_mit_weak() {
                return Err(Error::Inner("Invalid key/salt tuples".into()));
            }
            out.push(e);
        }
        Ok(out)
    }
}

#[derive(Default)]
pub(super) struct XdrW {
    pub(super) b: Vec<u8>,
}

pub(super) fn opaque_len(n: usize) -> usize {
    4 + n + (4 - n % 4) % 4
}

impl XdrW {
    /// No second key copy on grow.
    pub(super) fn with_capacity(n: usize) -> Self {
        Self {
            b: Vec::with_capacity(n),
        }
    }

    pub(super) fn u32(&mut self, v: u32) {
        self.b.extend_from_slice(&v.to_be_bytes());
    }
    pub(super) fn opaque(&mut self, d: &[u8]) {
        self.u32(u32::try_from(d.len()).unwrap_or(0));
        self.b.extend_from_slice(d);
        let pad = (4 - (d.len() % 4)) % 4;
        self.b.extend(std::iter::repeat_n(0u8, pad));
    }

    pub(super) fn nullstring(&mut self, s: Option<&str>) {
        self.cstring_bytes(s.map(str::as_bytes));
    }

    pub(super) fn cstring_bytes(&mut self, s: Option<&[u8]>) {
        match s {
            None => self.u32(0),
            Some(s) => {
                let n = s.len() + 1;
                self.u32(u32::try_from(n).unwrap_or(0));
                self.b.extend_from_slice(s);
                self.b.push(0);
                let pad = (4 - (n % 4)) % 4;
                self.b.extend(std::iter::repeat_n(0u8, pad));
            }
        }
    }
}
