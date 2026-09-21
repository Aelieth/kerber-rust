//! MS-PAC / MS-RPCE Type-Serialization v1 NDR32 codec for
//! `KERB_VALIDATION_INFO`.
//!
//! MIT `lib/krb5/krb/pac.c` does not parse this buffer; the codec is
//! the Windows layout, not an MIT function.

use super::{ExtraSid, GroupMembership, NDR_PTR_BASE, PacError, RpcSid, RpcUnicode};

pub(super) struct NdrR<'a> {
    pub(super) b: &'a [u8],
    pub(super) i: usize,
}

impl NdrR<'_> {
    fn need(&self, n: usize) -> Result<(), PacError> {
        if self.i.checked_add(n).is_none_or(|e| e > self.b.len()) {
            Err(PacError::Truncated)
        } else {
            Ok(())
        }
    }

    fn align4(&mut self) {
        let pad = (4 - (self.i % 4)) % 4;
        self.i = self.i.saturating_add(pad).min(self.b.len());
    }

    pub(super) fn u8(&mut self) -> Result<u8, PacError> {
        self.need(1)?;
        let v = self.b[self.i];
        self.i += 1;
        Ok(v)
    }

    pub(super) fn u16(&mut self) -> Result<u16, PacError> {
        self.need(2)?;
        let v = u16::from_le_bytes(
            self.b[self.i..self.i + 2]
                .try_into()
                .map_err(|_| PacError::Truncated)?,
        );
        self.i += 2;
        Ok(v)
    }

    pub(super) fn u32(&mut self) -> Result<u32, PacError> {
        self.need(4)?;
        let v = u32::from_le_bytes(
            self.b[self.i..self.i + 4]
                .try_into()
                .map_err(|_| PacError::Truncated)?,
        );
        self.i += 4;
        Ok(v)
    }

    pub(super) fn u64(&mut self) -> Result<u64, PacError> {
        self.need(8)?;
        let v = u64::from_le_bytes(
            self.b[self.i..self.i + 8]
                .try_into()
                .map_err(|_| PacError::Truncated)?,
        );
        self.i += 8;
        Ok(v)
    }

    pub(super) fn take_str(&mut self, s: RpcUnicode) -> Result<RpcUnicode, PacError> {
        if s.pointed {
            self.conf_string(s)
        } else {
            Ok(s)
        }
    }

    pub(super) fn bytes(&mut self, n: usize) -> Result<&[u8], PacError> {
        self.need(n)?;
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }

    pub(super) fn ustr(&mut self) -> Result<RpcUnicode, PacError> {
        let length = self.u16()?;
        let maximum_length = self.u16()?;
        let ptr = self.u32()?;
        Ok(RpcUnicode {
            length,
            maximum_length,
            pointed: ptr != 0,
            value: String::new(),
        })
    }

    fn conf_string(&mut self, mut s: RpcUnicode) -> Result<RpcUnicode, PacError> {
        self.align4();
        let maxc = self.u32()?;
        let _off = self.u32()?;
        let act = self.u32()?;
        if act > maxc || act > 1024 {
            return Err(PacError::Truncated);
        }
        let nbytes = usize::try_from(act.saturating_mul(2)).map_err(|_| PacError::Truncated)?;
        let raw = self.bytes(nbytes)?;
        let mut u16s = Vec::with_capacity(act as usize);
        for k in 0..act as usize {
            u16s.push(u16::from_le_bytes([raw[k * 2], raw[k * 2 + 1]]));
        }
        s.value = String::from_utf16(&u16s).map_err(|_| PacError::Truncated)?;
        let pad = (4 - (nbytes % 4)) % 4;
        self.i = self.i.saturating_add(pad).min(self.b.len());
        Ok(s)
    }

    pub(super) fn group_array(&mut self, expect: u32) -> Result<Vec<GroupMembership>, PacError> {
        self.align4();
        let maxc = self.u32()?;
        if maxc != expect || maxc > 1024 {
            return Err(PacError::Truncated);
        }
        let mut out = Vec::with_capacity(maxc as usize);
        for _ in 0..maxc {
            out.push(GroupMembership {
                relative_id: self.u32()?,
                attributes: self.u32()?,
            });
        }
        Ok(out)
    }

    pub(super) fn sid(&mut self) -> Result<RpcSid, PacError> {
        self.align4();
        let maxc = self.u32()?;
        let revision = self.u8()?;
        let subc = self.u8()?;
        if u32::from(subc) > maxc || subc > 15 {
            return Err(PacError::Truncated);
        }
        let ia = self.bytes(6)?;
        let mut identifier_authority = [0u8; 6];
        identifier_authority.copy_from_slice(ia);
        let mut sub_authority = Vec::with_capacity(usize::from(subc));
        for _ in 0..subc {
            sub_authority.push(self.u32()?);
        }
        Ok(RpcSid {
            revision,
            identifier_authority,
            sub_authority,
        })
    }

    pub(super) fn extra_sids(&mut self, expect: u32) -> Result<Vec<ExtraSid>, PacError> {
        self.align4();
        let maxc = self.u32()?;
        if maxc != expect || maxc > 64 {
            return Err(PacError::Truncated);
        }
        let mut hdrs = Vec::with_capacity(maxc as usize);
        for _ in 0..maxc {
            let ptr = self.u32()?;
            let attributes = self.u32()?;
            hdrs.push((ptr, attributes));
        }
        let mut out = Vec::with_capacity(hdrs.len());
        for (ptr, attributes) in hdrs {
            if ptr == 0 {
                return Err(PacError::Truncated);
            }
            out.push(ExtraSid {
                sid: self.sid()?,
                attributes,
            });
        }
        Ok(out)
    }
}

pub(super) struct NdrW {
    pub(super) b: Vec<u8>,
    next: u32,
}

impl Default for NdrW {
    fn default() -> Self {
        Self {
            b: Vec::new(),
            next: NDR_PTR_BASE,
        }
    }
}

impl NdrW {
    pub(super) fn u8(&mut self, v: u8) {
        self.b.push(v);
    }
    pub(super) fn u16(&mut self, v: u16) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    pub(super) fn u32(&mut self, v: u32) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    pub(super) fn u64(&mut self, v: u64) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn align4(&mut self) {
        while !self.b.len().is_multiple_of(4) {
            self.b.push(0);
        }
    }
    pub(super) fn ptr(&mut self, present: bool) {
        if present {
            self.u32(self.next);
            self.next = self.next.saturating_add(4);
        } else {
            self.u32(0);
        }
    }
    pub(super) fn ustr_hdr(&mut self, s: &RpcUnicode) {
        self.u16(s.length);
        self.u16(s.maximum_length);
        self.ptr(s.pointed);
    }
    pub(super) fn ustr_body(&mut self, s: &RpcUnicode) {
        if !s.pointed {
            return;
        }
        self.align4();
        self.u32(s.max_chars());
        self.u32(0);
        self.u32(s.actual_chars());
        let utf16: Vec<u8> = s.value.encode_utf16().flat_map(u16::to_le_bytes).collect();
        self.b.extend_from_slice(&utf16);
        self.align4();
    }
    pub(super) fn group_array(&mut self, g: &[GroupMembership]) {
        self.align4();
        self.u32(u32::try_from(g.len()).unwrap_or(0));
        for m in g {
            self.u32(m.relative_id);
            self.u32(m.attributes);
        }
    }
    pub(super) fn sid(&mut self, s: &RpcSid) {
        self.align4();
        let n = u32::try_from(s.sub_authority.len()).unwrap_or(0);
        self.u32(n);
        self.u8(s.revision);
        self.u8(u8::try_from(s.sub_authority.len()).unwrap_or(0));
        self.b.extend_from_slice(&s.identifier_authority);
        for r in &s.sub_authority {
            self.u32(*r);
        }
    }
    pub(super) fn extra_sids(&mut self, extras: &[ExtraSid]) {
        self.align4();
        self.u32(u32::try_from(extras.len()).unwrap_or(0));
        for e in extras {
            self.ptr(true);
            self.u32(e.attributes);
        }
        for e in extras {
            self.sid(&e.sid);
        }
    }
}
