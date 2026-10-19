use crate::{GSS_C_REPLAY, GSS_C_SEQUENCE};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SeqStatus {
    Complete,
    Gap,
    Unseq,
    Old,
    Duplicate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SeqState {
    pub(crate) do_replay: bool,
    pub(crate) do_sequence: bool,
    pub(crate) wide: bool,
    pub(crate) base: u64,
    pub(crate) next: u64,
    pub(crate) recvmap: u64,
}

impl SeqState {
    // MIT g_seqstate_init; see docs/parity/b1-gss.md
    pub(crate) fn new(seqnum: u64, flags: u32, wide: bool) -> Self {
        Self {
            do_replay: flags & GSS_C_REPLAY != 0,
            do_sequence: flags & GSS_C_SEQUENCE != 0,
            wide,
            base: seqnum,
            next: 0,
            recvmap: 0,
        }
    }

    fn mask(&self) -> u64 {
        if self.wide {
            u64::MAX
        } else {
            u64::from(u32::MAX)
        }
    }

    pub(crate) fn past_window(&self, seqnum: u64) -> bool {
        let rel = seqnum.wrapping_sub(self.base) & self.mask();
        rel < self.next && self.next - rel > 64
    }

    // MIT g_seqstate_check; see docs/parity/b1-gss.md
    pub(crate) fn check(&mut self, seqnum: u64) -> SeqStatus {
        if !self.do_replay && !self.do_sequence {
            return SeqStatus::Complete;
        }
        let mask = self.mask();
        let rel = seqnum.wrapping_sub(self.base) & mask;
        if rel >= self.next {
            let offset = rel - self.next;
            // A shift of 64 or more, undefined in MIT's C, empties the bitmap.
            self.recvmap = offset
                .checked_add(1)
                .and_then(|n| u32::try_from(n).ok())
                .and_then(|n| self.recvmap.checked_shl(n))
                .unwrap_or(0)
                | 1;
            self.next = rel.wrapping_add(1) & mask;
            return if offset > 0 && self.do_sequence {
                SeqStatus::Gap
            } else {
                SeqStatus::Complete
            };
        }
        let offset = self.next - rel;
        if offset > 64 {
            return if self.do_sequence {
                SeqStatus::Unseq
            } else {
                SeqStatus::Old
            };
        }
        let bit = 1u64 << (offset - 1);
        if self.do_replay && self.recvmap & bit != 0 {
            return SeqStatus::Duplicate;
        }
        self.recvmap |= bit;
        if self.do_sequence {
            SeqStatus::Unseq
        } else {
            SeqStatus::Complete
        }
    }
}
