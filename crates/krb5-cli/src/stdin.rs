use std::cell::RefCell;
use std::fmt;
use std::io::{self, BufRead, Read};
use std::os::fd::{AsFd as _, BorrowedFd};

use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::{SigSet, SigmaskHow, Signal, pthread_sigmask};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::sys::termios::{LocalFlags, SetArg, tcgetattr, tcsetattr};
use zeroize::Zeroize;

/// A terminal stdin is put back in line mode, with echo and its signal keys on.
// MIT: `readline` (util/ss/listen.c:32-50)
pub fn line_mode() {
    let stdin = io::stdin();
    if let Ok(mut mode) = tcgetattr(&stdin) {
        mode.local_flags
            .insert(LocalFlags::ICANON | LocalFlags::ISIG | LocalFlags::ECHO);
        let _ = tcsetattr(&stdin, SetArg::TCSANOW, &mode);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caught(pub Signal);

impl fmt::Display for Caught {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "read interrupted by {}", self.0)
    }
}

impl std::error::Error for Caught {}

#[must_use]
pub fn caught(e: &io::Error) -> Option<Signal> {
    e.get_ref()
        .and_then(|inner| inner.downcast_ref::<Caught>())
        .map(|c| c.0)
}

struct Catching {
    fd: SignalFd,
    mask: SigSet,
    before: SigSet,
}

thread_local! {
    static CATCHING: RefCell<Option<Catching>> = const { RefCell::new(None) };
}

#[must_use = "the signals are caught only while the catch lives"]
/// `SIGINT` during a read is returned, instead of ending the process.
// MIT: `catch_signals` (lib/krb5/os/prompter.c:134-146)
// MIT: `ss_listen` (util/ss/listen.c:67-169)
pub struct SignalCatch {
    added: SigSet,
}

impl SignalCatch {
    pub fn new(signals: &[Signal]) -> Self {
        let added = CATCHING.with(|c| {
            let mut state = c.borrow_mut();
            let mut added = SigSet::empty();
            for &s in signals {
                if !state.as_ref().is_some_and(|k| k.mask.contains(s)) {
                    added.add(s);
                }
            }
            if signals_of(&added).is_empty() {
                return added;
            }
            if let Some(k) = state.as_mut() {
                return if widen(k, &added) {
                    added
                } else {
                    SigSet::empty()
                };
            }
            *state = start(&added);
            if state.is_some() {
                added
            } else {
                SigSet::empty()
            }
        });
        Self { added }
    }
}

fn start(added: &SigSet) -> Option<Catching> {
    let mut before = SigSet::empty();
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(added), Some(&mut before)).ok()?;
    let flags = SfdFlags::SFD_NONBLOCK | SfdFlags::SFD_CLOEXEC;
    if let Ok(fd) = SignalFd::with_flags(added, flags) {
        Some(Catching {
            fd,
            mask: *added,
            before,
        })
    } else {
        let _ = pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&before), None);
        None
    }
}

fn widen(k: &mut Catching, added: &SigSet) -> bool {
    let mut mask = k.mask;
    for s in signals_of(added) {
        mask.add(s);
    }
    if pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(added), None).is_err() {
        return false;
    }
    if k.fd.set_mask(&mask).is_err() {
        let _ = pthread_sigmask(
            SigmaskHow::SIG_UNBLOCK,
            Some(&outside(added, &k.before)),
            None,
        );
        return false;
    }
    k.mask = mask;
    true
}

impl Drop for SignalCatch {
    fn drop(&mut self) {
        let added = signals_of(&self.added);
        if added.is_empty() {
            return;
        }
        CATCHING.with(|c| {
            let mut state = c.borrow_mut();
            let Some(k) = state.as_mut() else {
                return;
            };
            if k.fd.set_mask(&self.added).is_ok() {
                while let Ok(Some(_)) = k.fd.read_signal() {}
            }
            let mut mask = k.mask;
            for &s in &added {
                mask.remove(s);
            }
            if signals_of(&mask).is_empty() {
                let before = k.before;
                *state = None;
                let _ = pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&before), None);
                return;
            }
            let _ = k.fd.set_mask(&mask);
            k.mask = mask;
            let _ = pthread_sigmask(
                SigmaskHow::SIG_UNBLOCK,
                Some(&outside(&self.added, &k.before)),
                None,
            );
        });
    }
}

fn signals_of(set: &SigSet) -> Vec<Signal> {
    set.iter().collect()
}

fn outside(set: &SigSet, before: &SigSet) -> SigSet {
    let mut out = SigSet::empty();
    for s in set.iter().filter(|&s| !before.contains(s)) {
        out.add(s);
    }
    out
}

pub struct Stdin {
    buf: Box<[u8]>,
    pos: usize,
    len: usize,
}

impl Stdin {
    #[must_use]
    pub fn unbuffered() -> Self {
        Self {
            buf: Box::new([0]),
            pos: 0,
            len: 0,
        }
    }
}

impl Read for Stdin {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = {
            let have = self.fill_buf()?;
            let n = have.len().min(out.len());
            out[..n].copy_from_slice(&have[..n]);
            n
        };
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for Stdin {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.pos >= self.len {
            self.len = read_fd0(&mut self.buf)?;
            self.pos = 0;
        }
        Ok(&self.buf[self.pos..self.len])
    }

    fn consume(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.len);
    }
}

enum Woke {
    Signal(Signal),
    Readable,
    Again,
}

fn read_fd0(buf: &mut [u8]) -> io::Result<usize> {
    let stdin = io::stdin();
    let fd = stdin.as_fd();
    loop {
        let woke = CATCHING.with(|c| wait(c.borrow().as_ref(), fd))?;
        match woke {
            Woke::Signal(s) => return Err(io::Error::new(io::ErrorKind::Interrupted, Caught(s))),
            Woke::Again => continue,
            Woke::Readable => {}
        }
        match nix::unistd::read(fd, buf) {
            Ok(n) => return Ok(n),
            Err(Errno::EINTR) => {}
            Err(Errno::EBADF) => return Ok(0),
            Err(e) => return Err(e.into()),
        }
    }
}

fn wait(catching: Option<&Catching>, fd: BorrowedFd<'_>) -> io::Result<Woke> {
    let Some(k) = catching else {
        return Ok(Woke::Readable);
    };
    let mut fds = [
        PollFd::new(k.fd.as_fd(), PollFlags::POLLIN),
        PollFd::new(fd, PollFlags::POLLIN),
    ];
    match poll(&mut fds, PollTimeout::NONE) {
        Ok(_) | Err(Errno::EINTR) => {}
        Err(e) => return Err(e.into()),
    }
    if let Some(info) = k.fd.read_signal()?
        && let Some(s) = numbered(info.ssi_signo)
    {
        return Ok(Woke::Signal(s));
    }
    let ready = PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR | PollFlags::POLLNVAL;
    if fds[1].revents().is_some_and(|r| r.intersects(ready)) {
        Ok(Woke::Readable)
    } else {
        Ok(Woke::Again)
    }
}

fn numbered(signo: u32) -> Option<Signal> {
    i32::try_from(signo)
        .ok()
        .and_then(|n| Signal::try_from(n).ok())
}

#[must_use]
pub fn take_caught() -> Option<Signal> {
    CATCHING.with(|c| {
        let state = c.borrow();
        let info = state.as_ref()?.fd.read_signal().ok()??;
        numbered(info.ssi_signo)
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineEnd {
    Read,
    End,
    Caught(Signal),
    Failed,
}

pub fn fgets(input: &mut (impl BufRead + ?Sized), size: usize, line: &mut Vec<u8>) -> LineEnd {
    line.clear();
    while line.len() + 1 < size {
        let have = match input.fill_buf() {
            Ok(have) => have,
            Err(e) => {
                return match caught(&e) {
                    Some(s) => LineEnd::Caught(s),
                    None if e.kind() == io::ErrorKind::Interrupted => continue,
                    None => LineEnd::Failed,
                };
            }
        };
        if have.is_empty() {
            break;
        }
        let room = size - 1 - line.len();
        let take = have
            .iter()
            .take(room)
            .position(|&b| b == b'\n')
            .map_or_else(|| have.len().min(room), |at| at + 1);
        reserve_wiped(line, take);
        line.extend_from_slice(&have[..take]);
        input.consume(take);
        if line.last() == Some(&b'\n') {
            break;
        }
    }
    if line.is_empty() {
        LineEnd::End
    } else {
        LineEnd::Read
    }
}

fn reserve_wiped(line: &mut Vec<u8>, more: usize) {
    if line.capacity() - line.len() >= more {
        return;
    }
    let need = line.len().saturating_add(more);
    let mut grown = Vec::with_capacity(need.max(line.capacity().saturating_mul(2)));
    grown.extend_from_slice(line);
    let mut old = std::mem::replace(line, grown);
    old.resize(old.capacity(), 0);
    old.as_mut_slice().zeroize();
    #[cfg(test)]
    let _ = tests::OUTGROWN.try_with(|o| o.borrow_mut().push(old));
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        pub(super) static OUTGROWN: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
    }

    #[test]
    fn a_line_that_outgrows_its_buffer_wipes_the_old_one() {
        let mut typed = vec![b'p'; 3000];
        typed.push(b'\n');
        let mut input = io::BufReader::with_capacity(512, &typed[..]);
        let mut line = Vec::with_capacity(1024);
        let first = line.as_ptr();
        OUTGROWN.with(|o| o.borrow_mut().clear());
        assert_eq!(fgets(&mut input, usize::MAX, &mut line), LineEnd::Read);
        assert_eq!(line, typed);
        let old = OUTGROWN.with(|o| std::mem::take(&mut *o.borrow_mut()));
        assert_eq!(old, [vec![0; 1024], vec![0; 2048]]);
        assert_eq!(
            old[0].as_ptr(),
            first,
            "a copy was wiped, not the line's own buffer"
        );
    }
}
