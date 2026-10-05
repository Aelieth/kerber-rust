//! stdin as MIT's tools read it: unbuffered, one byte per read, so a reply takes only its line
//! and leaves the rest of the input to the next reader; and the signals a reader catches, so that
//! a read they cut short ends with the signal reported instead of the process ending.

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

/// A terminal stdin back in line mode, echoing, with its signal keys on; stdin that is not a
/// terminal is left alone.
/// MIT `readline` (`util/ss/listen.c:40-43`): `ICANON`, `ISIG` and `ECHO` set before each
/// prompt.
pub fn line_mode() {
    let stdin = io::stdin();
    if let Ok(mut mode) = tcgetattr(&stdin) {
        mode.local_flags
            .insert(LocalFlags::ICANON | LocalFlags::ISIG | LocalFlags::ECHO);
        let _ = tcsetattr(&stdin, SetArg::TCSANOW, &mode);
    }
}

/// The signal that cut a [`Stdin`] read short: the payload of the
/// [`io::ErrorKind::Interrupted`] error such a read returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caught(pub Signal);

impl fmt::Display for Caught {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "read interrupted by {}", self.0)
    }
}

impl std::error::Error for Caught {}

/// The signal a read error reports, when a caught signal cut the read short.
#[must_use]
pub fn caught(e: &io::Error) -> Option<Signal> {
    e.get_ref()
        .and_then(|inner| inner.downcast_ref::<Caught>())
        .map(|c| c.0)
}

/// The signals this thread holds off and reads from a signalfd while [`SignalCatch`]es live.
struct Catching {
    fd: SignalFd,
    mask: SigSet,
    /// The thread's signal mask before the first catch.
    before: SigSet,
}

thread_local! {
    static CATCHING: RefCell<Option<Catching>> = const { RefCell::new(None) };
}

/// While this lives, `signals` no longer take their default action on this thread: a [`Stdin`]
/// read they arrive during returns them as [`Caught`], and one that arrives between reads waits
/// for the next or for [`take_caught`]. MIT's readers install a handler for the same span: `krb5_prompter_posix` for
/// `SIGINT` while a reply is read, `ss_listen` for `SIGINT` through the command loop and for
/// `SIGCONT` while the prompt waits. Dropping it gives the signals back, a pending one it caught
/// included, so it does not fire later.
///
/// MIT `catch_signals` (`lib/krb5/os/prompter.c:133-146`): `SIGINT` caught, with no
/// `SA_RESTART`, for the read.
/// MIT `ss_listen` (`util/ss/listen.c:87-114`): `SIGINT` caught through the loop.
///
/// A thread that cannot hold a signal off (no signalfd) keeps its default action.
#[must_use = "the signals are caught only while the catch lives"]
pub struct SignalCatch {
    added: SigSet,
}

impl SignalCatch {
    /// Catch `signals` until this drops; ones an enclosing catch holds stay with it.
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

/// The first catch: `added` held off this thread and read from a new signalfd; `None`, with the
/// mask as it was, when either fails.
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

/// A nested catch: `added` held off too and read from the same signalfd; false, with the mask as
/// it was, when either fails.
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

/// The signals of `set` that `before` did not hold off: the ones a catch may give back.
fn outside(set: &SigSet, before: &SigSet) -> SigSet {
    let mut out = SigSet::empty();
    for s in set.iter().filter(|&s| !before.contains(s)) {
        out.add(s);
    }
    out
}

/// stdin (file descriptor 0) read without a buffer of its own beyond `capacity` bytes, and with
/// the signals a [`SignalCatch`] holds reported as [`Caught`].
pub struct Stdin {
    buf: Box<[u8]>,
    pos: usize,
    len: usize,
}

impl Stdin {
    /// One byte per read, as MIT sets stdin unbuffered for the prompt loop and reads a reply.
    /// MIT `readline` (`util/ss/listen.c:32-50`): stdin unbuffered, so nothing past the line is
    /// read.
    /// MIT `krb5_prompter_posix` (`lib/krb5/os/prompter.c:62-70`): the reply is read through an
    /// unbuffered `dup` of stdin.
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

/// What a wait for stdin turned up.
enum Woke {
    Signal(Signal),
    Readable,
    Again,
}

/// One `read(2)` of file descriptor 0; with a catch held, a caught signal first. A closed
/// descriptor reads as the end of the input, as Rust's own stdin does.
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

/// With no catch held, stdin is read at once; with one, `poll` waits for stdin or a caught
/// signal, the signal first, as a signal cuts a blocked read short.
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

/// A signal this thread's [`SignalCatch`]es hold pending, taken: one that came while no
/// [`Stdin`] read waited for it. `None` when none is pending or no catch is held.
#[must_use]
pub fn take_caught() -> Option<Signal> {
    CATCHING.with(|c| {
        let state = c.borrow();
        let info = state.as_ref()?.fd.read_signal().ok()??;
        numbered(info.ssi_signo)
    })
}

/// How [`fgets`] ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineEnd {
    /// Bytes were read: a line, or the input's last bytes, or `size - 1` bytes of a longer line.
    Read,
    /// The input ended before any byte.
    End,
    /// A caught signal cut the read short; the bytes read before it are kept.
    Caught(Signal),
    /// The read failed.
    Failed,
}

/// C `fgets(buf, size, stream)` on `input`, into `line`: at most `size - 1` bytes, up to and
/// including a newline; the rest of a longer line stays for the next read. A line can be a
/// password, so one that outgrows `line`'s buffer moves to a larger one and the old buffer is
/// wiped before it is freed.
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

/// Makes room for `more` bytes in `line`. A buffer too small is not reallocated in place, which
/// would free it unwiped: its bytes move to a buffer at least twice as large, and the old one is
/// zeroed whole before it is freed.
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
    use nix::sys::signal::raise;

    thread_local! {
        /// The buffers `reserve_wiped` replaced on this thread, kept alive as it left them.
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
        // The 1024-octet buffer the prompt starts with, then the 2048-octet one it grew into.
        assert_eq!(old, [vec![0; 1024], vec![0; 2048]]);
        assert_eq!(
            old[0].as_ptr(),
            first,
            "a copy was wiped, not the line's own buffer"
        );
    }

    fn read(input: &[u8], size: usize) -> (LineEnd, Vec<u8>, Vec<u8>) {
        let mut input = input;
        let mut line = Vec::new();
        let end = fgets(&mut input, size, &mut line);
        (end, line, input.to_vec())
    }

    #[test]
    fn fgets_stops_at_the_newline_or_size_minus_one() {
        assert_eq!(
            read(b"yes\nrest\n", 5),
            (LineEnd::Read, b"yes\n".to_vec(), b"rest\n".to_vec())
        );
        assert_eq!(
            read(b"yesss\n", 5),
            (LineEnd::Read, b"yess".to_vec(), b"s\n".to_vec())
        );
        assert_eq!(
            read(b"tail", 100),
            (LineEnd::Read, b"tail".to_vec(), Vec::new())
        );
        assert_eq!(read(b"", 100), (LineEnd::End, Vec::new(), Vec::new()));
    }

    #[test]
    fn a_caught_sigint_cuts_a_stdin_read_short_and_a_pending_one_goes_with_the_catch() {
        let catch = SignalCatch::new(&[Signal::SIGINT]);
        raise(Signal::SIGINT).unwrap();
        let mut line = Vec::new();
        assert_eq!(
            fgets(&mut Stdin::unbuffered(), 100, &mut line),
            LineEnd::Caught(Signal::SIGINT)
        );
        raise(Signal::SIGINT).unwrap();
        drop(catch);
    }

    #[test]
    fn take_caught_takes_a_pending_signal_once() {
        let catch = SignalCatch::new(&[Signal::SIGINT]);
        assert_eq!(take_caught(), None);
        raise(Signal::SIGINT).unwrap();
        assert_eq!(take_caught(), Some(Signal::SIGINT));
        assert_eq!(take_caught(), None);
        drop(catch);
        assert_eq!(take_caught(), None);
    }

    #[test]
    fn a_nested_catch_gives_back_only_its_own_signals() {
        let outer = SignalCatch::new(&[Signal::SIGINT]);
        {
            let _inner = SignalCatch::new(&[Signal::SIGINT, Signal::SIGCONT]);
            raise(Signal::SIGCONT).unwrap();
        }
        raise(Signal::SIGINT).unwrap();
        let mut line = Vec::new();
        assert_eq!(
            fgets(&mut Stdin::unbuffered(), 100, &mut line),
            LineEnd::Caught(Signal::SIGINT)
        );
        drop(outer);
    }

    #[test]
    fn caught_names_only_a_caught_signal() {
        let e = io::Error::new(io::ErrorKind::Interrupted, Caught(Signal::SIGINT));
        assert_eq!(caught(&e), Some(Signal::SIGINT));
        assert_eq!(caught(&io::Error::from(io::ErrorKind::Interrupted)), None);
    }
}
