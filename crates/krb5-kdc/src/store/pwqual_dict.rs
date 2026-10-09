//! The `dict` password-quality module (`lib/kadm5/srv/pwqual_dict.c`): the realm's `dict_file`,
//! read once by kadmind, kadmin.local and `kdb5_util create` into one block and a sorted index of
//! its words. The store shares it, and a reread moves it, never copies it. The KDC never reads
//! `dict_file`.

use std::io::{self, Read as _};
use std::path::Path;
use std::sync::{Arc, OnceLock};

use krb5_log::klog::{self, Severity};

use super::PrincipalStore;

/// How `strcasecmp` folds one byte. ASCII in the C and UTF-8 locales; ISO-8859-1 letters too
/// when the process locale names that codeset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CaseFold {
    /// `a-z` / `A-Z` only, as glibc `strcasecmp` does in the C and UTF-8 locales.
    Ascii,
    /// ASCII plus `U+00C0..U+00D6` and `U+00D8..U+00DE` (not `U+00D7`), as glibc does in an
    /// ISO-8859-1 locale.
    Latin1,
}

/// The words of a dictionary file, kept as MIT keeps them: the file in one block and an index
/// of where each word starts, sorted for a binary search.
/// MIT `init_dict` (`lib/kadm5/srv/pwqual_dict.c:124-151`): the file is read into one block and the words are pointers into it, sorted.
pub(crate) struct PwqualDict {
    /// The file's `\n`-terminated lines with each `\n` turned into a NUL, folded with [`Self::fold`].
    block: Box<[u8]>,
    /// Where each word starts in `block`, in the order of the folded bytes, each word once.
    words: Box<[u32]>,
    /// The fold applied when the block was loaded. Comparison uses this, not a later locale.
    fold: CaseFold,
}

impl std::fmt::Debug for PwqualDict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PwqualDict")
            .field("words", &self.words.len())
            .field("bytes", &self.block.len())
            .field("fold", &self.fold)
            .finish()
    }
}

impl PwqualDict {
    /// The dictionary `dict_file` names, `None` when there is none to read; either case gets
    /// MIT's notice, which `note` takes ([`PrincipalStore::init_pwqual`] logs it with klog).
    /// MIT `init_dict` (`lib/kadm5/srv/pwqual_dict.c:104-118`): no `dict_file` and a missing file leave the server without a dictionary; any other open error is returned.
    ///
    /// # Errors
    ///
    /// The open, `fstat` or read error of a `dict_file` that exists but cannot be read (a
    /// directory's `EISDIR`), and `FileTooLarge` for a dictionary of 4 GiB or more.
    pub(crate) fn open(
        dict_file: Option<&Path>,
        note: &mut dyn FnMut(Severity, &str),
    ) -> io::Result<Option<Self>> {
        let Some(path) = dict_file else {
            note(
                Severity::Info,
                "No dictionary file specified, continuing without one.",
            );
            return Ok(None);
        };
        let mut file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                note(
                    Severity::Err,
                    &format!(
                        "WARNING!  Cannot find dictionary file {}, continuing without one.",
                        path.display()
                    ),
                );
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        Self::from_bytes(read_fstat_size(&mut file)?).map(Some)
    }

    /// The dictionary in `block`, folded the way the process locale's `strcasecmp` folds.
    /// MIT `init_dict` (`lib/kadm5/srv/pwqual_dict.c:136-151`): every newline is a word, an unterminated last line is not, and a NUL ends the word so the words after it shift.
    /// MIT `word_compare` (`lib/kadm5/srv/pwqual_dict.c:64-68`): words sort with `strcasecmp`.
    ///
    /// # Errors
    ///
    /// `FileTooLarge` when a word's offset does not fit in 4 GiB.
    pub(crate) fn from_bytes(block: Vec<u8>) -> io::Result<Self> {
        Self::from_bytes_folded(block, case_fold())
    }

    /// [`Self::from_bytes`] with `fold` instead of the process locale.
    ///
    /// # Errors
    ///
    /// As [`Self::from_bytes`].
    pub(crate) fn from_bytes_folded(mut block: Vec<u8>, fold: CaseFold) -> io::Result<Self> {
        let too_large = || io::Error::from(io::ErrorKind::FileTooLarge);
        let end = block.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
        block.truncate(end);
        let mut word_count = 0usize;
        for byte in &mut block {
            if *byte == b'\n' {
                *byte = 0;
                word_count += 1;
            } else {
                *byte = fold_byte(*byte, fold);
            }
        }
        let mut spans = Vec::with_capacity(word_count);
        let mut pos = 0usize;
        for _ in 0..word_count {
            let start = pos.min(block.len());
            let start_u = u32::try_from(start).map_err(|_| too_large())?;
            spans.push(start_u);
            let len = word_at(&block, start_u).len();
            pos = start.saturating_add(len).saturating_add(1);
        }
        spans.sort_unstable_by(|&a, &b| word_at(&block, a).cmp(word_at(&block, b)));
        spans.dedup_by(|&mut a, &mut b| word_at(&block, a) == word_at(&block, b));
        block.shrink_to_fit();
        Ok(Self {
            block: block.into_boxed_slice(),
            words: spans.into_boxed_slice(),
            fold,
        })
    }

    /// Whether `password` is one of the words, compared as `strcasecmp` compares them; the
    /// password is folded as it is compared, never copied. A NUL ends the password.
    /// MIT `dict_check` (`lib/kadm5/srv/pwqual_dict.c:227-231`): a `bsearch` with `strcasecmp` finds the password among the sorted words.
    pub(crate) fn contains(&self, password: &[u8]) -> bool {
        let password = cstr_bytes(password);
        self.words
            .binary_search_by(|&start| {
                self.word(start)
                    .iter()
                    .copied()
                    .cmp(password.iter().copied().map(|b| fold_byte(b, self.fold)))
            })
            .is_ok()
    }

    /// The word starting at `start`: the bytes up to its NUL.
    fn word(&self, start: u32) -> &[u8] {
        word_at(&self.block, start)
    }

    /// How many distinct words the dictionary holds.
    #[cfg(test)]
    pub(crate) fn word_count(&self) -> usize {
        self.words.len()
    }
}

/// The bytes of a C string: up to, not including, the first NUL.
fn cstr_bytes(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&b| b == 0) {
        Some(n) => bytes.get(..n).unwrap_or_default(),
        None => bytes,
    }
}

/// The word at `start` in a block whose words are NUL-terminated.
fn word_at(block: &[u8], start: u32) -> &[u8] {
    let rest = block.get(start as usize..).unwrap_or_default();
    match rest.iter().position(|&b| b == 0) {
        Some(n) => rest.get(..n).unwrap_or_default(),
        None => rest,
    }
}

/// `b` folded the way `fold` says `strcasecmp` folds it.
pub(crate) fn fold_byte(b: u8, fold: CaseFold) -> u8 {
    match fold {
        CaseFold::Ascii => b.to_ascii_lowercase(),
        CaseFold::Latin1 => match b {
            b'A'..=b'Z' | 0xC0..=0xD6 | 0xD8..=0xDE => b.wrapping_add(0x20),
            _ => b,
        },
    }
}

/// `strcasecmp` of two byte strings under the process locale's fold. A NUL ends either side.
pub(crate) fn eq_ignore_case(left: &[u8], right: &[u8]) -> bool {
    let fold = case_fold();
    let left = cstr_bytes(left);
    let right = cstr_bytes(right);
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(a, b)| fold_byte(*a, fold) == fold_byte(*b, fold))
}

/// The fold `strcasecmp` uses in this process: Latin-1 only when `LC_ALL`, else `LC_CTYPE`,
/// else `LANG`, names that codeset. Read once.
pub(crate) fn case_fold() -> CaseFold {
    static FOLD: OnceLock<CaseFold> = OnceLock::new();
    *FOLD.get_or_init(|| case_fold_for_locale(&locale_spec()))
}

/// The fold `spec` names. `spec` is one locale string (`en_US.ISO-8859-1`, `C.UTF-8`, `C`).
pub(crate) fn case_fold_for_locale(spec: &str) -> CaseFold {
    let spec = spec.split('@').next().unwrap_or(spec);
    let codeset = spec.rsplit_once('.').map_or(spec, |(_, codeset)| codeset);
    let mut flat = String::new();
    for c in codeset.chars() {
        if c == '-' || c == '_' {
            continue;
        }
        flat.push(c.to_ascii_lowercase());
    }
    if flat == "iso88591" || flat == "latin1" {
        CaseFold::Latin1
    } else {
        CaseFold::Ascii
    }
}

/// `LC_ALL`, else `LC_CTYPE`, else `LANG`; empty when none of them is set to a non-empty value.
fn locale_spec() -> String {
    for key in ["LC_ALL", "LC_CTYPE", "LANG"] {
        if let Ok(value) = std::env::var(key)
            && !value.is_empty()
        {
            return value;
        }
    }
    String::new()
}

/// The file's bytes as MIT reads them: as many as `fstat` gives, at most, so a device that says 0
/// (`/dev/zero`, a FIFO with a writer) gives none. The first `read` is made even for 0 bytes, which
/// still reports a directory's `EISDIR`.
/// MIT `init_dict` (`lib/kadm5/srv/pwqual_dict.c:120-133`): the file is read once, `st_size` bytes from `fstat`.
fn read_fstat_size(file: &mut std::fs::File) -> io::Result<Vec<u8>> {
    let size = u32::try_from(file.metadata()?.len())
        .map_err(|_| io::Error::from(io::ErrorKind::FileTooLarge))?;
    let mut block = vec![0u8; size as usize];
    let mut filled = 0;
    loop {
        let n = file.read(block.get_mut(filled..).unwrap_or_default())?;
        filled += n;
        if n == 0 || filled >= block.len() {
            break;
        }
    }
    block.truncate(filled);
    Ok(block)
}

impl PrincipalStore {
    /// Read the realm's `dict_file` for the password-quality checks: kadmind, kadmin.local and
    /// `kdb5_util create` call this once as they start, and every request and reread after shares
    /// what it read. The KDC never calls it.
    /// MIT `kadm5_init` (`lib/kadm5/srv/server_init.c:266-268`): the password-quality modules are set up last, once per kadm5 handle.
    /// MIT `init_pwqual` (`lib/kadm5/srv/server_misc.c:62-66`): the `dict` module is bound to `[realms] dict_file`.
    ///
    /// # Errors
    ///
    /// The open or read error of a `dict_file` that exists but cannot be read (MIT's
    /// `kadm5_init` fails with it); the store keeps the dictionary it had.
    pub fn init_pwqual(&mut self, conf: Option<&krb5_config::KdcConf>) -> io::Result<()> {
        self.init_pwqual_noting(conf, &mut |severity, text| klog::syslog(severity, text))
    }

    /// [`Self::init_pwqual`], with MIT's notice given to `note` instead of the log.
    ///
    /// # Errors
    ///
    /// As [`Self::init_pwqual`].
    pub(crate) fn init_pwqual_noting(
        &mut self,
        conf: Option<&krb5_config::KdcConf>,
        note: &mut dyn FnMut(Severity, &str),
    ) -> io::Result<()> {
        let dict_file = conf.and_then(|c| c.dict_file.as_deref());
        self.pwqual_dict = PwqualDict::open(dict_file, note)?.map(Arc::new);
        Ok(())
    }
}
