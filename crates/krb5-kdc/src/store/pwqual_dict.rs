//! The `dict` password-quality module (`lib/kadm5/srv/pwqual_dict.c`): the realm's `dict_file`,
//! read once by kadmind, kadmin.local and `kdb5_util create` into one block and a sorted index of
//! its words. The store shares it, and a reread moves it, never copies it. The KDC never reads
//! `dict_file`.

use std::io::{self, Read as _};
use std::path::Path;
use std::sync::Arc;

use krb5_log::klog::{self, Severity};

use super::PrincipalStore;

/// The words of a dictionary file, kept as MIT keeps them: the file in one block and an index
/// of where each word starts, sorted for a binary search.
/// MIT `init_dict` (`lib/kadm5/srv/pwqual_dict.c:124-151`): the file is read into one block and the words are pointers into it, sorted.
pub(crate) struct PwqualDict {
    /// The file's `\n`-terminated lines, ASCII-lowercased; each word ends at its `\n`.
    block: Box<[u8]>,
    /// Where each word starts in `block`, in the order of the words' bytes, each word once.
    words: Box<[u32]>,
}

impl std::fmt::Debug for PwqualDict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PwqualDict")
            .field("words", &self.words.len())
            .field("bytes", &self.block.len())
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

    /// The dictionary in `block`, a dictionary file's bytes.
    /// MIT `init_dict` (`lib/kadm5/srv/pwqual_dict.c:136-151`): every `\n`-terminated line is a word, an unterminated last line is not, and a blank line is the empty word.
    /// MIT `word_compare` (`lib/kadm5/srv/pwqual_dict.c:64-68`): words sort with `strcasecmp`, the order of their ASCII-lowercased bytes.
    ///
    /// # Errors
    ///
    /// `FileTooLarge` when the words do not fit in 4 GiB.
    pub(crate) fn from_bytes(mut block: Vec<u8>) -> io::Result<Self> {
        let too_large = || io::Error::from(io::ErrorKind::FileTooLarge);
        let end = block.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
        block.truncate(end);
        block.make_ascii_lowercase();
        let mut spans: Vec<(u32, u32)> = Vec::new();
        let mut start = 0u32;
        for line in block.split_inclusive(|&b| b == b'\n') {
            let len = u32::try_from(line.len()).map_err(|_| too_large())?;
            spans.push((start, len.saturating_sub(1)));
            start = start.checked_add(len).ok_or_else(too_large)?;
        }
        let word = |&(s, l): &(u32, u32)| {
            block
                .get(s as usize..s as usize + l as usize)
                .unwrap_or_default()
        };
        spans.sort_unstable_by(|a, b| word(a).cmp(word(b)));
        spans.dedup_by(|a, b| word(a) == word(b));
        let words = spans.into_iter().map(|(s, _)| s).collect();
        block.shrink_to_fit();
        Ok(Self {
            block: block.into_boxed_slice(),
            words,
        })
    }

    /// Whether `password` is one of the words, compared as `strcasecmp` compares them; the
    /// password is folded as it is compared, never copied.
    /// MIT `dict_check` (`lib/kadm5/srv/pwqual_dict.c:227-231`): a `bsearch` with `strcasecmp` finds the password among the sorted words.
    pub(crate) fn contains(&self, password: &[u8]) -> bool {
        self.words
            .binary_search_by(|&start| {
                self.word(start)
                    .iter()
                    .copied()
                    .cmp(password.iter().map(u8::to_ascii_lowercase))
            })
            .is_ok()
    }

    /// The word starting at `start`: the bytes up to its `\n`.
    fn word(&self, start: u32) -> &[u8] {
        self.block
            .get(start as usize..)
            .and_then(|rest| rest.split(|&b| b == b'\n').next())
            .unwrap_or_default()
    }

    /// How many distinct words the dictionary holds.
    #[cfg(test)]
    pub(crate) fn word_count(&self) -> usize {
        self.words.len()
    }
}

/// The file's bytes as MIT reads them: as many as `fstat` gives, at most, so a device that says 0
/// (`/dev/zero`) gives none. The first `read` is made even for 0 bytes, which still reports a
/// directory's `EISDIR`.
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
