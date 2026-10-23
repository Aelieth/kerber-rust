//! Dictionary check of a password.

use std::io::{self, Read as _};
use std::path::Path;
use std::sync::{Arc, OnceLock};

use krb5_log::klog::{self, Severity};

use super::PrincipalStore;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CaseFold {
    Ascii,
    Latin1,
}

// MIT: `init_dict` (lib/kadm5/srv/pwqual_dict.c:124-151)
pub(crate) struct PwqualDict {
    block: Box<[u8]>,
    words: Box<[u32]>,
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
    // MIT: `init_dict` (lib/kadm5/srv/pwqual_dict.c:104-118)
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

    // MIT: `init_dict` (lib/kadm5/srv/pwqual_dict.c:136-151)
    // MIT: `word_compare` (lib/kadm5/srv/pwqual_dict.c:64-68)
    pub(crate) fn from_bytes(block: Vec<u8>) -> io::Result<Self> {
        Self::from_bytes_folded(block, case_fold())
    }

    /// A last line with no newline is not a word.
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

    // MIT: `dict_check` (lib/kadm5/srv/pwqual_dict.c:227-231)
    /// The fold is fixed at load.
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

    fn word(&self, start: u32) -> &[u8] {
        word_at(&self.block, start)
    }

    #[cfg(test)]
    pub(crate) fn word_count(&self) -> usize {
        self.words.len()
    }
}

fn cstr_bytes(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&b| b == 0) {
        Some(n) => bytes.get(..n).unwrap_or_default(),
        None => bytes,
    }
}

fn word_at(block: &[u8], start: u32) -> &[u8] {
    let rest = block.get(start as usize..).unwrap_or_default();
    match rest.iter().position(|&b| b == 0) {
        Some(n) => rest.get(..n).unwrap_or_default(),
        None => rest,
    }
}

/// Latin-1 folds letters, not byte D7.
pub(crate) fn fold_byte(b: u8, fold: CaseFold) -> u8 {
    match fold {
        CaseFold::Ascii => b.to_ascii_lowercase(),
        CaseFold::Latin1 => match b {
            b'A'..=b'Z' | 0xC0..=0xD6 | 0xD8..=0xDE => b.wrapping_add(0x20),
            _ => b,
        },
    }
}

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

pub(crate) fn case_fold() -> CaseFold {
    static FOLD: OnceLock<CaseFold> = OnceLock::new();
    *FOLD.get_or_init(|| case_fold_for_locale(&locale_spec()))
}

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

#[allow(clippy::disallowed_methods, reason = "the process's locale, read once")]
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

// MIT: `init_dict` (lib/kadm5/srv/pwqual_dict.c:120-133)
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
    // MIT: `kadm5_init` (lib/kadm5/srv/server_init.c:266-268)
    // MIT: `init_pwqual` (lib/kadm5/srv/server_misc.c:62-66)
    pub fn init_pwqual(&mut self, conf: Option<&krb5_config::KdcConf>) -> io::Result<()> {
        self.init_pwqual_noting(conf, &mut |severity, text| klog::syslog(severity, text))
    }

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
