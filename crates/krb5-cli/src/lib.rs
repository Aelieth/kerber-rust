//! Command lines and password prompts the MIT way, shared by the kerber-rust tools.
//!
//! - [`getopt`]: glibc `getopt` / `getopt_long`, for the tools MIT builds on it (`kinit`,
//!   `klist`, `krb5kdc`, `kadmin.local`, `kprop`).
//! - [`MitArgs`]: the tools that match each argument against a table by exact spelling
//!   instead (`kdb5_util`'s global options, `kadmind`), with options such as `-nofork`,
//!   `-port N` and `-sf FILE`.
//! - [`Prompter`]: MIT `krb5_prompter_posix` and `krb5_read_password`, one line per prompt
//!   from a pipe, echo off on a terminal, Ctrl-C reported as an interrupted read.
//! - [`Stdin`] and [`SignalCatch`]: stdin read a byte at a time, as MIT's tools set it, and the
//!   signals a read catches instead of ending the process.
//!
//! # Examples
//!
//! `kdb5_util` takes its global options anywhere on the line:
//!
//! ```
//! use krb5_cli::{MitArgs, MitOpt, Placement};
//! const GLOBALS: &[MitOpt] = &[MitOpt::value("-r"), MitOpt::value("-P"), MitOpt::flag("-m")];
//! let argv: Vec<String> = ["create", "-s", "-r", "EXAMPLE.COM"].map(String::from).into();
//! let args = MitArgs::parse(&argv, GLOBALS, Placement::Anywhere)?;
//! assert_eq!(args.value("-r"), Some("EXAMPLE.COM"));
//! assert_eq!(args.operands, ["create", "-s"]);
//! Ok::<(), krb5_cli::ArgError>(())
//! ```
//!
//! A master password piped twice, as KLLDAP feeds `kdb5_util create -s`:
//!
//! ```
//! use krb5_cli::Prompter;
//! let mut out = Vec::new();
//! let mut prompter = Prompter::new(&b"secret\nsecret\n"[..], &mut out);
//! let pw = prompter.password(
//!     "Enter KDC database master key",
//!     Some("Re-enter KDC database master key to verify"),
//! )?;
//! assert_eq!(pw.as_slice(), b"secret");
//! Ok::<(), krb5_cli::PromptError>(())
//! ```

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod args;
mod getopt;
mod prompt;
mod stdin;

pub use args::{ArgError, MitArgs, MitOpt, Placement};
pub use getopt::{LongOpt, Opt, getopt};
pub use nix::sys::signal::Signal;
pub use prompt::{PromptError, Prompter, prompt_hidden, read_password};
pub use stdin::{Caught, LineEnd, SignalCatch, Stdin, caught, fgets, line_mode, take_caught};
