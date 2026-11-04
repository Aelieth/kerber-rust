#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod args;
mod getopt;
mod prompt;
mod stdin;

pub use args::{ArgError, MitArgs, MitOpt, Placement};
pub use getopt::{LongOpt, Opt, getopt, getopt_each};
pub use nix::sys::signal::Signal;
pub use prompt::{PromptError, Prompter, prompt_hidden, read_password};
pub use stdin::{Caught, LineEnd, SignalCatch, Stdin, caught, fgets, line_mode, take_caught};
