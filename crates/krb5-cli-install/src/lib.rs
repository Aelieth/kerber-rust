//! Linked by `krb5-kinit` and `krb5-kadmind` so those binaries own the
//! two stderr lines. Other crates that call the emitters do not print.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

fn print_key_exp_banner() {
    eprintln!("Password expired.  You must change it now.");
}

fn print_kadm5_error(msg: &str) {
    eprintln!("kadm5: {msg}");
}

#[ctor::ctor]
fn install_cli_printers() {
    krb5_cli_print::set_key_exp_banner_hook(print_key_exp_banner);
    krb5_cli_print::set_kadm5_error_hook(print_kadm5_error);
}
