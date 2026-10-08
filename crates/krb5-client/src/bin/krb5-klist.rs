//! MIT `klist`: list a credential cache, the cache collection, or a keytab.
//!
//! Usage: `klist [-e] [[-c] [-l] [-A] [-d] [-f] [-s] [-a [-n]]] [-k [-i] [-t] [-K]] [-C] [name]`
//! (MIT's `-V` is not taken). Times follow the process locale, and the date columns are as wide
//! as MIT's probe of that locale; addresses (`-a`) are printed numerically.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::fmt::Write as _;
use std::sync::OnceLock;

use krb5_types::timestamp::timestamp_to_sfstring;

use krb5_asn1::decode;
use krb5_client::ccol::{Cache, collection, resolve};
use krb5_client::cli::{
    KlistArgs, KlistParseError, check_ccache, klist_usage, parse_klist, progname,
};
use krb5_client::creds::{princ_eq, unix_now, unparse};
use krb5_client::errmsg::{Code, Krb5Error};
use krb5_client::{
    KeytabName, keytab_read_error, kt_client_default_name, kt_default_name, kt_resolve, load_ccache,
};
use krb5_config::{CcSpec, parse_ccspec, resolve_ccspec};
use krb5_crypto::EncryptionType;
use krb5_protocol::{CcacheCred, Keytab, KeytabSlot};
use krb5_types::{Ticket, TicketFlags};
use zeroize::Zeroizing;

/// The width of a printed time, probed once.
static TIMESTAMP_WIDTH: OnceLock<usize> = OnceLock::new();

/// MIT `main` (`clients/klist/klist.c:232-236`): the column width is the first `sfstring` of now
/// that fits in 20 bytes, else in `BUFSIZ` (8192), else 15.
fn timestamp_width() -> usize {
    *TIMESTAMP_WIDTH.get_or_init(|| {
        let now = unix_now();
        timestamp_to_sfstring(now, 20, None)
            .or_else(|| timestamp_to_sfstring(now, 8192, None))
            .map_or(15, |s| s.len())
    })
}

fn main() {
    // MIT `main` (`clients/klist/klist.c:124-130`): the locale comes from the environment first.
    krb5_types::timestamp::setlocale();
    let argv: Vec<String> = std::env::args().collect();
    let argv0 = argv.first().map_or("klist", String::as_str);
    let prog = progname(argv0);
    let args = match parse_klist(argv.get(1..).unwrap_or_default()) {
        Ok(a) => a,
        Err(KlistParseError::Krb4) => {
            eprintln!("Kerberos 4 is no longer supported");
            std::process::exit(3);
        }
        Err(KlistParseError::Usage(e)) => {
            for line in e.lines(argv0) {
                eprintln!("{line}");
            }
            eprint!("{}", klist_usage(prog));
            std::process::exit(1);
        }
    };
    std::process::exit(run(prog, &args));
}

/// MIT `main` (`klist.c:229-260`): the library's profile; a name sets the default cache unless
/// `-k`; then the collection list (`-l`), every cache (`-A`), the default cache, or the keytab.
fn run(prog: &str, args: &KlistArgs) -> i32 {
    let now = unix_now();
    if let Err(e) = krb5_client::init_context() {
        eprintln!("{prog}: {e} while initializing krb5");
        return 1;
    }
    if args.keytab {
        return do_keytab(prog, args, args.ccache.as_deref());
    }
    let default = match &args.ccache {
        Some(name) => parse_ccspec(name),
        None => resolve_ccspec(None),
    }
    .map_err(|e| Krb5Error::from_ccname(&e));
    let mut out = String::new();
    let status = if args.list_all {
        list_all_ccaches(prog, &mut out, default.ok(), now)
    } else if args.show_all {
        show_all_ccaches(prog, &mut out, args, default.ok(), now)
    } else {
        do_ccache(prog, &mut out, args, default, now)
    };
    print!("{out}");
    status
}

/// The caches of the default's collection; a default of an unknown type has none.
fn caches(prog: &str, default: Option<CcSpec>, silent: bool) -> Result<Vec<Cache>, i32> {
    let Some(default) = default else {
        return Ok(Vec::new());
    };
    collection(&default).map_err(|e| {
        if !silent {
            eprintln!("{prog}: {e} while listing ccache collection");
        }
        1
    })
}

/// MIT `list_all_ccaches` (`klist.c:360-386`): one line per initialized cache, its principal and
/// full name, ` (Expired)` when it holds no current ticket; exit 0 when any was listed.
fn list_all_ccaches(prog: &str, out: &mut String, default: Option<CcSpec>, now: u32) -> i32 {
    let caches = match caches(prog, default, false) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let _ = writeln!(out, "{:<30} Cache name", "Principal name");
    let _ = writeln!(out, "{:<30} ----------", "--------------");
    let mut status = 1;
    for cache in caches {
        if list_ccache(out, &cache, now) == 0 {
            status = 0;
        }
    }
    status
}

/// MIT `list_ccache` (`klist.c:388-420`): a cache that is not initialized is skipped.
fn list_ccache(out: &mut String, cache: &Cache, now: u32) -> i32 {
    let Ok(cc) = load_ccache(&cache.spec()) else {
        return 1;
    };
    let _ = write!(out, "{:<30.30} {}", unparse(&cc.primary), cache.full_name());
    if check_ccache(&cc, now) != 0 {
        out.push_str(" (Expired)");
    }
    out.push('\n');
    0
}

/// MIT `show_all_ccaches` (`klist.c:422-450`): each cache of the collection as `show_ccache`
/// prints it, a blank line between; with `-s`, only the status; exit 0 when any cache passed.
fn show_all_ccaches(
    prog: &str,
    out: &mut String,
    args: &KlistArgs,
    default: Option<CcSpec>,
    now: u32,
) -> i32 {
    let caches = match caches(prog, default, args.silent) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let mut status = 1;
    for (i, cache) in caches.iter().enumerate() {
        if !args.silent && i > 0 {
            out.push('\n');
        }
        let st = if args.silent {
            check(cache, now)
        } else {
            show_ccache(prog, out, args, cache)
        };
        if st == 0 {
            status = 0;
        }
    }
    status
}

/// MIT `do_ccache` (`klist.c:452-465`): the default cache, shown or (`-s`) checked.
fn do_ccache(
    prog: &str,
    out: &mut String,
    args: &KlistArgs,
    default: Result<CcSpec, Krb5Error>,
    now: u32,
) -> i32 {
    let cache = match default.and_then(|d| resolve(&d)) {
        Ok(c) => c,
        Err(e) => {
            if !args.silent {
                eprintln!("{prog}: {e} while resolving ccache");
            }
            return 1;
        }
    };
    if args.silent {
        check(&cache, now)
    } else {
        show_ccache(prog, out, args, &cache)
    }
}

/// MIT `check_ccache` (`klist.c:532-576`): 0 when the cache holds a current local TGT, or holds
/// no local TGT but a current ticket.
fn check(cache: &Cache, now: u32) -> i32 {
    load_ccache(&cache.spec()).map_or(1, |cc| check_ccache(&cc, now))
}

/// MIT `show_ccache` (`klist.c:468-529`): the cache's name and default principal, the header, then
/// each credential (configuration entries only with `-C`).
fn show_ccache(prog: &str, out: &mut String, args: &KlistArgs, cache: &Cache) -> i32 {
    let cc = match load_ccache(&cache.spec()) {
        Ok(cc) => cc,
        Err(e) => {
            eprintln!(
                "{prog}: {}",
                krb5_client::cache_read_error(&cache.spec(), e.as_ref())
            );
            return 1;
        }
    };
    let defname = unparse(&cc.primary);
    let _ = writeln!(out, "Ticket cache: {}:{}", cache.type_name(), cache.name());
    let _ = writeln!(out, "Default principal: {defname}\n");
    let _ = writeln!(
        out,
        "Valid starting{}Expires{}Service principal",
        " ".repeat(timestamp_width() + 3 - "Valid starting".len() - 1),
        " ".repeat(timestamp_width() + 3 - "Expires".len() - 1),
    );
    for cred in cc.creds.iter().filter(|c| !c.is_removed()) {
        if args.config || !cred.is_config() {
            show_credential(out, args, cred, &defname);
        }
    }
    0
}

/// MIT `show_credential` (`klist.c:678-823`): the times and server, then on one line
/// `for client`, `renew until` and `Flags`, then (after a line break when three of those were
/// printed) the enctypes and authdata types, the addresses, and the ticket's own server when it
/// differs.
fn show_credential(out: &mut String, args: &KlistArgs, cred: &CcacheCred, defname: &str) {
    let name = unparse(&cred.client);
    let is_config = cred.is_config();
    let tkt = (!is_config)
        .then(|| decode::<Ticket>(&cred.ticket).ok())
        .flatten();
    let start = if cred.starttime == 0 {
        cred.authtime
    } else {
        cred.starttime
    };
    let mut extra = 0;
    let mut ccol = 0;
    if is_config {
        out.push_str("config: ");
        ccol = 8;
        for (i, comp) in cred.server.1.name_string.iter().enumerate().skip(1) {
            let comp = String::from_utf8_lossy(comp.as_bytes());
            let piece = if i > 1 {
                format!("({comp})")
            } else {
                comp.into_owned()
            };
            ccol += piece.len();
            out.push_str(&piece);
        }
        out.push_str(" = ");
        ccol += 3;
    } else {
        let _ = writeln!(
            out,
            "{}  {}  {}",
            printtime(start),
            printtime(cred.endtime),
            unparse(&cred.server)
        );
    }
    let sep = |out: &mut String, extra: i32| out.push_str(if extra == 0 { "\t" } else { ", " });
    if name != defname {
        let _ = write!(out, "\tfor client {name}");
        extra += 1;
    }
    if is_config {
        print_config_data(out, ccol, &cred.ticket);
    }
    if cred.renew_till != 0 {
        sep(out, extra);
        let _ = write!(out, "renew until {}", printtime(cred.renew_till));
        extra += 2;
    }
    if args.flags {
        let flags = TicketFlags::from_u32(cred.ticket_flags).mit_letters();
        if !flags.is_empty() {
            sep(out, extra);
            let _ = write!(out, "Flags: {flags}");
            extra += 1;
        }
    }
    if extra > 2 {
        out.push('\n');
        extra = 0;
    }
    if args.etype
        && let Some(t) = &tkt
    {
        sep(out, extra);
        let _ = write!(
            out,
            "Etype (skey, tkt): {}, {} ",
            etype_string(i32::from(cred.key.etype)),
            etype_string(t.enc_part.etype)
        );
        extra += 1;
    }
    if args.adtype && !cred.authdata.is_empty() {
        sep(out, extra);
        let types: Vec<String> = cred.authdata.iter().map(|(t, _)| t.to_string()).collect();
        let _ = write!(out, "AD types: {}", types.join(", "));
        extra += 1;
    }
    if extra != 0 {
        out.push('\n');
    }
    if args.addresses {
        if cred.addresses.is_empty() {
            out.push_str("\tAddresses: (none)\n");
        } else {
            let addrs: Vec<String> = cred
                .addresses
                .iter()
                .map(|(t, a)| one_addr(*t, a))
                .collect();
            let _ = writeln!(out, "\tAddresses: {}", addrs.join(", "));
        }
    }
    if let Some(t) = &tkt {
        let tkt_server = (t.realm.clone(), t.sname.clone());
        if !princ_eq(&cred.server, &tkt_server) {
            let _ = writeln!(out, "\tTicket server: {}", unparse(&tkt_server));
        }
    }
}

/// MIT `print_config_data` (`klist.c:653-676`): printable bytes as they are, others as `\ooo`,
/// from column 8, wrapped after column 72.
fn print_config_data(out: &mut String, mut col: usize, data: &[u8]) {
    for &b in data {
        while col < 8 {
            out.push(' ');
            col += 1;
        }
        if b > 0x20 && b < 0x7f {
            out.push(char::from(b));
            col += 1;
        } else {
            let _ = write!(out, "\\{b:03o}");
            col += 4;
        }
        if col > 72 {
            out.push('\n');
            col = 0;
        }
    }
    if col > 0 {
        out.push('\n');
    }
}

/// MIT `one_addr` (`klist.c:829-887`): an IPv4 or IPv6 address (numerically), a NetBIOS name, or
/// MIT's text for a broken or unknown one.
fn one_addr(addrtype: u16, a: &[u8]) -> String {
    match (addrtype, a.len()) {
        (2, 4) => std::net::Ipv4Addr::new(a[0], a[1], a[2], a[3]).to_string(),
        (24, 16) => <[u8; 16]>::try_from(a).map_or_else(
            |_| format!("broken address (type {addrtype} length 16)"),
            |o| std::net::Ipv6Addr::from(o).to_string(),
        ),
        (20, 16) => a
            .iter()
            .take(15)
            .take_while(|&&c| c != 0 && c != b' ')
            .map(|&c| char::from(c))
            .collect(),
        (2 | 24 | 20, n) => format!("broken address (type {addrtype} length {n})"),
        _ => format!("unknown addrtype {addrtype}"),
    }
}

/// MIT `etype_string` (`klist.c:587-603`): the enctype's name, `DEPRECATED:` before a deprecated
/// one, `etype N` for one this build does not know.
fn etype_string(etype: i32) -> String {
    match EncryptionType::known(etype) {
        Ok(e) if e.is_deprecated() => format!("DEPRECATED:{}", e.to_mit_name()),
        Ok(e) => e.to_mit_name().to_owned(),
        Err(_) => format!("etype {etype}"),
    }
}

/// MIT `printtime` (`klist.c:643-651`): the local time in `timestamp_width` columns, space-filled.
fn printtime(t: u32) -> String {
    timestamp_to_sfstring(t, timestamp_width() + 1, Some(b' ')).unwrap_or_default()
}

/// MIT `do_keytab` (`klist.c:263-358`): the keytab's name, the header (`-t` adds the timestamp
/// column), then one line per entry: the key version, `-t`'s timestamp, the principal, `-e`'s
/// enctype and `-K`'s key.
/// MIT `do_keytab` (`klist.c:338-343`): the key is printed only under `-K`. Here it is formatted
/// only then, from the keytab's own bytes; the file's bytes are wiped right after parsing, and the
/// listing, sized before it is written so that no reallocation leaves a key's hex behind, once
/// it is printed.
fn do_keytab(prog: &str, args: &KlistArgs, name: Option<&str>) -> i32 {
    let (ktname, doing) = match name {
        Some(n) => (n.to_owned(), format!("while resolving keytab {n}")),
        None if args.client_keytab => (
            kt_client_default_name(),
            "while getting default client keytab".to_owned(),
        ),
        None => (kt_default_name(), "while getting default keytab".to_owned()),
    };
    let kt = match kt_resolve(&ktname) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{prog}: {e} {doing}");
            return 1;
        }
    };
    let mut head = format!("Keytab name: {}\n", kt.full_name());
    let keytab = match &kt {
        KeytabName::Memory(_) => Keytab::default(),
        KeytabName::File(path) => {
            let read = krb5_protocol::read_secret_file(path)
                .map_err(|e| keytab_read_error(&e, &path.display().to_string()))
                .and_then(|b| {
                    Keytab::parse(&b).map_err(|e| Krb5Error::new(Code::Other, e.to_string()))
                });
            match read {
                Ok(k) => k,
                Err(e) => {
                    print!("{head}");
                    eprintln!("{prog}: {e} while starting keytab scan");
                    return 1;
                }
            }
        }
    };
    if args.times {
        let _ = writeln!(
            head,
            "KVNO Timestamp{}Principal",
            " ".repeat(timestamp_width() + 2 - "Timestamp".len() - 1)
        );
        let _ = writeln!(
            head,
            "---- {} {}",
            "-".repeat(timestamp_width()),
            "-".repeat(78 - timestamp_width() - "KVNO".len() - 1)
        );
    } else {
        head.push_str("KVNO Principal\n");
        let _ = writeln!(head, "---- {}", "-".repeat(74));
    }
    let mut lines = Vec::new();
    for slot in keytab.slots() {
        let (kvno, princ, timestamp, etype, key) = match slot {
            KeytabSlot::Entry(e) => (
                e.kvno,
                e.name
                    .unparse_with_realm(&String::from_utf8_lossy(e.realm.as_bytes())),
                e.timestamp,
                e.key.etype().to_iana(),
                args.keys.then(|| e.key.as_bytes()),
            ),
            KeytabSlot::Unparsed(raw) => {
                let Some((kvno, princ, ts, etype)) = Keytab::unparsed_meta(raw, keytab.version)
                else {
                    continue;
                };
                let key = if args.keys {
                    Keytab::unparsed_key(raw, keytab.version)
                } else {
                    None
                };
                (kvno, princ, ts, etype, key)
            }
        };
        let mut line = format!("{kvno:4} ");
        if args.times {
            let _ = write!(line, "{} ", printtime(timestamp));
        }
        line.push_str(&princ);
        if args.etype {
            let _ = write!(line, " ({}) ", etype_string(etype));
        }
        lines.push((line, key));
    }
    // ` (0x`, two hex digits a key octet, `)`.
    let hex_len = |key: Option<&[u8]>| {
        if args.keys {
            5 + 2 * key.map_or(0, <[u8]>::len)
        } else {
            0
        }
    };
    let size = head.len()
        + lines
            .iter()
            .map(|(line, key)| line.len() + hex_len(*key) + 1)
            .sum::<usize>();
    let mut out = Zeroizing::new(String::with_capacity(size));
    out.push_str(&head);
    for (line, key) in &lines {
        out.push_str(line);
        if args.keys {
            out.push_str(" (0x");
            for b in key.unwrap_or_default() {
                let _ = write!(out, "{b:02x}");
            }
            out.push(')');
        }
        out.push('\n');
    }
    print!("{}", out.as_str());
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_protocol::FileCcache;
    use krb5_types::PrincipalName;

    fn sample_cred(renew_till: u32, flags: u32) -> CcacheCred {
        let realm = krb5_protocol::realm("KERBER.TEST");
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
        let key =
            krb5_crypto::ProtocolKey::from_bytes(EncryptionType::Aes128CtsHmacSha196, &[0u8; 16])
                .unwrap();
        CcacheCred {
            client: (realm.clone(), user),
            server: (realm, PrincipalName::krbtgt("KERBER.TEST")),
            key: krb5_protocol::CcacheKeyblock::from_protocol(&key),
            authtime: 1_700_000_000,
            starttime: 1_700_000_000,
            endtime: 1_700_360_000,
            renew_till,
            is_skey: 0,
            ticket_flags: flags,
            addresses: Vec::new(),
            authdata: Vec::new(),
            ticket: Vec::new(),
            second_ticket: Vec::new(),
        }
    }

    fn args(flags: bool) -> KlistArgs {
        KlistArgs {
            flags,
            ..KlistArgs::default()
        }
    }

    /// Live MIT 1.22.2 `klist -f`: `renew until …, Flags: FRIA` on
    /// one line.
    #[test]
    fn renew_until_and_flags_share_a_line_as_mit() {
        let cred = sample_cred(1_700_720_000, 0x40e0_0000);
        let mut out = String::new();
        show_credential(&mut out, &args(true), &cred, "user@KERBER.TEST");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "{out}");
        assert!(lines[1].starts_with("\trenew until "), "{out}");
        assert!(lines[1].ends_with(", Flags: FRIA"), "{out}");
        let mut none = String::new();
        show_credential(
            &mut none,
            &args(false),
            &sample_cred(0, 0),
            "user@KERBER.TEST",
        );
        assert_eq!(none.lines().count(), 1, "{none}");
    }

    #[test]
    fn ticket_server_only_when_sname_differs() {
        use krb5_asn1::encode;
        use krb5_types::{EncryptedData, OctetString, ascii};
        let mut cred = sample_cred(0, 0);
        let tkt = Ticket {
            tkt_vno: Ticket::VNO,
            realm: ascii("KERBER.TEST"),
            sname: PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "testhost.kerber.test"]),
            enc_part: EncryptedData {
                etype: 18,
                kvno: Some(1),
                cipher: OctetString::from(vec![0u8; 16]),
            },
        };
        cred.ticket = encode(&tkt).unwrap();
        let mut out = String::new();
        show_credential(&mut out, &args(false), &cred, "user@KERBER.TEST");
        assert!(
            out.contains("Ticket server: host/testhost.kerber.test@KERBER.TEST"),
            "{out}"
        );
        cred.server = (
            krb5_protocol::realm("KERBER.TEST"),
            PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "testhost.kerber.test"]),
        );
        let mut same = String::new();
        show_credential(&mut same, &args(false), &cred, "user@KERBER.TEST");
        assert!(!same.contains("Ticket server:"), "{same}");
    }

    /// Live MIT 1.22.2 `klist -C`: `config: fast_avail(krbtgt/…) = yes`.
    #[test]
    fn config_entries_print_as_mit() {
        let mut cc = FileCcache::new(sample_cred(0, 0).client, Vec::new());
        cc.set_config(Some("krbtgt/KERBER.TEST@KERBER.TEST"), "fast_avail", b"yes");
        let mut out = String::new();
        let all = KlistArgs {
            config: true,
            ..KlistArgs::default()
        };
        show_credential(&mut out, &all, &cc.creds[0], "user@KERBER.TEST");
        assert_eq!(
            out,
            "config: fast_avail(krbtgt/KERBER.TEST@KERBER.TEST) = yes\n"
        );
    }

    #[test]
    fn printtime_is_timestamp_width() {
        assert_eq!(printtime(1_700_000_000).len(), timestamp_width());
        assert_eq!(etype_string(18), "aes256-cts-hmac-sha1-96");
        assert_eq!(etype_string(99), "etype 99");
        assert_eq!(one_addr(2, &[192, 0, 2, 1]), "192.0.2.1");
        assert_eq!(one_addr(99, &[]), "unknown addrtype 99");
    }

    /// Live MIT 1.22.2 `klist -k` / `-kte` / `-kK`: the layout.
    #[test]
    fn keytab_listing_lays_out_as_mit() {
        let key =
            krb5_crypto::ProtocolKey::from_bytes(EncryptionType::Aes128CtsHmacSha196, &[0xa1; 16])
                .unwrap();
        let kt = Keytab::single(
            krb5_protocol::realm("KERBER.TEST"),
            PrincipalName::new(PrincipalName::NT_SRV_HST, ["nfs", "services.kerber.test"]),
            2,
            key,
        );
        let path = krb5_testkit::scratch_dir("klist-k").join("kt");
        kt.write_file(&path).unwrap();
        let name = path.display().to_string();
        let a = KlistArgs {
            keytab: true,
            etype: true,
            keys: true,
            ..KlistArgs::default()
        };
        assert_eq!(do_keytab("klist", &a, Some(&name)), 0);
        assert_eq!(do_keytab("klist", &a, Some("BOGUS:/x")), 1);
        assert_eq!(do_keytab("klist", &a, Some("/no/such/keytab")), 1);
        let _ = std::fs::remove_file(&path);
    }
}
