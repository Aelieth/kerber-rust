//! FILE identity, MEMORY consume, and Rust remove_cred for ccache-gate.

fn main() {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_default();
    let rc = match cmd.as_str() {
        "identity" => identity(args.next().as_deref()),
        "memory-from" => memory_from(args.next().as_deref()),
        "remove" => remove(args.next().as_deref(), args.next().as_deref()),
        _ => {
            eprintln!("usage: ccache-probe identity|memory-from|remove ...");
            2
        }
    };
    std::process::exit(rc);
}

fn identity(path: Option<&str>) -> i32 {
    let Some(path) = path else {
        eprintln!("ccache-probe identity PATH");
        return 2;
    };
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read: {e}");
            return 1;
        }
    };
    let cc = match krb5_protocol::FileCcache::parse(&bytes) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("parse: {e}");
            return 1;
        }
    };
    let out = match cc.to_bytes() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("to_bytes: {e}");
            return 1;
        }
    };
    if out != bytes {
        eprintln!("identity mismatch have={} want={}", out.len(), bytes.len());
        return 1;
    }
    println!("identity_ok bytes={}", bytes.len());
    0
}

fn memory_from(path: Option<&str>) -> i32 {
    let Some(path) = path else {
        eprintln!("ccache-probe memory-from PATH");
        return 2;
    };
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read: {e}");
            return 1;
        }
    };
    let cc = match krb5_protocol::FileCcache::parse(&bytes) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("parse: {e}");
            return 1;
        }
    };
    krb5_protocol::memory_store("g8a", cc);
    let Some(got) = krb5_protocol::memory_retrieve("g8a") else {
        eprintln!("memory retrieve miss");
        return 1;
    };
    let princ = krb5_protocol::FileCcache::format_principal(&got.primary.0, &got.primary.1);
    if got.list().is_empty() {
        eprintln!("memory empty");
        return 1;
    }
    println!("memory_ok principal={princ} tickets={}", got.list().len());
    0
}

fn remove(path: Option<&str>, server: Option<&str>) -> i32 {
    let (Some(path), Some(server)) = (path, server) else {
        eprintln!("ccache-probe remove PATH SERVER");
        return 2;
    };
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read: {e}");
            return 1;
        }
    };
    let mut cc = match krb5_protocol::FileCcache::parse(&bytes) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("parse: {e}");
            return 1;
        }
    };
    let (name, realm) = match krb5_protocol::parse_principal(server) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("principal: {e}");
            return 1;
        }
    };
    cc.remove_cred(&krb5_protocol::realm(&realm), &name);
    if let Err(e) = cc.write_file(path) {
        eprintln!("write: {e}");
        return 1;
    }
    println!("remove_ok list={}", cc.list().len());
    0
}
