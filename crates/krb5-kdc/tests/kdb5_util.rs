//! `kdb5_util` (the `krb5-kdb` binary, run under MIT's name): MIT's command line, the realm
//! `create` makes, `stash`, `dump`, `load` and `destroy`, with the texts and exit statuses
//! settled live against MIT 1.22.2.
//! MIT `kdb5_create` (`kdb5_create.c:142-336`): `create` writes `K/M` and `krbtgt`, then `kadm5_create` the two `kadmin/` services.
//! MIT `add_admin_princs` (`kadm5_create.c:139-154`): the `kadmin/admin` and `kadmin/changepw` attributes and lifetimes.

#![cfg(unix)]

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use krb5_crypto::EncryptionType;
use krb5_kdc::{
    KDB_DISALLOW_ALL_TIX, KDB_DISALLOW_TGT_BASED, KDB_LOCKDOWN_KEYS, KDB_PWCHANGE_SERVICE,
    KDB_REQUIRES_PRE_AUTH, PrincipalStore, create_realm, kdc_conf_for_realm, load_store,
    master_key_from_password, parse_dump, tl_mod_princ_name,
};
use krb5_testkit::scratch_dir;

const USAGE_HEAD: &str = "Usage: kdb5_util [-r realm] [-d dbname] [-k mkeytype] [-kv mkeyVNO]\n";

/// A scratch realm: its krb5.conf, kdc.conf, database and stash, and `kdb5_util` (a link to
/// the binary, so messages carry MIT's program name).
struct Realm {
    dir: PathBuf,
    db: PathBuf,
    stash: PathBuf,
    krb5_conf: PathBuf,
    kdc_conf: PathBuf,
    tool: PathBuf,
}

impl Realm {
    fn new(name: &str, stanza: &str) -> Self {
        let dir = scratch_dir(name);
        let db = dir.join("principal");
        let stash = dir.join(".k5.KL.TEST");
        let krb5_conf = dir.join("krb5.conf");
        let kdc_conf = dir.join("kdc.conf");
        std::fs::write(&krb5_conf, "[libdefaults]\n    default_realm = KL.TEST\n").unwrap();
        std::fs::write(
            &kdc_conf,
            format!(
                "[realms]\n    KL.TEST = {{\n        database_name = {}\n        key_stash_file = {}\n{stanza}    }}\n",
                db.display(),
                stash.display()
            ),
        )
        .unwrap();
        let tool = dir.join("kdb5_util");
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_krb5-kdb"), &tool).unwrap();
        Self {
            dir,
            db,
            stash,
            krb5_conf,
            kdc_conf,
            tool,
        }
    }

    fn sha1() -> &'static str {
        "        master_key_type = aes256-cts-hmac-sha1-96\n        supported_enctypes = aes256-cts-hmac-sha1-96:normal\n"
    }

    fn run(&self, args: &[&str], stdin: &str) -> Output {
        let mut cmd = Command::new(&self.tool);
        cmd.args(args)
            .current_dir(&self.dir)
            .env("KRB5_CONFIG", &self.krb5_conf)
            .env("KRB5_KDC_PROFILE", &self.kdc_conf)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for v in [
            "KRB5_KDC_DB",
            "KRB5_KDC_STASH",
            "KRB5_MASTER_ETYPE",
            "KRB5_MASTER_PASSWORD",
            "KRB5_TEST_USER_PASSWORD",
            "KRB5_TEST_ADMIN_PASSWORD",
            "KRB5_ACL_FILE",
            "KRB5_KDC_CONF",
        ] {
            cmd.env_remove(v);
        }
        let mut child = cmd.spawn().unwrap();
        {
            use std::io::Write as _;
            let mut input = child.stdin.take().unwrap();
            let _ = input.write_all(stdin.as_bytes());
        }
        child.wait_with_output().unwrap()
    }

    fn create(&self) {
        let out = self.run(&["-P", "kl-master", "create", "-s"], "");
        assert!(out.status.success(), "{}", text(&out.stderr));
    }

    fn store(&self) -> PrincipalStore {
        load_store(&self.db, &self.stash).unwrap()
    }
}

impl Drop for Realm {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn status(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
}

fn ino(p: &Path) -> u64 {
    std::fs::metadata(p).unwrap().ino()
}

#[test]
fn create_from_a_pipe_makes_the_four_principals_mit_makes() {
    // KLLDAP's call: the master password twice on stdin, one line each.
    let realm = Realm::new("kdb5-create-pipe", Realm::sha1());
    let out = realm.run(&["create", "-s"], "kl-master\nkl-master\n");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    let db = realm.db.display();
    assert_eq!(
        text(&out.stdout),
        format!(
            "Initializing database '{db}' for realm 'KL.TEST',\nmaster key name 'K/M@KL.TEST'\n\
             You will be prompted for the database Master Password.\n\
             It is important that you NOT FORGET this password.\n\
             Enter KDC database master key: \nRe-enter KDC database master key to verify: \n"
        )
    );
    assert_eq!(text(&out.stderr), "");
    assert_eq!(mode(&realm.db), 0o600);
    assert_eq!(mode(&realm.stash), 0o600);
    let store = realm.store();
    assert_eq!(
        store.ids(),
        [
            "K/M@KL.TEST",
            "kadmin/admin@KL.TEST",
            "kadmin/changepw@KL.TEST",
            "krbtgt/KL.TEST@KL.TEST"
        ]
    );
    let km = store.get("K/M@KL.TEST").unwrap();
    assert_eq!(km.attributes, KDB_DISALLOW_ALL_TIX | KDB_LOCKDOWN_KEYS);
    assert_eq!(km.keys.len(), 1);
    assert_eq!(km.keys[0].kvno, 1);
    let master =
        master_key_from_password("KL.TEST", b"kl-master", EncryptionType::Aes256CtsHmacSha196)
            .unwrap();
    assert_eq!(km.keys[0].key.as_bytes(), master.as_bytes());
    let tgt = store.get("krbtgt/KL.TEST@KL.TEST").unwrap();
    assert_eq!(tgt.attributes, KDB_LOCKDOWN_KEYS);
    assert_eq!(
        tgt.keys.iter().map(|k| k.etype).collect::<Vec<_>>(),
        [EncryptionType::Aes256CtsHmacSha196]
    );
    let admin = store.get("kadmin/admin@KL.TEST").unwrap();
    assert_eq!(admin.attributes, KDB_DISALLOW_TGT_BASED | KDB_LOCKDOWN_KEYS);
    assert_eq!(admin.max_life, 3 * 3600);
    let changepw = store.get("kadmin/changepw@KL.TEST").unwrap();
    assert_eq!(
        changepw.attributes,
        KDB_DISALLOW_TGT_BASED | KDB_PWCHANGE_SERVICE | KDB_LOCKDOWN_KEYS
    );
    assert_eq!(changepw.max_life, 300);
    for p in [km, tgt] {
        assert_eq!(p.max_life, 86400);
        assert_eq!(p.max_renewable_life, 0);
        assert_eq!(
            tl_mod_princ_name(&p.tl_data).as_deref(),
            Some("db_creation@KL.TEST")
        );
        assert!(
            !p.tl_data
                .iter()
                .any(|t| t.ty == krb5_kdc::TL_LAST_PWD_CHANGE)
        );
    }
    for p in [admin, changepw] {
        assert_eq!(
            tl_mod_princ_name(&p.tl_data).as_deref(),
            Some("kdb5_util@KL.TEST")
        );
    }
}

#[test]
fn an_unset_master_key_type_is_mits_aes256_sha1() {
    let realm = Realm::new("kdb5-create-default-etype", "");
    realm.create();
    let store = realm.store();
    let km = store.get("K/M@KL.TEST").unwrap();
    assert_eq!(km.keys[0].etype, EncryptionType::Aes256CtsHmacSha196);
    let kt = krb5_protocol::Keytab::parse(&std::fs::read(&realm.stash).unwrap()).unwrap();
    assert_eq!(kt.entries.len(), 1);
    assert_eq!(kt.entries[0].kvno, 1);
    assert_eq!(
        kt.entries[0].key.etype(),
        EncryptionType::Aes256CtsHmacSha196
    );
}

#[test]
fn an_unset_supported_enctypes_keys_mits_default_pair() {
    // MIT (settled live): krbtgt and the kadmin services get aes256 then aes128 sha1 only.
    let realm = Realm::new("kdb5-create-default-keysalts", "");
    realm.create();
    let store = realm.store();
    for id in [
        "krbtgt/KL.TEST@KL.TEST",
        "kadmin/admin@KL.TEST",
        "kadmin/changepw@KL.TEST",
    ] {
        let etypes: Vec<EncryptionType> = store
            .get(id)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.etype)
            .collect();
        assert_eq!(
            etypes,
            [
                EncryptionType::Aes256CtsHmacSha196,
                EncryptionType::Aes128CtsHmacSha196
            ],
            "{id}"
        );
    }
}

#[test]
fn create_takes_the_stanzas_flags_lifetimes_and_keysalts() {
    let realm = Realm::new(
        "kdb5-create-stanza",
        "        max_life = 10h 0m 0s\n        max_renewable_life = 7d 0h 0m 0s\n        default_principal_flags = +preauth,-forwardable\n        supported_enctypes = aes128-cts-hmac-sha1-96:normal aes256-cts-hmac-sha1-96:normal\n",
    );
    realm.create();
    let store = realm.store();
    let km = store.get("K/M@KL.TEST").unwrap();
    // MIT getprinc K/M: DISALLOW_FORWARDABLE DISALLOW_ALL_TIX REQUIRES_PRE_AUTH LOCKDOWN_KEYS.
    assert_eq!(km.attributes, 0x0080_00c2);
    assert_eq!((km.max_life, km.max_renewable_life), (36000, 604_800));
    let tgt = store.get("krbtgt/KL.TEST@KL.TEST").unwrap();
    assert_eq!(tgt.attributes, 0x0080_0082);
    assert_eq!(
        tgt.keys.iter().map(|k| k.etype).collect::<Vec<_>>(),
        [
            EncryptionType::Aes128CtsHmacSha196,
            EncryptionType::Aes256CtsHmacSha196
        ]
    );
    // The kadmin services take only their own attributes, but the realm's renewable life.
    let admin = store.get("kadmin/admin@KL.TEST").unwrap();
    assert_eq!(admin.attributes, KDB_DISALLOW_TGT_BASED | KDB_LOCKDOWN_KEYS);
    assert_eq!(admin.attributes & KDB_REQUIRES_PRE_AUTH, 0);
    assert_eq!((admin.max_life, admin.max_renewable_life), (10800, 604_800));
}

#[test]
fn another_realms_stanza_is_not_read_for_this_one() {
    let text = "[realms]\n    OTHER.TEST = {\n        max_life = 1h\n    }\n    KL.TEST = {\n        max_renewable_life = 2d\n    }\n";
    let kl = kdc_conf_for_realm(text, "KL.TEST").unwrap();
    assert_eq!((kl.max_life, kl.max_renewable_life), (86400, 2 * 86400));
    let none = kdc_conf_for_realm(text, "NONE.TEST").unwrap();
    assert_eq!((none.max_life, none.max_renewable_life), (86400, 0));
    let master =
        master_key_from_password("KL.TEST", b"pw", EncryptionType::Aes256CtsHmacSha196).unwrap();
    let store = create_realm("KL.TEST", Some(&kl), &master, 1).unwrap();
    assert!(store.ulog().is_none());
    assert_eq!(store.serial(), 0);
    assert!(store.get("kadmin/history@KL.TEST").is_none());
}

#[test]
fn create_without_s_leaves_no_stash() {
    let realm = Realm::new("kdb5-create-nostash", Realm::sha1());
    std::fs::write(&realm.stash, b"stale").unwrap();
    let out = realm.run(&["-P", "kl-master", "create"], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    assert!(
        !text(&out.stdout).contains("prompted"),
        "-P does not prompt"
    );
    assert!(realm.db.exists());
    assert!(!realm.stash.exists());
}

#[test]
fn create_over_an_existing_database_is_refused_after_the_prompts() {
    let realm = Realm::new("kdb5-create-exists", Realm::sha1());
    realm.create();
    let before = std::fs::read(&realm.db).unwrap();
    let out = realm.run(&["create", "-s"], "pw\npw\n");
    assert_eq!(status(&out), 1);
    assert!(text(&out.stdout).ends_with("Re-enter KDC database master key to verify: \n"));
    let db = realm.db.display();
    assert_eq!(
        text(&out.stderr),
        format!(
            "kdb5_util: Cannot open DB2 database '{db}': File exists while creating database '{db}'\n"
        )
    );
    assert_eq!(std::fs::read(&realm.db).unwrap(), before);
}

#[test]
fn create_password_errors_are_mits() {
    let realm = Realm::new("kdb5-create-pwerr", Realm::sha1());
    let out = realm.run(&["create", "-s"], "pw\nother\n");
    assert_eq!(status(&out), 1);
    assert_eq!(
        text(&out.stderr),
        "kdb5_util: Password mismatch while reading master key from keyboard\n"
    );
    let out = realm.run(&["create", "-s"], "pw\n");
    assert_eq!(status(&out), 1);
    assert_eq!(
        text(&out.stderr),
        "kdb5_util: Cannot read password while reading master key from keyboard\n"
    );
    assert!(!realm.db.exists() && !realm.stash.exists());
}

#[test]
fn usage_and_option_errors_are_mits() {
    let realm = Realm::new("kdb5-usage", Realm::sha1());
    realm.create();
    for args in [
        &[][..],
        &["bogus"],
        &["-r"],
        &["create", "-P"],
        &["list_mkeys"],
        &["dump", "-b7", "x"],
    ] {
        let out = realm.run(args, "");
        assert_eq!(status(&out), 1, "{args:?}");
        assert!(text(&out.stderr).starts_with(USAGE_HEAD), "{args:?}");
        assert!(
            text(&out.stderr)
                .ends_with("\t\t\tLook at each database documentation for supported arguments\n")
        );
    }
    let out = realm.run(&["create", "-Z"], "");
    assert_eq!(status(&out), 1);
    assert!(text(&out.stderr).starts_with(&format!("create: invalid option -- 'Z'\n{USAGE_HEAD}")));
    for (args, msg) in [
        (
            &["-k", "no-such-enctype", "create", "-s"][..],
            "kdb5_util: Invalid argument : no-such-enctype is an invalid enctype\n",
        ),
        // MIT `krb5_string_to_enctype` takes names only, as given: no number, no blanks.
        (
            &["-k", "18", "dump", "-"],
            "kdb5_util: Invalid argument : 18 is an invalid enctype\n",
        ),
        (
            &["-k", " aes256-cts", "dump", "-"],
            "kdb5_util: Invalid argument :  aes256-cts is an invalid enctype\n",
        ),
        (
            &["-k", "aes256-cts-hmac-sha1-96", "-k", "17", "dump", "-"],
            "kdb5_util: Invalid argument : 17 is an invalid enctype\n",
        ),
        (
            &["-kv", "0", "create"],
            "kdb5_util: Invalid argument : 0 is an invalid mkeyVNO\n",
        ),
        (
            &["-kv", "x", "create"],
            "kdb5_util: Invalid argument : x is an invalid mkeyVNO\n",
        ),
    ] {
        let out = realm.run(args, "");
        assert_eq!(status(&out), 1);
        assert_eq!(text(&out.stderr), msg);
    }
    let out = realm.run(&["-x", "foo", "-P", "pw", "create", "-s"], "");
    assert_eq!(status(&out), 1);
    assert_eq!(
        text(&out.stderr),
        format!(
            "kdb5_util: Unsupported argument \"foo\" for db2 while creating database '{}'\n",
            realm.db.display()
        )
    );
}

#[test]
fn no_realm_is_mits_error() {
    let realm = Realm::new("kdb5-norealm", Realm::sha1());
    std::fs::write(&realm.krb5_conf, "[libdefaults]\n").unwrap();
    for args in [
        &["-P", "pw", "create", "-s"][..],
        &["dump", "x"],
        &["load", "x"],
    ] {
        let out = realm.run(args, "");
        assert_eq!(status(&out), 1);
        assert_eq!(
            text(&out.stderr),
            "kdb5_util: Configuration file does not specify default realm while getting default realm\n"
        );
    }
}

/// The stash's `K/M` entry: kvno and key bytes (its timestamp is the write's).
fn stash_entry(p: &Path) -> (u32, Vec<u8>) {
    let kt = krb5_protocol::Keytab::parse(&std::fs::read(p).unwrap()).unwrap();
    assert_eq!(kt.entries.len(), 1);
    (kt.entries[0].kvno, kt.entries[0].key.as_bytes().to_vec())
}

#[test]
fn stash_leaves_a_new_0600_file() {
    let realm = Realm::new("kdb5-stash", Realm::sha1());
    realm.create();
    std::fs::set_permissions(&realm.stash, std::fs::Permissions::from_mode(0o640)).unwrap();
    let before = stash_entry(&realm.stash);
    let old = ino(&realm.stash);
    let out = realm.run(&["stash"], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        "Using existing stashed keys to update stash file.\n"
    );
    assert_eq!(mode(&realm.stash), 0o600);
    assert_ne!(ino(&realm.stash), old);
    assert_eq!(stash_entry(&realm.stash), before);
    // No stash: the master key is typed once, then the stash is written.
    std::fs::remove_file(&realm.stash).unwrap();
    let out = realm.run(&["stash"], "kl-master\n");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "Enter KDC database master key: \n");
    assert_eq!(
        text(&out.stderr),
        "kdb5_util: Can not fetch master key (error: No such file or directory). while reading master key\n\
         kdb5_util: Warning: proceeding without master key\n"
    );
    assert_eq!(stash_entry(&realm.stash), before);
    std::fs::remove_file(&realm.stash).unwrap();
    let out = realm.run(&["stash"], "wrong\n");
    assert_eq!(status(&out), 2);
    assert!(text(&out.stderr).ends_with(
        "kdb5_util: Unable to decrypt latest master key with the provided master key\n while getting master key list\n"
    ));
    assert!(!realm.stash.exists());
}

#[test]
fn dump_then_load_round_trips_and_load_leaves_a_new_file() {
    let realm = Realm::new("kdb5-dump-load", Realm::sha1());
    realm.create();
    let out = realm.run(&["dump", "full.dump"], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    assert_eq!(
        (text(&out.stdout), text(&out.stderr)),
        (String::new(), String::new())
    );
    let dumped = realm.dir.join("full.dump");
    assert_eq!(mode(&dumped), 0o600);
    assert_eq!(
        std::fs::read(realm.dir.join("full.dump.dump_ok")).unwrap(),
        [0]
    );
    let dump_text = std::fs::read_to_string(&dumped).unwrap();
    assert!(dump_text.starts_with("kdb5_util load_dump version 7\nprinc\t38\t11\t"));
    let names: Vec<String> = parse_dump(&dump_text)
        .unwrap()
        .princs
        .into_iter()
        .map(|p| p.name)
        .collect();
    assert_eq!(
        names,
        [
            "K/M@KL.TEST",
            "kadmin/admin@KL.TEST",
            "kadmin/changepw@KL.TEST",
            "krbtgt/KL.TEST@KL.TEST"
        ]
    );
    let ids = realm.store().ids();
    std::fs::set_permissions(&realm.db, std::fs::Permissions::from_mode(0o640)).unwrap();
    let old = ino(&realm.db);
    let out = realm.run(&["load", "full.dump"], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    assert_eq!(
        (text(&out.stdout), text(&out.stderr)),
        (String::new(), String::new())
    );
    assert_eq!(mode(&realm.db), 0o600);
    assert_ne!(ino(&realm.db), old);
    assert_eq!(realm.store().ids(), ids);
    let out = realm.run(&["load", "-verbose", "full.dump"], "");
    assert_eq!(status(&out), 0);
    assert_eq!(text(&out.stderr), format!("{}\n", names.join("\n")));
}

#[test]
fn dump_options_and_patterns() {
    let realm = Realm::new("kdb5-dump-opts", Realm::sha1());
    realm.create();
    let out = realm.run(&["dump", "-verbose", "-rev", "-", "kadmin/.*"], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3, "{stdout}");
    assert!(lines[1].contains("\tkadmin/changepw@KL.TEST\t"));
    assert!(lines[2].contains("\tkadmin/admin@KL.TEST\t"));
    assert_eq!(
        text(&out.stderr),
        "kadmin/changepw@KL.TEST\nkadmin/admin@KL.TEST\n"
    );
    let out = realm.run(&["dump", "-r18", "-"], "");
    assert!(text(&out.stdout).starts_with("kdb5_util load_dump version 6\n"));
    let out = realm.run(&["dump", "-ov", "x"], "");
    assert_eq!(status(&out), 1);
    assert_eq!(text(&out.stderr), "OV dump format not supported\n");
    let out = realm.run(&["dump", "-c", "x"], "");
    assert_eq!(status(&out), 1);
    assert_eq!(
        text(&out.stderr),
        "kdb5_util: Conditional dump is an undocumented option for use only for iprop dumps\n"
    );
}

#[test]
fn a_wrong_master_password_warns_and_dump_still_writes() {
    let realm = Realm::new("kdb5-dump-wrongpw", Realm::sha1());
    realm.create();
    let out = realm.run(&["-P", "wrong", "dump", "d2"], "");
    assert_eq!(status(&out), 1);
    assert_eq!(
        text(&out.stderr),
        "kdb5_util: Unable to decrypt latest master key with the provided master key\n while getting master key list\n\
         kdb5_util: Warning: proceeding without master key list\n"
    );
    assert!(realm.dir.join("d2").exists());
    // MIT `main` (`kdb5_util.c:230-232`): a later -P replaces an earlier one.
    let out = realm.run(&["-P", "wrong", "-P", "kl-master", "dump", "d3"], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    assert_eq!(text(&out.stderr), "");
    // MIT's load reads no master key; this one opens the dump with -P's key before the stash's.
    let out = realm.run(&["-P", "wrong", "load", "d2"], "");
    assert_eq!(status(&out), 1);
    assert_eq!(
        text(&out.stderr),
        "kdb5_util: Unable to decrypt latest master key with the provided master key\n while getting master key list\n"
    );
}

#[test]
fn load_takes_p_before_the_stash() {
    let realm = Realm::new("kdb5-load-p-first", Realm::sha1());
    realm.create();
    let other = Realm::new("kdb5-load-p-other", Realm::sha1());
    let out = other.run(&["-P", "other-master", "create", "-s"], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    let out = other.run(&["dump", "other.dump"], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    let dumped = other.dir.join("other.dump");
    // The stash does not open the other realm's dump; its own master password does.
    let out = realm.run(&["load", dumped.to_str().unwrap()], "");
    assert_eq!(status(&out), 1);
    let out = realm.run(
        &["-P", "other-master", "load", dumped.to_str().unwrap()],
        "",
    );
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    let out = realm.run(&["-m", "load", dumped.to_str().unwrap()], "other-master\n");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "Enter KDC database master key: \n");
}

#[test]
fn a_dump_with_no_principal_loads_a_database_with_none() {
    let realm = Realm::new("kdb5-load-empty", Realm::sha1());
    std::fs::write(realm.dir.join("h7"), "kdb5_util load_dump version 7\n").unwrap();
    std::fs::write(realm.dir.join("h6"), "kdb5_util load_dump version 6\n").unwrap();
    let policy = "policy\tp1\t0\t0\t8\t1\t1\t0\t0\t0\t0\t0\t0\t0\t-\t0";
    std::fs::write(
        realm.dir.join("p1"),
        format!("kdb5_util load_dump version 7\n{policy}\n"),
    )
    .unwrap();
    // No stash and no -P: there is no key to open, as MIT reads none.
    let out = realm.run(&["load", "h7"], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    assert_eq!(
        std::fs::read_to_string(&realm.db).unwrap(),
        "kdb5_util load_dump version 7\n"
    );
    assert_eq!(mode(&realm.db), 0o600);
    for args in [&["dump", "-"][..], &["destroy", "-f"]] {
        let out = realm.run(args, "");
        assert_eq!(status(&out), 1, "{args:?}");
        assert_eq!(
            text(&out.stderr),
            "kdb5_util: No such entry in the database while retrieving master entry\n"
        );
    }
    let out = realm.run(&["load", "-r18", "h6"], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    let out = realm.run(&["load", "-verbose", "p1"], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    assert_eq!(text(&out.stderr), "created policy p1\n");
    assert_eq!(
        std::fs::read_to_string(&realm.db).unwrap(),
        format!("kdb5_util load_dump version 7\n{policy}\n")
    );
    // -update with no principal: the live database keeps its records and gains the policies.
    let live = Realm::new("kdb5-load-empty-update", Realm::sha1());
    live.create();
    let before = std::fs::read_to_string(&live.db).unwrap();
    let out = live.run(
        &["load", "-update", realm.dir.join("h7").to_str().unwrap()],
        "",
    );
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    assert_eq!(std::fs::read_to_string(&live.db).unwrap(), before);
    let out = live.run(
        &["load", "-update", realm.dir.join("p1").to_str().unwrap()],
        "",
    );
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    assert_eq!(
        std::fs::read_to_string(&live.db).unwrap(),
        format!("{before}{policy}\n")
    );
    assert_eq!(live.store().ids().len(), 4);
}

/// MIT `ctx_create_db` (`kdb_db2.c:710-716`): `-x temporary` destroys a leftover temporary
/// database before creating it, where a plain create refuses an existing one; settled live
/// (`mit-temporary.txt`).
#[test]
fn temporary_create_destroys_a_leftover_first() {
    let realm = Realm::new("kdb5-temporary-leftover", Realm::sha1());
    let temp = realm.dir.join("principal~");
    let temp_policy = realm.dir.join("principal~.kadm5");
    std::fs::write(&temp, "junk").unwrap();
    std::fs::write(&temp_policy, "junk").unwrap();
    let out = realm.run(&["-x", "temporary", "-P", "kl-master", "create", "-s"], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    assert!(
        std::fs::read_to_string(&temp)
            .unwrap()
            .starts_with("kdb5_util load_dump version 7\n")
    );
    assert!(!temp_policy.exists());
    assert!(!realm.db.exists(), "a temporary database is not made live");
    std::fs::write(&realm.db, "junk").unwrap();
    let out = realm.run(&["-P", "kl-master", "create", "-s"], "");
    assert_eq!(status(&out), 1);
}

#[test]
fn db_arguments_are_db2s() {
    let realm = Realm::new("kdb5-db-args", Realm::sha1());
    realm.create();
    let db = realm.db.display().to_string();
    for (args, context) in [
        (
            &["-x", "foo=bar", "dump", "-"][..],
            "while initializing database",
        ),
        (
            &["-x", "hash", "stash", "-f", "s2"],
            "while initializing database",
        ),
        (
            &["-x", "foo=bar", "load", "x.dump"],
            "while creating database",
        ),
        (
            &["-x", "temporary=1", "destroy", "-f"],
            "while initializing database",
        ),
    ] {
        std::fs::write(realm.dir.join("x.dump"), "kdb5_util load_dump version 7\n").unwrap();
        let out = realm.run(args, "");
        assert_eq!(status(&out), 1, "{args:?}");
        let name = args[1].split('=').next().unwrap();
        assert_eq!(
            text(&out.stderr),
            format!("kdb5_util: Unsupported argument \"{name}\" for db2 {context}\n"),
            "{args:?}"
        );
    }
    let plain = realm.run(&["dump", "-"], "");
    let out = realm.run(
        &[
            "-x",
            "hash=1",
            "-x",
            "lockiter",
            "-x",
            "unlockiter",
            "-x",
            "merge_nra",
            "dump",
            "-",
        ],
        "",
    );
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    assert_eq!(out.stdout, plain.stdout);
    let out = realm.run(&["-x", "temporary", "dump", "-"], "");
    assert_eq!(status(&out), 1);
    assert_eq!(
        text(&out.stderr),
        format!(
            "kdb5_util: Cannot open DB2 database '{db}~': No such file or directory while initializing database\n"
        )
    );
    // dbname= names the file; the messages keep kdc.conf's (or -d's) name, as MIT's do.
    let alt = realm.dir.join("alt");
    let alt_stash = realm.dir.join("alt.stash");
    let x_alt = format!("dbname={}", alt.display());
    let out = realm.run(
        &[
            "-x",
            &x_alt,
            "-sf",
            alt_stash.to_str().unwrap(),
            "-P",
            "alt-master",
            "create",
            "-s",
        ],
        "",
    );
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    assert!(text(&out.stdout).starts_with(&format!("Initializing database '{db}' for realm")));
    assert!(alt.exists() && alt_stash.exists());
    let alt_dump = realm.run(
        &[
            "-x",
            &x_alt,
            "-sf",
            alt_stash.to_str().unwrap(),
            "dump",
            "-",
        ],
        "",
    );
    assert_eq!(status(&alt_dump), 0, "{}", text(&alt_dump.stderr));
    assert_ne!(alt_dump.stdout, plain.stdout);
    let last_wins = realm.run(
        &[
            "-d",
            &db,
            "-x",
            &x_alt,
            "-sf",
            alt_stash.to_str().unwrap(),
            "dump",
            "-",
        ],
        "",
    );
    assert_eq!(last_wins.stdout, alt_dump.stdout);
    let last_wins = realm.run(&["-x", &x_alt, "-d", &db, "dump", "-"], "");
    assert_eq!(last_wins.stdout, plain.stdout);
    let out = realm.run(
        &[
            "-x",
            &x_alt,
            "-sf",
            alt_stash.to_str().unwrap(),
            "destroy",
            "-f",
        ],
        "",
    );
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        format!("** Database '{db}' destroyed.\n")
    );
    assert!(!alt.exists());
    assert!(realm.db.exists());
}

#[test]
fn load_errors_are_mits() {
    let realm = Realm::new("kdb5-load-errors", Realm::sha1());
    realm.create();
    let out = realm.run(&["load", "no-such.dump"], "");
    assert_eq!(status(&out), 1);
    assert_eq!(
        text(&out.stderr),
        "kdb5_util: No such file or directory while opening no-such.dump\n"
    );
    std::fs::write(realm.dir.join("bad.dump"), "garbage\n").unwrap();
    let out = realm.run(&["load", "bad.dump"], "");
    assert_eq!(
        text(&out.stderr),
        "kdb5_util: dump header bad in bad.dump\n"
    );
    std::fs::write(realm.dir.join("empty.dump"), "").unwrap();
    let out = realm.run(&["load", "empty.dump"], "");
    assert_eq!(
        text(&out.stderr),
        "kdb5_util: can't read dump header in empty.dump\n"
    );
    let out = realm.run(&["dump", "full.dump"], "");
    assert_eq!(status(&out), 0);
    let full = std::fs::read_to_string(realm.dir.join("full.dump")).unwrap();
    std::fs::write(
        realm.dir.join("badrec.dump"),
        full.replacen("princ\t38\t11", "princ\tx\t11", 1),
    )
    .unwrap();
    let out = realm.run(&["load", "badrec.dump"], "");
    assert_eq!(status(&out), 1);
    assert_eq!(
        text(&out.stderr),
        "badrec.dump(2): cannot match size tokens\n\
         kdb5_util: error processing line 2 of badrec.dump\n\
         kdb5_util: Kerberos version 5 release 1.11 restore failed\n"
    );
    let out = realm.run(&["load", "-r18", "full.dump"], "");
    assert_eq!(
        text(&out.stderr),
        "kdb5_util: dump header bad in full.dump\n"
    );
}

#[test]
fn load_without_a_stash_needs_a_master_password() {
    let realm = Realm::new("kdb5-load-nostash", Realm::sha1());
    let golden =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/traces/kdb/mit-dump-v7.txt");
    let out = realm.run(&["load", golden.to_str().unwrap()], "");
    assert_eq!(status(&out), 1);
    assert_eq!(
        text(&out.stderr),
        "kdb5_util: Can not fetch master key (error: No such file or directory). while reading master key\n"
    );
    // The golden dump is MIT's, under an aes256-sha384 master key: its K/M names the type.
    let out = realm.run(
        &["-P", "masterpassword", "load", golden.to_str().unwrap()],
        "",
    );
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    assert!(realm.db.exists());
    assert!(!realm.stash.exists(), "MIT's load writes no stash");
    let out = realm.run(&["-P", "wrong", "load", golden.to_str().unwrap()], "");
    assert_eq!(status(&out), 1);
    assert_eq!(
        text(&out.stderr),
        "kdb5_util: Unable to decrypt latest master key with the provided master key\n while getting master key list\n"
    );
}

/// MIT `destroy_file` (`kdb_db2.c:619-682`): the database is zeroed before it is unlinked, so
/// another link to the file (or its freed blocks) keeps no key; settled live with a hard link.
#[test]
fn destroy_zeroes_the_database_before_unlinking_it() {
    let realm = Realm::new("kdb5-destroy-zero", Realm::sha1());
    realm.create();
    let link = realm.dir.join("principal.link");
    std::fs::hard_link(&realm.db, &link).unwrap();
    let size = std::fs::metadata(&link).unwrap().len();
    assert!(size > 0);
    let side: Vec<PathBuf> = [".ok", ".kadm5", ".kadm5.lock"]
        .iter()
        .map(|s| realm.dir.join(format!("principal{s}")))
        .collect();
    for p in &side {
        std::fs::write(p, "db2").unwrap();
    }
    let ulog = realm.dir.join("principal.ulog");
    assert!(!ulog.exists(), "no update log without iprop");
    let out = realm.run(&["destroy", "-f"], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    assert!(!realm.db.exists());
    assert!(side.iter().all(|p| !p.exists()));
    let left = std::fs::read(&link).unwrap();
    assert_eq!(left.len() as u64, size);
    assert!(
        left.iter().all(|&b| b == 0),
        "the other link still holds the database"
    );
    assert!(realm.stash.exists(), "destroy leaves the stash");
}

#[test]
fn destroy_asks_for_yes() {
    let realm = Realm::new("kdb5-destroy", Realm::sha1());
    realm.create();
    let db = realm.db.display().to_string();
    let prompt =
        format!("Deleting KDC database stored in '{db}', are you sure?\n(type 'yes' to confirm)? ");
    for answer in ["no\n", "", "yes"] {
        let out = realm.run(&["destroy"], answer);
        assert_eq!(status(&out), 1, "{answer:?}");
        assert_eq!(text(&out.stdout), prompt);
        assert!(realm.db.exists());
    }
    let out = realm.run(&["destroy"], "yes\n");
    assert_eq!(status(&out), 0);
    assert_eq!(
        text(&out.stdout),
        format!("{prompt}OK, deleting database '{db}'...\n** Database '{db}' destroyed.\n")
    );
    assert!(!realm.db.exists());
    assert!(realm.stash.exists(), "destroy leaves the stash");
    let out = realm.run(&["destroy", "-f"], "");
    assert_eq!(status(&out), 1);
    assert_eq!(
        text(&out.stderr),
        format!(
            "kdb5_util: Cannot open DB2 database '{db}': No such file or directory while initializing database\n"
        )
    );
}

/// A database file that is no database is refused with MIT's open text, settled live on MIT
/// 1.22.2 with a dump file put where its db2 database was: `dump` and `stash` while initializing
/// the database, `load -update` while opening it, before its permanent lock would remove
/// `principal.kadm5.lock`.
#[test]
fn a_database_file_that_is_no_database_is_refused_with_mit_s_text() {
    let realm = Realm::new("kdb5-not-a-database", Realm::sha1());
    realm.create();
    let dump = realm.dir.join("realm.dump");
    let dump = dump.to_str().unwrap();
    let out = realm.run(&["dump", dump], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    std::fs::write(&realm.db, "not a database\n").unwrap();
    let refused = format!(
        "kdb5_util: Cannot open DB2 database '{}': Invalid argument",
        realm.db.display()
    );
    for cmd in [&["dump", "out.dump"][..], &["stash"][..]] {
        let out = realm.run(cmd, "");
        assert_eq!(status(&out), 1, "{cmd:?}");
        assert_eq!(
            text(&out.stderr),
            format!("{refused} while initializing database\n"),
            "{cmd:?}"
        );
    }
    let out = realm.run(&["load", "-update", dump], "");
    assert_eq!(status(&out), 1);
    assert_eq!(
        text(&out.stderr),
        format!("{refused} while opening database\n")
    );
    assert!(realm.dir.join("principal.kadm5.lock").exists());
}

/// An MIT db2 database where the database should be (MIT 1.22.2's own btree and hash headers,
/// settled live) is named with the way over by every command that opens it, and left as it was.
#[test]
fn an_mit_db2_database_is_named_with_the_dump_and_load_way_over() {
    let realm = Realm::new("kdb5-mit-db2", Realm::sha1());
    realm.create();
    let dump = realm.dir.join("realm.dump");
    let dump = dump.to_str().unwrap();
    let out = realm.run(&["dump", dump], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    let refused = format!(
        "kdb5_util: Cannot open DB2 database '{}': This is an MIT db2 database; dump it with the \
         old installation's kdb5_util, then kdb5_util load here (docs/install.md, Upgrading an \
         MIT realm)",
        realm.db.display()
    );
    let btree = [0x62, 0x31, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x10];
    let hash = [
        0x00, 0x06, 0x15, 0x61, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x04, 0xd2,
    ];
    for head in [&btree[..], &hash[..]] {
        let mut db2 = head.to_vec();
        db2.resize(8192, 0);
        std::fs::write(&realm.db, &db2).unwrap();
        for cmd in [
            &["dump", "out.dump"][..],
            &["stash"][..],
            &["destroy", "-f"][..],
        ] {
            let out = realm.run(cmd, "");
            assert_eq!(status(&out), 1, "{cmd:?}");
            assert_eq!(
                text(&out.stderr),
                format!("{refused} while initializing database\n"),
                "{cmd:?}"
            );
        }
        let out = realm.run(&["load", "-update", dump], "");
        assert_eq!(status(&out), 1);
        assert_eq!(
            text(&out.stderr),
            format!("{refused} while opening database\n")
        );
        assert_eq!(std::fs::read(&realm.db).unwrap(), db2, "left as it was");
        assert!(realm.dir.join("principal.kadm5.lock").exists());
    }
}

#[cfg(feature = "test-hooks")]
#[test]
fn test_hooks_seed_the_gates_principals_and_stand_in_for_the_password() {
    let realm = Realm::new("kdb5-test-hooks", Realm::sha1());
    let out = Command::new(&realm.tool)
        .args(["create", "-s"])
        .env("KRB5_CONFIG", &realm.krb5_conf)
        .env("KRB5_KDC_PROFILE", &realm.kdc_conf)
        .env_remove("KRB5_KDC_DB")
        .env_remove("KRB5_KDC_STASH")
        .env("KRB5_MASTER_PASSWORD", "kl-master")
        .env("KRB5_TEST_USER_PASSWORD", "kl-user")
        .env("KRB5_TEST_ADMIN_PASSWORD", "kl-admin")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    let ids = realm.store().ids();
    for id in [
        "K/M@KL.TEST",
        "admin@KL.TEST",
        "host/testhost.kl.test@KL.TEST",
        "kadmin/admin@KL.TEST",
        "kadmin/changepw@KL.TEST",
        "kiprop/testhost.kerber.test@KL.TEST",
        "krbtgt/KL.TEST@KL.TEST",
        "user@KL.TEST",
    ] {
        assert!(ids.iter().any(|i| i == id), "{id} in {ids:?}");
    }
    // load with no stash: KRB5_MASTER_PASSWORD opens the dump and the stash is written.
    let golden =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/traces/kdb/mit-dump-v7.txt");
    std::fs::remove_file(&realm.stash).unwrap();
    let out = Command::new(&realm.tool)
        .args(["load", golden.to_str().unwrap()])
        .env("KRB5_CONFIG", &realm.krb5_conf)
        .env("KRB5_KDC_PROFILE", &realm.kdc_conf)
        .env("KRB5_MASTER_PASSWORD", "masterpassword")
        .output()
        .unwrap();
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    assert_eq!(mode(&realm.stash), 0o600);
    assert_eq!(realm.store().realm(), "KERBER.TEST");
}

fn iprop_stanza() -> String {
    format!(
        "{}        iprop_enable = true\n        iprop_port = 2121\n        iprop_ulogsize = 4\n",
        Realm::sha1()
    )
}

/// Settled live on MIT 1.22.2: without iprop, `create`, `dump` and `load` touch no update log,
/// and `dump -i` / `load -i` say "Iprop not enabled".
#[test]
fn without_iprop_no_command_touches_an_update_log() {
    let realm = Realm::new("kdb5-iprop-off", Realm::sha1());
    realm.create();
    let ulog = realm.dir.join("principal.ulog");
    let plain = realm.dir.join("plain.dump");
    let out = realm.run(&["dump", plain.to_str().unwrap()], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    let out = realm.run(&["dump", "-i1", "x.dump"], "");
    assert_eq!(
        (status(&out), text(&out.stderr)),
        (1, "Iprop not enabled\n".into())
    );
    let out = realm.run(&["load", "-i", plain.to_str().unwrap()], "");
    assert_eq!(
        (status(&out), text(&out.stderr)),
        (1, "Iprop not enabled\n".into())
    );
    for load in [&["load"][..], &["load", "-update"]] {
        let out = realm.run(&[load, &[plain.to_str().unwrap()]].concat(), "");
        assert_eq!(status(&out), 0, "{load:?}: {}", text(&out.stderr));
    }
    assert!(!ulog.exists());
}

/// Settled live on MIT 1.22.2 with iprop on: `create` makes the log (one dummy entry at serial
/// 1), `dump -i1` heads the dump with its last serial and time, a full `load` starts it over,
/// `load -i` sets it to the dump's serial and time, and `destroy` removes it.
#[cfg(feature = "test-hooks")]
#[test]
fn with_iprop_create_dump_load_and_destroy_keep_the_update_log() {
    let realm = Realm::new("kdb5-iprop-on", &iprop_stanza());
    realm.create();
    let ulog = realm.dir.join("principal.ulog");
    assert_eq!(std::fs::metadata(&ulog).unwrap().len(), 40 + 4 * 2048);
    let log = krb5_kdc::Ulog::map(&ulog, 4).unwrap();
    let created = log.get_last().unwrap();
    assert_eq!(created.sno, 1);
    let ipropx = realm.dir.join("i1.dump");
    let out = realm.run(&["dump", "-i1", ipropx.to_str().unwrap()], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    let dumped = std::fs::read_to_string(&ipropx).unwrap();
    let head = dumped.lines().next().unwrap().to_owned();
    assert_eq!(
        head,
        format!(
            "ipropx 1 1 {} {}",
            created.time.seconds, created.time.useconds
        )
    );
    let out = realm.run(&["dump", "-i", "i0.dump"], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    let i0 = std::fs::read_to_string(realm.dir.join("i0.dump")).unwrap();
    assert!(i0.starts_with(&format!("iprop 1 {} ", created.time.seconds)));
    // -c keeps a dump whose serial and time the log still holds: only its first line is read,
    // so a marked tail survives when the dump is not written again.
    let marked = format!("{dumped}kept\n");
    std::fs::write(&ipropx, &marked).unwrap();
    let out = realm.run(&["dump", "-i1", "-c", ipropx.to_str().unwrap()], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    assert_eq!(std::fs::read_to_string(&ipropx).unwrap(), marked);
    let out = realm.run(&["dump", "-c", "plain.dump"], "");
    assert_eq!(
        (status(&out), text(&out.stderr)),
        (
            1,
            "kdb5_util: Conditional dump is an undocumented option for use only for iprop dumps\n"
                .into()
        )
    );
    // A full load starts the log over; load -i then takes the dump's serial and time.
    let plain = realm.dir.join("plain.dump");
    let out = realm.run(&["dump", plain.to_str().unwrap()], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    let out = realm.run(&["load", plain.to_str().unwrap()], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    assert_eq!(log.get_last().unwrap().sno, 1);
    std::fs::write(
        &ipropx,
        dumped.replacen(&head, "ipropx 1 7 1791208296 779547", 1),
    )
    .unwrap();
    let out = realm.run(&["load", "-i", ipropx.to_str().unwrap()], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    let hdr = log.header_now().unwrap();
    assert_eq!((hdr.num, hdr.first_sno, hdr.last_sno), (1, 7, 7));
    assert_eq!(
        (hdr.last_time.seconds, hdr.last_time.useconds),
        (1_791_208_296, 779_547)
    );
    let out = realm.run(&["load", "-i", plain.to_str().unwrap()], "");
    assert_eq!(
        (status(&out), text(&out.stderr)),
        (
            1,
            format!("kdb5_util: dump header bad in {}\n", plain.display())
        )
    );
    drop(log);
    let out = realm.run(&["destroy", "-f"], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    assert!(
        !ulog.exists(),
        "destroy removes the update log with iprop on"
    );
}

/// Settled live on MIT 1.22.2 with iprop on (`settle-s7-load-update.txt`): `load -update` logs
/// every principal it puts, one entry each in the dump's order (a record the database already
/// holds unchanged carries only its name), and a policy record then starts the log over.
#[cfg(feature = "test-hooks")]
#[test]
fn with_iprop_load_update_logs_each_principal_and_a_policy_starts_the_log_over() {
    let stanza = format!(
        "{}        iprop_enable = true\n        iprop_port = 2121\n        iprop_ulogsize = 64\n",
        Realm::sha1()
    );
    let realm = Realm::new("kdb5-iprop-update", &stanza);
    realm.create();
    let plain = realm.dir.join("plain.dump");
    let out = realm.run(&["dump", plain.to_str().unwrap()], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    let dumped = std::fs::read_to_string(&plain).unwrap();
    let names: Vec<&str> = dumped
        .lines()
        .filter_map(|l| l.strip_prefix("princ\t"))
        .map(|l| l.split('\t').nth(5).unwrap())
        .collect();
    assert!(names.len() >= 4, "{names:?}");
    let log = krb5_kdc::Ulog::map(&realm.dir.join("principal.ulog"), 64).unwrap();
    let out = realm.run(&["load", "-update", plain.to_str().unwrap()], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    let entries = log.entries().unwrap();
    assert_eq!(entries.len(), names.len() + 1, "{entries:?}");
    assert_eq!(
        (entries[0].sno, entries[0].size),
        (1, 0),
        "create's dummy entry"
    );
    for (n, (e, name)) in (2..).zip(entries[1..].iter().zip(&names)) {
        assert_eq!(
            (e.sno, e.name.as_str(), e.deleted, e.attrs),
            (n, *name, false, 1 << krb5_kdc::AT_PRINC)
        );
    }
    let policy = "policy\tp1\t0\t0\t8\t1\t1\t0\t0\t0\t0\t0\t0\t0\t-\t0";
    let withpol = realm.dir.join("withpol.dump");
    std::fs::write(&withpol, format!("{dumped}{policy}\n")).unwrap();
    let out = realm.run(&["load", "-update", withpol.to_str().unwrap()], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    let hdr = log.header_now().unwrap();
    assert_eq!((hdr.num, hdr.first_sno, hdr.last_sno), (1, 1, 1));
    // An empty database file is an empty database: each record the update puts is a new
    // principal, which the log sends whole, and the database takes the dump's domain SID.
    let sid = realm.store().domain_sid().clone();
    std::fs::write(&realm.db, b"").unwrap();
    let out = realm.run(&["load", "-update", plain.to_str().unwrap()], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    let entries = log.entries().unwrap();
    assert_eq!(entries.len(), names.len() + 1, "{entries:?}");
    for (n, (e, name)) in (2..).zip(entries[1..].iter().zip(&names)) {
        assert_eq!((e.sno, e.name.as_str()), (n, *name));
        assert_ne!(
            e.attrs & (1 << krb5_kdc::AT_KEYDATA),
            0,
            "{name}: keys sent"
        );
    }
    let store = realm.store();
    assert_eq!(store.domain_sid(), &sid);
    assert!(
        names.iter().all(|n| store.get_raw(n).is_some()),
        "{names:?}"
    );
}

/// Settled live on MIT 1.22.2 (`settle-s10-load-fails-early.txt`): a full load starts the log
/// over only once the dump is in the temporary database, so a load whose temporary database
/// cannot be made leaves the log as it was.
#[test]
fn a_full_load_that_fails_before_the_promotion_leaves_the_update_log() {
    let realm = Realm::new("kdb5-iprop-load-early", &iprop_stanza());
    realm.create();
    let plain = realm.dir.join("plain.dump");
    let out = realm.run(&["dump", plain.to_str().unwrap()], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    let log = krb5_kdc::Ulog::map(&realm.dir.join("principal.ulog"), 4).unwrap();
    let kept = krb5_kdc::UlogLast {
        sno: 7,
        time: krb5_kdc::UlogTime {
            seconds: 1_791_208_296,
            useconds: 779_547,
        },
    };
    log.set_last(kept).unwrap();
    let plant = realm.dir.join("principal~");
    std::fs::create_dir(&plant).unwrap();
    std::fs::write(plant.join("keep"), b"").unwrap();
    let out = realm.run(&["load", plain.to_str().unwrap()], "");
    assert_eq!(status(&out), 1);
    assert!(
        text(&out.stderr).ends_with(" while creating database\n"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(log.get_last().unwrap(), kept);
    std::fs::remove_dir_all(&plant).unwrap();
    let out = realm.run(&["load", plain.to_str().unwrap()], "");
    assert_eq!(status(&out), 0, "{}", text(&out.stderr));
    assert_eq!(log.get_last().unwrap().sno, 1);
}

/// Settled live: MIT's admin interface refuses iprop without `iprop_port` ("Required parameters
/// in kdc.conf missing"); this create stops before writing anything.
#[test]
fn create_with_iprop_and_no_port_is_refused() {
    let stanza = format!("{}        iprop_enable = true\n", Realm::sha1());
    let realm = Realm::new("kdb5-iprop-noport", &stanza);
    let out = realm.run(&["-P", "kl-master", "create", "-s"], "");
    assert_eq!(status(&out), 1);
    assert_eq!(
        text(&out.stderr),
        "kdb5_util: Required parameters in kdc.conf missing while initializing the Kerberos admin interface\n"
    );
    assert!(!realm.db.exists());
}
