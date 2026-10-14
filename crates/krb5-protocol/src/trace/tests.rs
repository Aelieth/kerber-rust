//! The formatter and the points against the lines MIT 1.22.2's tools wrote live.

use std::net::SocketAddr;

use krb5_types::{PaData, PrincipalName};

use super::*;

fn pa(t: i32) -> PaData {
    PaData {
        padata_type: t,
        padata_value: Vec::new().into(),
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Live MIT 1.22.2 (`s01-keyblock-form.txt`): the key whose bytes MIT's `klist -K` printed traced
/// as `aes256-sha2/4149`, the first two bytes of its SHA-1; no key byte is printed.
#[test]
fn a_keyblock_is_its_enctype_and_a_sixteen_bit_hash() {
    let key = hex("6bf42ce474920d4ddef1ecbdc6371c3bbd395ef68a7bda72c4e8c1f381152a77");
    let k = Key {
        etype: 20,
        bytes: &key,
    };
    let line = trace_format(
        "AS key obtained from gak_fct: {keyblock}",
        &[Arg::Keyblock(Some(k))],
    );
    assert_eq!(line, "AS key obtained from gak_fct: aes256-sha2/4149");
    assert_eq!(
        trace_format("subkey {key}", &[Arg::Key(Some(k))]),
        "subkey aes256-sha2/4149"
    );
    assert_eq!(trace_format("{keyblock}", &[Arg::Keyblock(None)]), "(null)");
    assert_eq!(
        trace_format(
            "SPAKE algorithm result: {hashlenstr}",
            &[Arg::HashLenStr(Some(&key))]
        ),
        "SPAKE algorithm result: 4149"
    );
}

/// Live MIT 1.22.2 kinit: the KDC's method data and the next request's padata.
#[test]
fn padata_lists_print_names_and_numbers() {
    let list = [pa(136), pa(19), pa(151), pa(2), pa(133)];
    assert_eq!(
        trace_format(
            "Processing preauth types: {patypes}",
            &[Arg::Patypes(&list)]
        ),
        "Processing preauth types: PA-FX-FAST (136), PA-ETYPE-INFO2 (19), PA-SPAKE (151), \
         PA-ENC-TIMESTAMP (2), PA-FX-COOKIE (133)"
    );
    assert_eq!(
        trace_format(
            "Produced preauth for next request: {patypes}",
            &[Arg::Patypes(&[])]
        ),
        "Produced preauth for next request: (empty)"
    );
    assert_eq!(
        trace_format("Continuing preauth mech {patype}", &[Arg::Patype(151)]),
        "Continuing preauth mech PA-SPAKE (151)"
    );
    assert_eq!(trace_format("{patype}", &[Arg::Patype(4242)]), "4242");
}

/// Live MIT 1.22.2 kvno: the shortest enctype names.
#[test]
fn enctypes_print_their_shortest_names() {
    assert_eq!(
        trace_format(
            "etypes requested in TGS request: {etypes}",
            &[Arg::Etypes(&[20, 19, 18, 17])]
        ),
        "etypes requested in TGS request: aes256-sha2, aes128-sha2, aes256-cts, aes128-cts"
    );
    assert_eq!(trace_format("{etypes}", &[Arg::Etypes(&[])]), "(empty)");
    assert_eq!(trace_format("{etype}", &[Arg::Etype(23)]), "rc4-hmac");
    assert_eq!(trace_format("{etype}", &[Arg::Etype(99)]), "99");
}

/// Live MIT 1.22.2: an error code prints with its table text, or the message the library set.
#[test]
fn errors_print_their_code_and_text() {
    assert_eq!(
        trace_format("{kerr}", &[Arg::Kerr(kdc_code(25), None)]),
        "-1765328359/Additional pre-authentication required"
    );
    assert_eq!(
        trace_format("{kerr}", &[Arg::Kerr(0, Some("ignored"))]),
        "0/Success"
    );
    assert_eq!(
        trace_format(
            "{kerr}",
            &[Arg::Kerr(
                -1_765_328_243,
                Some("Matching credential not found (filename: /tmp/krb5cc_0)")
            )]
        ),
        "-1765328243/Matching credential not found (filename: /tmp/krb5cc_0)"
    );
    assert_eq!(
        error_message(-1_765_328_243),
        "Matching credential not found"
    );
    assert_eq!(
        error_message(kdc_code(13)),
        "KDC can't fulfill requested option"
    );
    assert_eq!(error_message(2), "No such file or directory");
    assert_eq!(
        trace_format("{errno}", &[Arg::Errno(111)]),
        "111/Connection refused"
    );
}

/// Live MIT 1.22.2 kinit and kpasswd: addresses with their transport.
#[test]
fn remote_addresses_print_transport_and_address() {
    let addr: SocketAddr = "127.0.0.1:88".parse().unwrap();
    let udp = RemoteAddr {
        transport: Transport::Udp,
        addr,
    };
    assert_eq!(
        trace_format(
            "Sending initial UDP request to {raddr}",
            &[Arg::Raddr(&udp)]
        ),
        "Sending initial UDP request to dgram 127.0.0.1:88"
    );
    let tcp = RemoteAddr {
        transport: Transport::Tcp,
        addr: "[::1]:464".parse().unwrap(),
    };
    assert_eq!(
        trace_format("{raddr}", &[Arg::Raddr(&tcp)]),
        "stream [::1]:464"
    );
}

/// Live MIT 1.22.2 SPAKE kinit: a cookie with bytes outside 32 to 126 prints them as `\xNN`.
#[test]
fn unprintable_bytes_print_as_escapes() {
    assert_eq!(
        trace_format(
            "Received cookie: {lenstr}",
            &[Arg::LenStr(Some(b"MIT1\x00\x00\x00\x01Fot\x95\\x"))]
        ),
        "Received cookie: MIT1\\x00\\x00\\x00\\x01Fot\\x95\\x"
    );
    assert_eq!(
        trace_format("Received cookie: {lenstr}", &[Arg::LenStr(Some(b"MIT"))]),
        "Received cookie: MIT"
    );
    assert_eq!(trace_format("{str}", &[Arg::Str(None)]), "(null)");
}

/// Live MIT 1.22.2 kinit: a config entry's principal escapes `/` and `@` in its third component.
#[test]
fn credentials_print_client_and_server() {
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    let conf = PrincipalName::new(
        PrincipalName::NT_UNKNOWN,
        [
            "krb5_ccache_conf_data",
            "fast_avail",
            "krbtgt/KERBER.TEST@KERBER.TEST",
        ],
    );
    let line = trace_format(
        "Storing {creds} in {ccache}",
        &[
            Arg::Creds(
                Some(Princ::new(&user, b"KERBER.TEST")),
                Princ::new(&conf, b"X-CACHECONF:"),
            ),
            Arg::Ccache("MEMORY:mua1adX"),
        ],
    );
    assert_eq!(
        line,
        "Storing user@KERBER.TEST -> krb5_ccache_conf_data/fast_avail/krbtgt\\/KERBER.TEST\\@\
         KERBER.TEST@X-CACHECONF: in MEMORY:mua1adX"
    );
    // Live MIT 1.22.2 `kvno -U user -P`: the S4U2Proxy lookup matches any client.
    assert_eq!(
        trace_format(
            "Retrieving {creds} from {ccache}",
            &[
                Arg::Creds(None, Princ::new(&user, b"KERBER.TEST")),
                Arg::Ccache("FILE:/tmp/krb5cc_0"),
            ]
        ),
        "Retrieving  -> user@KERBER.TEST from FILE:/tmp/krb5cc_0"
    );
    assert_eq!(
        trace_format("for {princ}: x", &[Arg::Princ(None)]),
        "for : x"
    );
}

/// Live MIT 1.22.2 kinit: the timestamp line, `{long}.{int}` with no padding.
#[test]
fn hex_data_prints_upper_case() {
    let plain = hex("301aa011180f32303236313030353134333834335aa105020300af76");
    let line = trace_format(
        "Encrypted timestamp (for {long}.{int}): plain {hexdata}, encrypted {hexdata}",
        &[
            Arg::Long(1_791_211_123),
            Arg::Int(44_918),
            Arg::HexData(Some(&plain)),
            Arg::HexData(Some(&[0xbb, 0x19])),
        ],
    );
    assert_eq!(
        line,
        "Encrypted timestamp (for 1791211123.44918): plain \
         301AA011180F32303236313030353134333834335AA105020300AF76, encrypted BB19"
    );
}

/// MIT `trace_format`: an unknown word prints nothing and takes no argument, and a `{` with no
/// `}` ends the message, as MIT's own `TRACE_TGS_REPLY_DECODE_SESSION` shows.
#[test]
fn unknown_words_and_open_braces_follow_mit() {
    assert_eq!(
        trace_format(
            "TGS reply didn't decode with subkey; trying session key ({keyblock)}",
            &[Arg::Keyblock(None)]
        ),
        "TGS reply didn't decode with subkey; trying session key ("
    );
    assert_eq!(trace_format("a {nope} {int} b", &[Arg::Int(7)]), "a  7 b");
    assert_eq!(trace_format("a {int", &[Arg::Int(7)]), "a ");
    assert_eq!(trace_format("{int}", &[Arg::Str(Some(b"x"))]), "");
}

#[test]
fn the_krb5_table_is_whole() {
    assert_eq!(krb5_err::TEXTS.len(), 256);
    assert_eq!(error_message(ERROR_TABLE_BASE_KRB5), "No error");
    assert_eq!(
        error_message(ERROR_TABLE_BASE_KRB5 + 255),
        "Tracing unsupported"
    );
    for (code, text) in [
        (KRB5_CC_NOTFOUND, "Matching credential not found"),
        (KRB5_KDCREP_MODIFIED, "KDC reply did not match expectations"),
        (
            KRB5_KDC_UNREACH,
            "Cannot contact any KDC for requested realm",
        ),
        (KRB5_KT_NOTFOUND, "Key table entry not found"),
        (KRB5_FCC_NOFILE, "No credentials cache found"),
    ] {
        assert_eq!(error_message(code), text);
    }
}

#[test]
fn at_secure_reads_the_auxiliary_vector() {
    let w = std::mem::size_of::<usize>();
    let entry = |k: usize, v: usize| [k.to_ne_bytes(), v.to_ne_bytes()].concat();
    let mut v = [entry(6, 4096), entry(23, 0), entry(0, 0)].concat();
    assert!(!at_secure(&v));
    v[w * 3..w * 4].copy_from_slice(&1usize.to_ne_bytes());
    assert!(at_secure(&v));
}

/// Live MIT 1.22.2 kinit (`kinit/mit.trace`): the output cache written through a MEMORY cache.
#[test]
fn write_out_ccache_is_mits_memory_cache_sequence() {
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    let realm = crate::ccache::realm("KERBER.TEST");
    let mut cc = crate::ccache::FileCcache::new((realm.clone(), user.clone()), Vec::new());
    cc.set_config(Some("krbtgt/KERBER.TEST@KERBER.TEST"), "fast_avail", b"yes");
    let mut tgt = cc.creds[0].clone();
    tgt.server = (realm, PrincipalName::krbtgt("KERBER.TEST"));
    cc.creds.push(tgt);
    let lines = capture(|| write_out_ccache("FILE:/tmp/krb5cc_0", &cc));
    let mcc = lines[1]
        .strip_prefix("Initializing ")
        .and_then(|s| s.split(' ').next())
        .unwrap()
        .to_owned();
    assert!(mcc.starts_with("MEMORY:") && mcc.len() == 14, "{mcc}");
    let want = [
        "Resolving unique ccache of type MEMORY".to_owned(),
        format!("Initializing {mcc} with default princ user@KERBER.TEST"),
        format!("Storing config in {mcc} for krbtgt/KERBER.TEST@KERBER.TEST: fast_avail: yes"),
        format!(
            "Storing user@KERBER.TEST -> krb5_ccache_conf_data/fast_avail/krbtgt\\/KERBER.TEST\\@\
             KERBER.TEST@X-CACHECONF: in {mcc}"
        ),
        format!("Storing user@KERBER.TEST -> krbtgt/KERBER.TEST@KERBER.TEST in {mcc}"),
        format!("Moving ccache {mcc} to FILE:/tmp/krb5cc_0"),
        format!("Destroying ccache {mcc}"),
    ];
    assert_eq!(lines, want);
}

/// Live MIT 1.22.2 kinit and kvno: the points' texts, MIT's conditional words included.
#[test]
fn points_print_mits_lines() {
    let addr = RemoteAddr {
        transport: Transport::Udp,
        addr: "127.0.0.1:88".parse().unwrap(),
    };
    let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "testhost.kerber.test"]);
    let lines = capture(|| {
        sendto_kdc(168, b"KERBER.TEST", false, false);
        sendto_kdc(168, b"KERBER.TEST", false, true);
        sendto_kdc_resolving("127.0.0.1");
        sendto_kdc_udp_send_initial(&addr);
        sendto_kdc_response(865, &addr);
        fast_nego(true);
        fast_nego(false);
        tkt_creds_service_req(Princ::new(&host, b"KERBER.TEST"), true);
        preauth_process("encrypted_timestamp", 2, true, 0, None);
        init_creds_error_reply(kdc_code(25));
    });
    assert_eq!(
        lines,
        [
            "Sending request (168 bytes) to KERBER.TEST",
            "Sending request (168 bytes) to KERBER.TEST (tcp only)",
            "Resolving hostname 127.0.0.1",
            "Sending initial UDP request to dgram 127.0.0.1:88",
            "Received answer (865 bytes) from dgram 127.0.0.1:88",
            "FAST negotiation: available",
            "FAST negotiation: unavailable",
            "Requesting tickets for host/testhost.kerber.test@KERBER.TEST, referrals on",
            "Preauth module encrypted_timestamp (2) (real) returned: 0/Success",
            "Received error from KDC: -1765328359/Additional pre-authentication required",
        ]
    );
}

/// No trace line carries a key's or a secret's bytes, in either hex case.
#[test]
fn no_point_prints_key_or_secret_bytes() {
    let secret: Vec<u8> = (0u8..32)
        .map(|i| i.wrapping_mul(37).wrapping_add(11))
        .collect();
    let key = Key {
        etype: 18,
        bytes: &secret,
    };
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    let tgs = PrincipalName::krbtgt("KERBER.TEST");
    let (c, s) = (
        Princ::new(&user, b"KERBER.TEST"),
        Princ::new(&tgs, b"KERBER.TEST"),
    );
    let lines = capture(|| {
        init_creds_as_key_gak(key);
        init_creds_as_key_preauth(key);
        init_creds_decrypted_reply(key);
        preauth_enc_ts_key_gak(key);
        fast_armor_ccache_key(key);
        fast_armor_key(key);
        fast_reply_key(key);
        send_tgs_subkey(key);
        tgs_reply(c, s, key);
        mk_req(c, s, 0, Some(key), key);
        rd_rep(1, 2, Some(key), 3);
        spake_result(&secret);
        preauth_enc_ts_armored(1, 2, b"plain", &secret);
    });
    let mut hex_upper = String::new();
    add_hex(&mut hex_upper, &secret);
    let hex_lower = hex_upper.to_lowercase();
    for line in &lines {
        for i in 0..secret.len() - 3 {
            let window = &hex_upper[2 * i..2 * i + 8];
            assert!(
                !line.contains(window) && !line.contains(&hex_lower[2 * i..2 * i + 8]),
                "{line}"
            );
        }
    }
    assert_eq!(lines.len(), 13);
    assert!(lines[11].starts_with("SPAKE algorithm result: ") && lines[11].len() == 28);
    let (head, hash) = lines[12].rsplit_once(' ').unwrap();
    assert_eq!(
        head,
        "Encrypted timestamp (for 1.2): plain 706C61696E, encrypted"
    );
    assert!(
        hash.len() == 4 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
        "{hash}"
    );
}

/// MIT `init_creds_step_request` (`lib/krb5/krb/get_in_tkt.c:1321-1322`): a retry after a KDC error names the error, then the mechanism.
#[test]
fn tryagain_names_the_error_then_the_mechanism() {
    let lines = capture(|| init_creds_preauth_tryagain(65, 16));
    assert_eq!(
        lines,
        ["Recovering from KDC error 65 using preauth mech PA-PK-AS-REQ (16)"]
    );
}

/// The `Arg` kinds a `{word}` prints, as `format_word` matches them.
fn kinds_of(word: &str) -> &'static [&'static str] {
    match word {
        "int" | "long" => &["Int", "Long"],
        "str" => &["Str"],
        "lenstr" => &["LenStr"],
        "hexlenstr" => &["HexLenStr"],
        "hashlenstr" => &["HashLenStr"],
        "raddr" => &["Raddr"],
        "data" => &["Data"],
        "hexdata" => &["HexData"],
        "errno" => &["Errno"],
        "kerr" => &["Kerr"],
        "keyblock" => &["Keyblock"],
        "key" => &["Key"],
        "cksum" => &["Cksum"],
        "princ" => &["Princ", "PrincName"],
        "ptype" => &["Ptype"],
        "patypes" => &["Patypes"],
        "patype" => &["Patype"],
        "etype" => &["Etype"],
        "etypes" => &["Etypes"],
        "ccache" => &["Ccache"],
        "keytab" => &["Keytab"],
        "creds" => &["Creds"],
        _ => &[],
    }
}

/// Every point hands each `{word}` of its text, in order, an argument of the kind that word
/// prints; a word handed another kind prints nothing.
#[test]
fn every_point_gives_each_word_its_kind() {
    assert!(WORDS.iter().all(|w| !kinds_of(w).is_empty()));
    let src = include_str!("points.rs");
    let mut points = 0;
    for call in src.split("krb5int_trace(").skip(1) {
        let open = call.find('"').expect("a format");
        let mut fmt = String::new();
        let mut end = None;
        let mut chars = call[open + 1..].char_indices();
        while let Some((i, c)) = chars.next() {
            match c {
                '\\' => fmt.push(chars.next().expect("an escape").1),
                '"' => {
                    end = Some(open + 1 + i + 1);
                    break;
                }
                c => fmt.push(c),
            }
        }
        let rest = &call[end.expect("a closed format")..];
        let body = &rest[..rest.find(");").expect("the call's end")];
        let kinds: Vec<&str> = body
            .match_indices("Arg::")
            .map(|(i, _)| {
                let name = &body[i + 5..];
                &name[..name
                    .find(|c: char| !c.is_ascii_alphanumeric())
                    .unwrap_or(name.len())]
            })
            .collect();
        let mut words = Vec::new();
        let mut text = fmt.as_str();
        while let Some(at) = text.find('{') {
            text = &text[at + 1..];
            let Some(close) = text.find('}') else {
                break;
            };
            if is_word(&text[..close]) {
                words.push(&text[..close]);
            }
            text = &text[close + 1..];
        }
        assert_eq!(words.len(), kinds.len(), "{fmt}: {kinds:?}");
        for (word, kind) in words.iter().zip(&kinds) {
            assert!(
                kinds_of(word).contains(kind),
                "{fmt}: {{{word}}} is handed Arg::{kind}"
            );
        }
        points += 1;
    }
    assert_eq!(points, src.matches("\npub fn ").count());
}

/// `Arg`'s `Debug` shows a `{hashlenstr}`'s length and a key's enctype, never their bytes.
#[test]
fn debug_withholds_hashed_and_key_bytes() {
    let secret = b"seed bytes!";
    assert_eq!(
        format!("{:?}", Arg::HashLenStr(Some(secret))),
        "HashLenStr(Some(<11 bytes>))"
    );
    let key = Key {
        etype: 18,
        bytes: secret,
    };
    assert_eq!(
        format!("{:?}", Arg::Keyblock(Some(key))),
        "Keyblock(Some(Key { etype: 18, .. }))"
    );
    assert_eq!(format!("{:?}", Arg::Int(65)), "Int(65)");
}

#[test]
fn principal_types_have_mit_names() {
    assert_eq!(
        trace_format("{ptype}", &[Arg::Ptype(3)]),
        "service with host as instance"
    );
    assert_eq!(trace_format("{ptype}", &[Arg::Ptype(99)]), "?");
}
