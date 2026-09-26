//! The crypto layer's structured events carry the log contract's four fields.
//! `docs/logging.md` names `event`, `correlation_id`, `component` and `outcome` on every
//! library event; this test reads them off a JSON subscriber around `string_to_key`.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use krb5_crypto::{EncryptionType, string_to_key};

struct Mem(Arc<Mutex<Vec<u8>>>);

impl Write for Mem {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("poison"))?
            .extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn string_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{key}\":");
    let rest = line[line.find(&pat)? + pat.len()..].trim_start();
    let rest = rest.strip_prefix('"')?;
    Some(&rest[..rest.find('"')?])
}

#[test]
fn string_to_key_event_carries_the_four_schema_fields() {
    let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let writer = Arc::clone(&buf);
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_ansi(false)
        .with_current_span(false)
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || Mem(Arc::clone(&writer)))
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        string_to_key(
            EncryptionType::Aes128CtsHmacSha196,
            b"password",
            b"ATHENA.MIT.EDUraeburn",
            Some(&1u32.to_be_bytes()),
        )
        .unwrap();
    });
    let text = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
    let line = text
        .lines()
        .find(|l| string_field(l, "event") == Some("crypto.string_to_key"))
        .unwrap_or_else(|| panic!("no crypto.string_to_key line in {text}"));
    for key in ["event", "correlation_id", "component", "outcome"] {
        assert!(string_field(line, key).is_some(), "{key} missing in {line}");
    }
    assert_eq!(string_field(line, "component"), Some("krb5-crypto"));
    assert_eq!(string_field(line, "outcome"), Some("ok"));
}
