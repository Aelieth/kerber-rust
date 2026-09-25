//! Known answers and the logging schema. These examples do not talk to a KDC.
//!
//! RFC 3962 appendix B, AES-128, one iteration:
//!
//! ```
//! use krb5_crypto::{EncryptionType, string_to_key};
//! let key = string_to_key(
//!     EncryptionType::Aes128CtsHmacSha196,
//!     b"password",
//!     b"ATHENA.MIT.EDUraeburn",
//!     Some(&1u32.to_be_bytes()),
//! )?;
//! assert_eq!(
//!     key.as_bytes(),
//!     &[
//!         0x42, 0x26, 0x3c, 0x6e, 0x89, 0xf4, 0xfc, 0x28, 0xb8, 0xdf, 0x68, 0xee, 0x09, 0x79, 0x9f,
//!         0x15,
//!     ]
//! );
//! Ok::<(), krb5_crypto::Error>(())
//! ```
//!
//! RFC 3962 appendix B, AES-256, one iteration:
//!
//! ```
//! use krb5_crypto::{EncryptionType, string_to_key};
//! let key = string_to_key(
//!     EncryptionType::Aes256CtsHmacSha196,
//!     b"password",
//!     b"ATHENA.MIT.EDUraeburn",
//!     Some(&1u32.to_be_bytes()),
//! )?;
//! assert_eq!(
//!     key.as_bytes(),
//!     &[
//!         0xfe, 0x69, 0x7b, 0x52, 0xbc, 0x0d, 0x3c, 0xe1, 0x44, 0x32, 0xba, 0x03, 0x6a, 0x92, 0xe6,
//!         0x5b, 0xbb, 0x52, 0x28, 0x09, 0x90, 0xa2, 0xfa, 0x27, 0x88, 0x39, 0x98, 0xd7, 0x2a, 0xf3,
//!         0x01, 0x61,
//!     ]
//! );
//! Ok::<(), krb5_crypto::Error>(())
//! ```
//!
//! A JSON subscriber sees `event`, `correlation_id`, `component`, and
//! `outcome` on the string-to-key event the library emits:
//!
//! ```
//! use std::io::{self, Write};
//! use std::sync::{Arc, Mutex};
//!
//! use krb5_crypto::{EncryptionType, string_to_key};
//!
//! struct Mem(Arc<Mutex<Vec<u8>>>);
//!
//! impl Write for Mem {
//!     fn write(&mut self, data: &[u8]) -> io::Result<usize> {
//!         self.0
//!             .lock()
//!             .map_err(|_| io::Error::other("poison"))?
//!             .extend_from_slice(data);
//!         Ok(data.len())
//!     }
//!     fn flush(&mut self) -> io::Result<()> {
//!         Ok(())
//!     }
//! }
//!
//! let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
//! let writer = Arc::clone(&buf);
//! assert!(
//!     tracing_subscriber::fmt()
//!         .json()
//!         .with_ansi(false)
//!         .with_current_span(false)
//!         .with_max_level(tracing::Level::INFO)
//!         .with_writer(move || Mem(Arc::clone(&writer)))
//!         .try_init()
//!         .is_ok()
//! );
//!
//! let _ = string_to_key(
//!     EncryptionType::Aes128CtsHmacSha196,
//!     b"password",
//!     b"ATHENA.MIT.EDUraeburn",
//!     Some(&1u32.to_be_bytes()),
//! )?;
//! let text = String::from_utf8(buf.lock().expect("lock").clone()).expect("utf8");
//! fn string_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
//!     let pat = format!("\"{key}\":");
//!     let rest = line[line.find(&pat)? + pat.len()..].trim_start();
//!     let rest = rest.strip_prefix('"')?;
//!     Some(&rest[..rest.find('"')?])
//! }
//! let mut seen = std::collections::BTreeSet::new();
//! for line in text.lines() {
//!     if !line.starts_with('{') {
//!         continue;
//!     }
//!     for key in ["event", "correlation_id", "component", "outcome"] {
//!         assert!(string_field(line, key).is_some(), "{key} missing in {line}");
//!     }
//!     if let Some(event) = string_field(line, "event") {
//!         seen.insert(event.to_owned());
//!     }
//! }
//! assert!(
//!     seen.contains("crypto.string_to_key"),
//!     "library string-to-key did not emit"
//! );
//! assert!(!seen.is_empty());
//! Ok::<(), krb5_crypto::Error>(())
//! ```
