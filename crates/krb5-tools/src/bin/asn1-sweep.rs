#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

include!("../asn1_sweep.rs");

use std::process::ExitCode;

fn read(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))
}

fn run(args: &[String]) -> Result<bool, String> {
    let messages = messages();
    if let Some(m) = messages.iter().find(|m| m.debug.contains("None")) {
        return Err(format!("{}: a sample leaves an OPTIONAL field out", m.name));
    }
    let cases = corpus(&messages);
    match args {
        [cmd] if cmd == "corpus" => {
            print!("{}", corpus_text(&cases));
            Ok(true)
        }
        [cmd] if cmd == "rust" => {
            print!("{}", rust_text(&messages, &cases));
            Ok(true)
        }
        [cmd, mit, mit_of_rust, out] if cmd == "golden" => {
            let (text, parts) = golden_text(
                &messages,
                &cases,
                &parse_mit(&read(mit)?),
                &parse_mit(&read(mit_of_rust)?),
            );
            std::fs::write(out, text).map_err(|e| format!("{out}: {e}"))?;
            for p in &parts {
                println!("PART\t{p}");
            }
            println!("{} of {} cases part from MIT", parts.len(), cases.len());
            Ok(parts.is_empty())
        }
        [cmd, golden] if cmd == "check" => {
            let parts = check_golden(&messages, &cases, &read(golden)?);
            for p in &parts {
                println!("PART\t{p}");
            }
            println!(
                "{} of {} cases part from the golden",
                parts.len(),
                cases.len()
            );
            Ok(parts.is_empty())
        }
        _ => Err(
            "usage: asn1-sweep corpus | rust | golden <mit> <mit-of-rust> <out> | check <golden>"
                .into(),
        ),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("asn1-sweep: {e}");
            ExitCode::from(2)
        }
    }
}
