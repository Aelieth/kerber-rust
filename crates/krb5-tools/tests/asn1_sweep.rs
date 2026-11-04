#![allow(dead_code)]

include!("../src/asn1_sweep.rs");

#[test]
fn each_case_decodes_as_mit_decodes_it() {
    let messages = messages();
    let cases = corpus(&messages);
    let parts = check_golden(&messages, &cases, include_str!("data/asn1-mit-golden.tsv"));
    assert!(
        parts.is_empty(),
        "{} of {} cases part from MIT 1.22.2's decoder:\n{}",
        parts.len(),
        cases.len(),
        parts
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
