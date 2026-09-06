//! MIT `krb5_pac_parse` refusals (`pac.c:281-317`): version, buffer count,
//! 8-byte alignment, offsets inside the header or past the end.

use krb5_types::pac::{PAC_LOGON_INFO, Pac, PacBuffer};

fn canonical() -> Vec<u8> {
    Pac::built(
        0,
        vec![
            PacBuffer::new(PAC_LOGON_INFO, vec![0x11; 24]),
            PacBuffer::new(PAC_LOGON_INFO + 9, vec![0x22; 8]),
        ],
    )
    .to_bytes()
}

#[test]
fn parse_accepts_the_canonical_layout() {
    assert!(Pac::parse(&canonical()).is_ok());
}

#[test]
fn parse_refuses_version_other_than_zero() {
    let mut pac = canonical();
    pac[4] = 1;
    assert!(Pac::parse(&pac).is_err());
}

#[test]
fn parse_refuses_zero_buffers() {
    let mut pac = canonical();
    pac[0..4].copy_from_slice(&0u32.to_le_bytes());
    assert!(Pac::parse(&pac).is_err());
}

#[test]
fn parse_refuses_unaligned_offset() {
    let mut pac = canonical();
    let off = u64::from_le_bytes(pac[16..24].try_into().unwrap());
    pac[16..24].copy_from_slice(&(off + 1).to_le_bytes());
    assert!(Pac::parse(&pac).is_err());
}

#[test]
fn parse_refuses_offset_inside_the_header() {
    let mut pac = canonical();
    pac[16..24].copy_from_slice(&8u64.to_le_bytes());
    assert!(Pac::parse(&pac).is_err());
}

#[test]
fn parse_refuses_size_past_the_end() {
    let mut pac = canonical();
    pac[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(Pac::parse(&pac).is_err());
}
