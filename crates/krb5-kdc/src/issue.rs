// MIT: `process_as_req` (kdc/do_as_req.c:470-470)
mod as_req;
// MIT: `dispatch` (kdc/dispatch.c:90-90)
mod dispatch;
// MIT: `kdc_find_fast` (kdc/fast_util.c:127-127)
mod fast_util;
// MIT: `validate_as_request` (kdc/kdc_util.c:716-716)
mod kdc_util;
mod reply;
// MIT: `check_tgs_policy` (kdc/tgs_policy.c:733-733)
mod tgs_policy;
// MIT: `process_tgs_req` (kdc/do_tgs_req.c:1164-1164)
mod tgs_req;

pub use as_req::{IssuedAs, issue_as};
pub(crate) use as_req::{extract_enc_timestamp, verify_enc_timestamp};
pub(crate) use dispatch::{KdcDispatch, ThreadSlots};
pub use dispatch::{handle_request, handle_request_from};
pub(crate) use kdc_util::decrypt_presented_tgt;
pub(crate) use reply::kdc_error_bytes;
pub use tgs_req::{IssuedTgs, issue_tgs, tgs_header_is_crossrealm};
