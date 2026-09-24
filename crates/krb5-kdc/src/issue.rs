//! AS and TGS ticket issuance as functions over the principal store.
//!
//! One module per MIT source family: `dispatch` (`dispatch.c` +
//! `net-server.c`), `as_req` (`do_as_req.c`), `tgs_req`
//! (`do_tgs_req.c`), `tgs_policy` (`tgs_policy.c`), `kdc_util`
//! (`kdc_util.c` and the PROCESS_TGS helpers), `fast_util`
//! (`fast_util.c`), `reply` (issued tickets and KRB-ERROR).

mod as_req;
mod dispatch;
mod fast_util;
mod kdc_util;
mod reply;
mod tgs_policy;
mod tgs_req;

pub use as_req::{IssuedAs, issue_as};
pub(crate) use as_req::{extract_enc_timestamp, verify_enc_timestamp};
pub use dispatch::{handle_request, handle_request_from};
pub(crate) use reply::kdc_error_bytes;
pub use tgs_req::{IssuedTgs, issue_tgs, tgs_header_is_crossrealm};
