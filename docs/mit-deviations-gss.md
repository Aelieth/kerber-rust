# AP-REQ and GSS deviations from MIT 1.22.2

The rows of [mit-deviations.md](mit-deviations.md) that concern the AP-REQ authenticator our GSS initiator and clients build, kept here whole so that file stays under its size cap.

| Deviation | MIT | Rust | Why |
| --- | --- | --- | --- |
| The GSS initiator's initial sequence number (`init_sec_context.c:523`; `mk_req_ext.c:137-143` under DO_SEQUENCE; RFC 4120 §3.2.2 and §5.5.1 say it SHOULD be random) | the authenticator carries a random non-zero seq-number below 2^30 and the per-message SND_SEQ starts there | the authenticator's seq-number is 0 and SND_SEQ starts at 0 | Settled live (`working/logs/f-KI/gss-seq-settle/`): MIT accepts our contexts; a token replayed into a new context fails its MIC (BAD_SIG), because each context's key derives from a fresh random initiator subkey (RFC 4121 §2). A predictable start gains an attacker nothing; it is a missed SHOULD. A random start is planned for 1.1.1 |
| `[libdefaults] client_aware_channel_bindings` (`gen_authenticator`: AD-AP-OPTIONS `KERB_AP_OPTIONS_CBT` 0x4000) | with the relation true, or `GSS_C_CHANNEL_BOUND_FLAG`, every AP-REQ's authenticator carries authorization data AD-IF-RELEVANT holding AD-AP-OPTIONS 0x4000; off by default | the relation is not read; no AP-REQ carries AD-AP-OPTIONS | Fail-closed: a service that requires a channel-binding-aware client refuses ours rather than accepting it, and the default matches MIT's (settled live, `working/logs/f-KI/gss-seq-settle/`). Planned for 1.1.1 |
