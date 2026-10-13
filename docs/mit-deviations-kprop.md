# kprop deviations from MIT 1.22.2

The rows of [mit-deviations.md](mit-deviations.md) that concern kprop, kept here whole so that file stays under its size cap.

| Deviation | MIT | Rust | Why |
| --- | --- | --- | --- |
| kprop's names, keytab and replies | `get_tickets` (`kprop.c:173-208`): `sn2princ_realm` of both hosts, expanded as `dns_canonicalize_hostname` says; `krb5_read_message` allocates what a reply's length says | names without DNS, as kpropd's above; a keytab that cannot be read stops kprop before its AS exchange; **STRICTER**: a kpropd reply past 8 MiB is refused as `ENOMEM` | `kprop_names_a_failure_as_mits_com_err`; `kprop_refuses_a_reply_past_eight_mib` |
| kprop's clock after the AS reply (`kdc_timesync`) | `verify_as_reply` (`get_in_tkt.c:260-264`): with `kdc_timesync` (the default) the reply's authtime sets the context's clock offset, so the authenticator's ctime and kprop's other timestamps are the KDC's | kprop keeps that offset for its own authenticator; the client libraries have none (the `kdc_timesync` row of [mit-deviations.md](mit-deviations.md)) | exact for kprop | `kprop_dates_its_authenticator_by_the_kdcs_clock` |
