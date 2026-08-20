# Golden DER / traces

In-crate tests assert RFC 4120 APPLICATION tags against the shipped
encoder (`0x61` Ticket, `0x79` EncASRepPart, `0x7e` KRB-ERROR, `0x76`
KRB-CRED). Live MIT 1.22.2 captures belong here when the harness is run
(`scripts/client-gate.sh`, `scripts/kdc-gate.sh`).
