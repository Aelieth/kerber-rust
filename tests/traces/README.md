# Golden DER / traces

In-crate tests assert RFC 4120 APPLICATION tags against the shipped
encoder (`0x61` Ticket, `0x79` EncASRepPart, `0x7e` KRB-ERROR, `0x76`
KRB-CRED).

Set `KERBER_CAPTURE_DIR` to this directory (or a temp dir) when running
the KDC or client: each raw PDU is written as `{kdc,client}-{req,rep}-<nonce>.der`
at the Rust socket boundary (no packet sniffer required). Copy MIT 1.22.2
captures here when a content-asserting gate is added for that PDU.
