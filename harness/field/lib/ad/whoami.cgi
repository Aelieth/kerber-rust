#!/bin/sh
# ad-trust (SB.ad-spnego): echo who Apache authenticated.
printf 'Content-Type: text/plain\r\n\r\n'
printf 'REMOTE_USER=%s\nAUTH_TYPE=%s\nGSS_NAME=%s\nREMOTE_ADDR=%s\nSERVER_NAME=%s\n' "$REMOTE_USER" "$AUTH_TYPE" "$GSS_NAME" "$REMOTE_ADDR" "$SERVER_NAME"
