#!/usr/bin/env python3
"""Hold one kadm5 RPC connection and send one byte every 34s. Never finish a record."""
import select
import socket
import sys
import time

port = int(sys.argv[1]) if len(sys.argv) > 1 else 749
bound = float(sys.argv[2]) if len(sys.argv) > 2 else 60.0
s = socket.create_connection(("127.0.0.1", port), 5)
s.setblocking(False)
t0 = time.monotonic()
sent = 0
next_send = t0
closed = None
try:
    while True:
        now = time.monotonic()
        if now - t0 >= bound:
            break
        if now >= next_send:
            try:
                s.send(b"\x00")
            except OSError as exc:
                closed = f"send {exc.__class__.__name__}"
                break
            sent += 1
            next_send = now + 34.0
        wait = min(1.0, max(0.0, bound - (now - t0)), max(0.0, next_send - now))
        r, _, _ = select.select([s], [], [], wait)
        if r:
            try:
                data = s.recv(64)
            except OSError as exc:
                closed = f"recv {exc.__class__.__name__}"
                break
            if data == b"":
                closed = "eof"
                break
except Exception as exc:
    closed = exc.__class__.__name__
finally:
    s.close()
elapsed = time.monotonic() - t0
print(f"TRICKLE sent={sent} closed={closed or 'bound'} elapsed={elapsed:.1f}", flush=True)
