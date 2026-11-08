#!/usr/bin/env python3
"""
Traffic generator for the end-to-end test (stdlib only).

  e2e_traffic.py serve   BIND_IP PORT --me pc1|pc2 --n-pc1 N --n-pc2 N
  e2e_traffic.py connect SERVER_IP PORT --me pc1|pc2 --n-pc1 N --n-pc2 N
  e2e_traffic.py echo-serve BIND_IP PORT
  e2e_traffic.py echo-connect SERVER_IP PORT

Duplex mode: both sides send a deterministic stream (it starts with a visible
marker so captures can be searched) and verify the SHA-256 of what they get.
"""
import argparse, hashlib, socket, sys, threading

MARKERS = {"pc1": b"PC1-SECRET-MARKER-", "pc2": b"PC2-SECRET-MARKER-"}


def stream(name, n):
    """First 2 KiB: marker repeated; then SHA-256 based pseudo-random bytes."""
    out = bytearray()
    m = MARKERS[name]
    while len(out) < min(n, 2048):
        out += m
    ctr = 0
    while len(out) < n:
        out += hashlib.sha256(name.encode() + ctr.to_bytes(8, "big")).digest()
        ctr += 1
    return bytes(out[:n])


def duplex(sock, me, n_pc1, n_pc2):
    peer = "pc2" if me == "pc1" else "pc1"
    n_me, n_peer = (n_pc1, n_pc2) if me == "pc1" else (n_pc2, n_pc1)
    expected = hashlib.sha256(stream(peer, n_peer)).hexdigest()
    mine = stream(me, n_me)
    err = []

    def sender():
        try:
            sock.sendall(mine)
            sock.shutdown(socket.SHUT_WR)
        except Exception as e:                       # noqa
            err.append(("send", e))

    t = threading.Thread(target=sender)
    t.start()
    h, got = hashlib.sha256(), 0
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        h.update(chunk)
        got += len(chunk)
    t.join()
    ok = (not err) and got == n_peer and h.hexdigest() == expected
    print(f"[{me}] sent={n_me} received={got}/{n_peer} sha256 {'OK' if ok else 'MISMATCH'}"
          + (f" err={err}" if err else ""))
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["serve", "connect", "echo-serve", "echo-connect"])
    ap.add_argument("ip")
    ap.add_argument("port", type=int)
    ap.add_argument("--me", choices=["pc1", "pc2"])
    ap.add_argument("--n-pc1", type=int, default=0)
    ap.add_argument("--n-pc2", type=int, default=0)
    a = ap.parse_args()

    if a.mode in ("serve", "echo-serve"):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((a.ip, a.port))
        srv.listen(1)
        srv.settimeout(40)
        conn, _ = srv.accept()
        conn.settimeout(60)
        if a.mode == "serve":
            sys.exit(0 if duplex(conn, a.me, a.n_pc1, a.n_pc2) else 1)
        while True:                                   # echo server
            d = conn.recv(65536)
            if not d:
                break
            conn.sendall(d)
        sys.exit(0)

    s = socket.socket()
    s.settimeout(60)
    s.connect((a.ip, a.port))
    if a.mode == "connect":
        sys.exit(0 if duplex(s, a.me, a.n_pc1, a.n_pc2) else 1)

    sizes = [1, 2, 3, 7, 16, 17, 100, 1000, 1431, 1432, 1433, 1460, 4000, 20000]
    ok = True
    for sz in sizes:
        msg = (b"echo-%d-" % sz) * (sz // 6 + 1)
        msg = msg[:sz]
        s.sendall(msg)
        buf = b""
        while len(buf) < sz:
            c = s.recv(sz - len(buf))
            if not c:
                break
            buf += c
        if buf != msg:
            ok = False
            print(f"echo of {sz} bytes: MISMATCH")
    s.close()
    print(f"echo test ({len(sizes)} message sizes, 1..20000 bytes): {'OK' if ok else 'FAILED'}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
