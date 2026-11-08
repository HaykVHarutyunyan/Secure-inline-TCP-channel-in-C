#!/usr/bin/env python3
"""
Analyse packet captures taken at three points of the lab:

  A = PC1 <-> Device1 link   (clear text on both sides of PC1)
  B = Device1 <-> Device2    (the protected link)
  C = Device2 <-> PC2 link   (clear text on both sides of PC2)

usage: e2e_analyze.py [--lossy] A.pcap B.pcap C.pcap   (stdlib only)
"""
import struct, sys

PC1, PC2 = "10.0.1.2", "10.0.3.2"
OVERHEAD = 24
MARKERS = [b"PC1-SECRET-MARKER-", b"PC2-SECRET-MARKER-"]
fails = 0


def check(ok, text):
    global fails
    print(("  PASS  " if ok else "  FAIL  ") + text)
    if not ok:
        fails += 1


def read_pcap(path):
    d = open(path, "rb").read()
    magic = struct.unpack("<I", d[:4])[0]
    endian = "<" if magic in (0xa1b2c3d4, 0xa1b23c4d) else ">"
    link = struct.unpack(endian + "I", d[20:24])[0]
    off, frames = 24, []
    while off + 16 <= len(d):
        _, _, caplen, _ = struct.unpack(endian + "IIII", d[off:off + 16])
        off += 16
        frames.append(d[off:off + caplen])
        off += caplen
    assert link == 1, "expected Ethernet captures"
    return frames


def ones(b):
    s = 0
    for i in range(0, len(b) - 1, 2):
        s += (b[i] << 8) | b[i + 1]
    if len(b) & 1:
        s += b[-1] << 8
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return s


def ip(b):
    return ".".join(str(x) for x in b)


def parse(frames):
    pk = []
    for f in frames:
        if len(f) < 34 or f[12:14] != b"\x08\x00":
            continue
        p = f[14:]
        ihl = (p[0] & 15) * 4
        tot = struct.unpack(">H", p[2:4])[0]
        if p[9] != 6:
            continue
        p = p[:tot]
        t = p[ihl:]
        thl = (t[12] >> 4) * 4
        tl = len(t)
        ph = p[12:20] + bytes([0, 6]) + struct.pack(">H", tl)
        s = ones(ph) + ones(t)
        while s >> 16:
            s = (s & 0xffff) + (s >> 16)
        pk.append(dict(
            frame=f, ip_len=tot, src=ip(p[12:16]), dst=ip(p[16:20]),
            sport=struct.unpack(">H", t[0:2])[0], dport=struct.unpack(">H", t[2:4])[0],
            seq=struct.unpack(">I", t[4:8])[0], flags=t[13],
            payload=t[thl:], plen=tl - thl, ip_ok=ones(p[:ihl]) == 0xffff, tcp_ok=s == 0xffff,
            syn=bool(t[13] & 2), opts=t[20:thl]))
    return pk


def data(pk, src):
    return [p for p in pk if p["src"] == src and p["plen"] > 0]


def keyset(pkts):
    d = {}
    for p in pkts:
        d.setdefault((p["sport"], p["dport"], p["seq"]), set()).add(p["plen"])
    return d


def mss_of(p):
    o, i = p["opts"], 0
    while i < len(o):
        if o[i] == 0:
            break
        if o[i] == 1:
            i += 1
            continue
        if o[i] == 2 and o[i + 1] == 4:
            return struct.unpack(">H", o[i + 2:i + 4])[0]
        i += o[i + 1]
    return None


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    lossy = "--lossy" in sys.argv
    A, B, C = (parse(read_pcap(p)) for p in args)
    print(f"captured TCP packets: A={len(A)}  B={len(B)}  C={len(C)}")

    blob = lambda pk: b"".join(p["frame"] for p in pk)
    for m in MARKERS:
        check(m in blob(A) and m in blob(C), f"clear-text marker {m.decode()}... visible on PC-side links (A, C)")
        check(m not in blob(B), f"marker {m.decode()}... NOT visible on the Device1<->Device2 link (B)")

    check(all(p["ip_ok"] and p["tcp_ok"] for p in B), "all IP and TCP checksums valid on link B (protected packets)")
    check(all(p["ip_ok"] and p["tcp_ok"] for p in C), "all IP and TCP checksums valid on link C (restored packets)")
    check(all(p["ip_ok"] and p["tcp_ok"] for p in A), "all IP and TCP checksums valid on link A (restored packets)")
    check(max(p["ip_len"] for p in B) <= 1500, f"largest packet on link B is {max(p['ip_len'] for p in B)} bytes (<= MTU 1500, no fragmentation)")

    # MSS as RECEIVED by each host must be reduced; as SENT by the host it is the original value.
    to_pc1 = [mss_of(p) for p in A if p["syn"] and p["dst"] == PC1]
    to_pc2 = [mss_of(p) for p in C if p["syn"] and p["dst"] == PC2]
    from_pc1 = [mss_of(p) for p in A if p["syn"] and p["src"] == PC1]
    from_pc2 = [mss_of(p) for p in C if p["syn"] and p["src"] == PC2]
    print(f"    MSS in SYN/SYN-ACK: sent by PC1 {from_pc1}, received by PC2 {to_pc2}; sent by PC2 {from_pc2}, received by PC1 {to_pc1}")
    check(to_pc1 and to_pc2 and all(m == 1460 - OVERHEAD for m in to_pc1 + to_pc2) and
          all(m == 1460 for m in from_pc1 + from_pc2),
          "every SYN/SYN-ACK delivered to a host carries MSS 1436 (1460 - 24); the hosts' own were 1460")

    for label, src, plain_side, deliv_side in (("PC1->PC2", PC1, A, C), ("PC2->PC1", PC2, C, A)):
        P, W, D = (keyset(data(x, src)) for x in (plain_side, B, deliv_side))
        print(f"    {label}: data segments plain={len(P)} wire={len(W)} delivered={len(D)}")
        check(len(W) > 0, f"{label}: payload-bearing packets present on link B")
        if lossy:
            check(all(k in W and {l + OVERHEAD for l in D[k]} <= W[k] for k in D),
                  f"{label}: every delivered segment was protected on the wire (+24 bytes)")
        else:
            check(set(P) == set(W) == set(D), f"{label}: same set of (ports, seq) on plain side, wire and delivery")
            check(all(W[k] == {l + OVERHEAD for l in P[k]} for k in P), f"{label}: every wire payload is exactly plaintext length + 24 bytes (8 nonce + 16 tag)")
            check(all(D[k] == P[k] for k in P), f"{label}: restored payload lengths equal the originals")

        ctrs = [struct.unpack(">Q", p["payload"][:8])[0] for p in data(B, src)]
        check(len(ctrs) == len(set(ctrs)), f"{label}: all {len(ctrs)} explicit nonce counters on the wire are unique")
        if not lossy:
            check(ctrs == list(range(len(ctrs))), f"{label}: counters are exactly 0..{len(ctrs)-1} in transmission order")

    print()
    print("ANALYSIS: " + ("ALL PASS" if not fails else f"{fails} FAILED"))
    sys.exit(1 if fails else 0)


main()
