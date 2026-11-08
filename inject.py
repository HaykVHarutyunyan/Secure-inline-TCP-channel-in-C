#!/usr/bin/env python3
"""
Attack injector for the end-to-end test.  Run inside Device1's namespace; it
sends forged / replayed packets onto the Device1 -> Device2 link (stdlib only).

  inject.py plain  CAPTURE_B.pcap   plaintext payload claiming to be PC1 -> PC2
  inject.py replay CAPTURE_B.pcap   exact copy of a genuine protected packet
  inject.py tamper CAPTURE_B.pcap   genuine packet, ciphertext bit flipped, FRESH counter
                                    (passes the replay window, must fail the GCM tag)
  inject.py splice CAPTURE_B.pcap   genuine packet moved to another TCP seq number
                                    (its counter was already used, so the replay window
                                    rejects it before the tag is even checked)
"""
import socket, struct, sys

PC1, PC2 = "10.0.1.2", "10.0.3.2"


def ones(b):
    s = 0
    for i in range(0, len(b) - 1, 2):
        s += (b[i] << 8) | b[i + 1]
    if len(b) & 1:
        s += b[-1] << 8
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return s


def fix(pkt):
    pkt = bytearray(pkt)
    ihl = (pkt[0] & 15) * 4
    pkt[10:12] = b"\0\0"
    pkt[10:12] = struct.pack(">H", ~ones(bytes(pkt[:ihl])) & 0xffff)
    t = pkt[ihl:]
    t[16:18] = b"\0\0"
    ph = bytes(pkt[12:20]) + bytes([0, 6]) + struct.pack(">H", len(t))
    t[16:18] = struct.pack(">H", ~(ones(ph + bytes(t))) & 0xffff)
    pkt[ihl:] = t
    return bytes(pkt)


def last_data_packet(path):
    d = open(path, "rb").read()
    off, found = 24, None
    while off + 16 <= len(d):
        caplen = struct.unpack("<I", d[off + 8:off + 12])[0]
        f = d[off + 16:off + 16 + caplen]
        off += 16 + caplen
        if len(f) > 54 and f[12:14] == b"\x08\x00":
            p = f[14:]
            ihl = (p[0] & 15) * 4
            tot = struct.unpack(">H", p[2:4])[0]
            thl = (p[ihl + 12] >> 4) * 4
            if p[9] == 6 and socket.inet_ntoa(p[12:16]) == PC1 and tot - ihl - thl > 24:
                found = p[:tot]
    if not found:
        sys.exit("no protected data packet in capture")
    return bytearray(found)


def main():
    mode, cap = sys.argv[1], sys.argv[2]
    if mode == "plain":
        payload = b"INJECTED-PLAINTEXT-PAYLOAD-0123456789"
        ihl = 20
        tcp = struct.pack(">HHIIBBHHH", 44444, 5001, 1234567, 0, 5 << 4, 0x18, 8192, 0, 0) + payload
        pkt = bytearray(struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0x4242, 0x4000, 64, 6, 0,
                                    socket.inet_aton(PC1), socket.inet_aton(PC2))) + tcp
    else:
        pkt = last_data_packet(cap)
        ihl = (pkt[0] & 15) * 4
        if mode == "tamper":
            thl = (pkt[ihl + 12] >> 4) * 4
            ctr = struct.unpack(">Q", pkt[ihl + thl:ihl + thl + 8])[0] + 10**9
            pkt[ihl + thl:ihl + thl + 8] = struct.pack(">Q", ctr)   # unseen counter
            pkt[-30] ^= 0x01                              # inside the ciphertext
        elif mode == "splice":
            seq = struct.unpack(">I", pkt[ihl + 4:ihl + 8])[0]
            pkt[ihl + 4:ihl + 8] = struct.pack(">I", (seq + 1) & 0xffffffff)
        elif mode != "replay":
            sys.exit("unknown mode")
    pkt = fix(pkt)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.sendto(pkt, (PC2, 0))
    print(f"injected {mode} packet ({len(pkt)} bytes) towards Device2")


main()
