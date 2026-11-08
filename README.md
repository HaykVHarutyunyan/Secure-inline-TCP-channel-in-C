# Secure Inline Communication Channel (C / Linux)

```
PC1 ──► Device1 ══════ protected link ══════► Device2 ──► PC2
        encrypt TCP payload                   verify tag, decrypt,
        (AES-256-GCM)                         restore, recompute checksums
```

Device1 and Device2 are ordinary Linux routers. The kernel routes the packets;
an iptables rule hands the selected TCP/IPv4 packets to a user-space program
(NFQUEUE) that rewrites them in place and returns them to the kernel.

## What it does

| Requirement | Implementation |
|---|---|
| Secure session before data flows | Device1 ↔ Device2 run a handshake on TCP port 39001 first. Until it succeeds nothing is listening on the NFQUEUE, so the kernel **drops** the protected traffic (fail closed). |
| Diffie–Hellman key exchange | Ephemeral **X25519** on both sides, then HKDF-SHA256 → two AES-256 keys (one per direction) and two 4-byte nonce salts. The exchange is authenticated with HMAC-SHA256 over the transcript using a pre-shared key, so a man in the middle cannot substitute keys. |
| Encrypt only the TCP payload | AES-256-GCM over the TCP payload only. |
| Keep IP/TCP headers, append the tag | `IP hdr │ TCP hdr │ counter(8) │ ciphertext │ tag(16)` – headers untouched, no UDP, no extra protocol header between IP and TCP. Only IP total length and the two checksums change. |
| Forward directly to the peer device | The original IP header (dst = PC2) is kept; the packet is simply routed to Device2 as next hop. |
| Verify, decrypt, restore, checksums | Device2 checks the tag, decrypts, removes the 24 bytes, fixes IP total length, IP header checksum and TCP checksum, and the kernel forwards the packet to PC2. |
| Unique nonce per packet per session | `nonce(12) = salt(4) ‖ counter(8)`. The salt comes from the DH exchange, the counter starts at 0 for every session and is incremented for every encrypted packet (retransmissions get a new one). Each direction has its own key, so a (key, nonce) pair has exactly one sender. The counter never wraps: at 2⁶⁴−1 the device refuses to encrypt. A new handshake gives new keys. Only the 8-byte counter travels in the packet (same construction as RFC 4106). |

Extra protections beyond the brief:

* **Header binding:** IP src/dst, TCP ports and TCP sequence number are fed to GCM as additional authenticated data, so a valid protected payload cannot be moved to another flow or sequence position.
* **Anti-replay:** 1024-packet sliding window on the counter; the window only moves after the tag verified.
* **Fail closed:** unauthenticated payloads, IP fragments, malformed packets and exhausted counters are dropped, never forwarded in clear.
* The handshake server ignores junk connections and only accepts a peer that proves knowledge of the PSK.

### Why no TCP sequence/ACK translation is needed

The extra 24 bytes exist only on the Device1 ↔ Device2 link. Device2 removes
them again, so PC1 and PC2 see exactly the segments they sent and the sequence
and ACK numbers match end to end. The only side effect is a bigger packet on
the protected link, handled by **MSS clamping**: Device1 lowers the MSS in every
SYN and SYN-ACK by 24 bytes (1460 → 1436), so a full-size segment becomes
exactly 1500 bytes on the wire.

## Files

| File | Purpose |
|---|---|
| `crypto.c/h` | AES-256-GCM (with AAD, in-place) |
| `handshake.c/h` | X25519 + HKDF + PSK-authenticated handshake |
| `packet.c/h` | encrypt/decrypt of a packet, nonce counter, replay window, checksums, MSS clamp |
| `engine.c/h` | NFQUEUE loop shared by both devices |
| `device1.c`, `device2.c`, `cli.c/h` | the two programs and their option parsing |
| `test_*.c` | unit tests (OpenSSL only, no root) |
| `scripts/` | `lab.sh` (4 network namespaces), `e2e_test.sh` + helpers (end-to-end test) |

## Build and test

```bash
sudo apt install -y build-essential libssl-dev libnetfilter-queue-dev   # OpenSSL 3 required
make            # device1, device2
make test       # unit tests, no root needed
sudo make e2e   # full PC1→Device1→Device2→PC2 test in network namespaces
                # (needs iptables, iproute2, tcpdump, python3)
```

`make e2e` builds the whole topology on one machine, starts both devices,
transfers data in both directions, captures all three links and checks them,
simulates packet loss, and injects plaintext, replayed, bit-flipped and
spliced packets. Logs and pcaps land in `lab-logs/`. See `TEST_RESULTS.txt`.

## Running on real hosts / VMs

Topology: PC1 – Device1 – Device2 – PC2, routed (each device has two NICs).
Example addresses as in `scripts/lab.sh`: PC1 10.0.1.2, Device1 10.0.1.1 / 10.0.2.1,
Device2 10.0.2.2 / 10.0.3.1, PC2 10.0.3.2.

```bash
# PC1:      ip route add default via 10.0.1.1
# PC2:      ip route add default via 10.0.3.1

# Device1 (as root)
sysctl -w net.ipv4.ip_forward=1
ip route add 10.0.3.0/24 via 10.0.2.2
iptables -t raw -A PREROUTING -p tcp -s 10.0.1.2 -d 10.0.3.2 -j CT --notrack
iptables -t raw -A PREROUTING -p tcp -s 10.0.3.2 -d 10.0.1.2 -j CT --notrack
iptables -A FORWARD -p tcp -s 10.0.1.2 -d 10.0.3.2 -j NFQUEUE --queue-num 0
iptables -A FORWARD -p tcp -s 10.0.3.2 -d 10.0.1.2 -j NFQUEUE --queue-num 0

# Device2: same rules, and  ip route add 10.0.1.0/24 via 10.0.2.1

# Start Device2 first (it waits for the handshake), then Device1:
echo 'a-long-random-shared-secret' > /etc/sic.psk && chmod 600 /etc/sic.psk
sudo ./device2 -f /etc/sic.psk   10.0.1.2 10.0.3.2                 # PC1_IP PC2_IP
sudo ./device1 -f /etc/sic.psk   10.0.2.2 10.0.1.2 10.0.3.2        # DEVICE2_IP PC1_IP PC2_IP
```

Options (both devices): `-p PORT` protect only flows whose PC2-side port is PORT
(use the same value on both devices and add `--dport/--sport PORT` to the rules),
`-q NUM` queue number, `-H PORT` handshake port, `-f FILE` / `SIC_PSK` / last
argument for the PSK (min. 8 characters; the file or variable keeps it out of
`ps`), `-v` log every drop. `kill -USR1` prints the counters, `SIGTERM` stops.

Traffic that is **not** selected (other ports with `-p`, other hosts) is not
protected and passes in clear text.

## Limitations (prototype)

* **One session per run.** Restart both devices to re-key. There is no rekey timer, but the 64-bit counter makes exhaustion irrelevant in practice.
* **Only the payload is confidential and integrity-protected.** IP/TCP headers stay visible (by design). Only IP addresses, ports and the sequence number are authenticated; an on-path attacker could still alter other header fields (ACK, flags, window, options) or drop/delay packets.
* **MTU:** the MSS clamp covers connections that start after the devices are up. A connection that was already running with full 1500-byte packets will black-hole (PMTU discovery cannot fix it). Assumes a 1500-byte path MTU between the devices.
* **IP fragments** of selected TCP flows are dropped (fail closed). IPv4 and TCP only; IPv6 and UDP are not handled.
* **Routed inline model.** Devices must be IP routers on the path; the conntrack bypass rule is recommended because conntrack on the inter-device link would see the longer segments. GRO/GSO packets are segmented by the kernel before they reach the queue, so offloads can stay on, but `ethtool -K IF gro off` is the safest setting in a lab.
* The PSK is the trust anchor: protect it. Session keys do not depend on it, so a later PSK leak does not expose recorded sessions (forward secrecy), but it would allow impersonating a device in a future handshake.

## Changes relative to the starter project

* Fixed: MSS changes on SYN packets were computed but discarded (packet accepted unmodified); `\\n` printed literally in messages; IP total length handling with trailing link-layer padding; handshake aborted the device on any junk connection.
* The README claimed TCP sequence/ACK translation was required – it is not (see above).
* Added: GCM additional authenticated data, replay window, directional nonce salts (explicit nonce reduced from 12 to 8 bytes), shared engine for both devices, PSK from file/env, statistics, graceful shutdown, namespace lab and automated end-to-end test, much larger unit-test suite.
