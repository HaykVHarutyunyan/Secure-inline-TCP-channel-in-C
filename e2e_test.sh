#!/usr/bin/env bash
#
# End-to-end test of PC1 -> Device1 -> Device2 -> PC2 in four network
# namespaces (run as root:  sudo scripts/e2e_test.sh).
#
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
LOGS=$ROOT/lab-logs
LAB=$ROOT/scripts/lab.sh
PY="python3 -I"
PSK_FILE=$LOGS/psk
FAILS=0

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
for b in device1 device2; do [ -x ./$b ] || { echo "build first: make"; exit 1; }; done
for t in ip iptables tcpdump python3; do command -v $t >/dev/null || { echo "missing tool: $t"; exit 1; }; done

rm -rf "$LOGS"; mkdir -p "$LOGS"
printf '%s\n' "e2e-pre-shared-key-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')" > "$PSK_FILE"
chmod 600 "$PSK_FILE"

PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
    sleep 0.3
    $LAB down >/dev/null 2>&1
}
trap cleanup EXIT

ok()   { echo "  PASS  $1"; }
bad()  { echo "  FAIL  $1"; FAILS=$((FAILS + 1)); }
step() { echo; echo "== $1"; }
nsx()  { $LAB exec "$@"; }

start_capture() {   # start_capture NS IFACE NAME
    "$LAB" exec "$1" tcpdump -i "$2" -U -s0 -n -w "$LOGS/$3.pcap" >"$LOGS/$3.tcpdump.log" 2>&1 &
    PIDS+=($!)
    CAPPID=$!
    for _ in $(seq 50); do grep -q "listening on" "$LOGS/$3.tcpdump.log" && break; sleep 0.1; done
}
stop_captures() { for p in "$@"; do kill -TERM "$p" 2>/dev/null; done; sleep 1; }

stats_block() {   # stats_block LOGFILE KEY  -> value of key in the LAST statistics block
    awk -v k="$2" '/^statistics\[/ {blk=""} {blk = blk " " $0} END {print blk}' "$1" |
        grep -o "$2=[0-9]*" | tail -1 | cut -d= -f2
}
dump_stats() {   # ask both devices for statistics
    kill -USR1 "$D1PID" "$D2PID"; sleep 0.7
}

# ---------------------------------------------------------------------------
step "Lab topology: PC1 - Device1 - Device2 - PC2"
$LAB up || { echo "lab setup failed"; exit 1; }

step "Before the secure session exists, protected traffic must not flow (fail closed)"
if nsx sic-pc1 timeout 6 $PY -c "
import socket
s=socket.socket(); s.settimeout(2)
try: s.connect(('10.0.3.2',5001)); raise SystemExit(1)
except OSError: raise SystemExit(0)"; then ok "PC1 cannot reach PC2 while no device has a session"; else bad "traffic leaked before the session"; fi

step "Handshake: start Device2, then Device1 (X25519 Diffie-Hellman over TCP :39001)"
"$LAB" exec sic-d2 ./device2 -f "$PSK_FILE" 10.0.1.2 10.0.3.2 >"$LOGS/device2.log" 2>&1 &
D2PID=$!; PIDS+=($D2PID)
sleep 0.5
"$LAB" exec sic-d1 ./device1 -f "$PSK_FILE" 10.0.2.2 10.0.1.2 10.0.3.2 >"$LOGS/device1.log" 2>&1 &
D1PID=$!; PIDS+=($D1PID)
for _ in $(seq 100); do
    grep -q "running" "$LOGS/device1.log" && grep -q "running" "$LOGS/device2.log" && break; sleep 0.1
done
grep -q "Device1 running" "$LOGS/device1.log" && grep -q "Device2 running" "$LOGS/device2.log" \
    && ok "both devices completed the handshake and entered packet processing" \
    || { bad "devices did not start"; cat "$LOGS"/device*.log; exit 1; }
cat "$LOGS/device1.log" "$LOGS/device2.log" | sed 's/^/    | /'

step "Captures on link A (PC1-Device1), B (Device1-Device2), C (Device2-PC2)"
start_capture sic-d1 veth-d1a A; CA=$CAPPID
start_capture sic-d1 veth-d1b B; CB=$CAPPID
start_capture sic-d2 veth-d2c C; CC=$CAPPID

N=3000000
step "Traffic 1: PC1 -> PC2 connection, 3 MB each way at the same time"
nsx sic-pc2 $PY scripts/e2e_traffic.py serve 10.0.3.2 5001 --me pc2 --n-pc1 $N --n-pc2 $N >"$LOGS/srv1.log" 2>&1 &
S1=$!; sleep 0.5
nsx sic-pc1 timeout 90 $PY scripts/e2e_traffic.py connect 10.0.3.2 5001 --me pc1 --n-pc1 $N --n-pc2 $N >"$LOGS/cli1.log" 2>&1; R1=$?
wait $S1; R1S=$?
cat "$LOGS/cli1.log" "$LOGS/srv1.log" | sed 's/^/    | /'
[ $R1 = 0 ] && [ $R1S = 0 ] && ok "data identical in both directions (SHA-256 verified at both ends)" || bad "transfer 1 corrupted/failed"

step "Traffic 2: connection initiated by PC2 towards PC1"
nsx sic-pc1 $PY scripts/e2e_traffic.py serve 10.0.1.2 5002 --me pc1 --n-pc1 1000000 --n-pc2 1000000 >"$LOGS/srv2.log" 2>&1 &
S2=$!; sleep 0.5
nsx sic-pc2 timeout 90 $PY scripts/e2e_traffic.py connect 10.0.1.2 5002 --me pc2 --n-pc1 1000000 --n-pc2 1000000 >"$LOGS/cli2.log" 2>&1; R2=$?
wait $S2; R2S=$?
cat "$LOGS/cli2.log" "$LOGS/srv2.log" | sed 's/^/    | /'
[ $R2 = 0 ] && [ $R2S = 0 ] && ok "PC2-initiated connection works (MSS clamped on SYN and SYN-ACK)" || bad "transfer 2 failed"

step "Traffic 3: interactive echo with small and odd-sized messages (1 .. 20000 bytes)"
nsx sic-pc2 $PY scripts/e2e_traffic.py echo-serve 10.0.3.2 5003 >"$LOGS/srv3.log" 2>&1 &
S3=$!; sleep 0.5
nsx sic-pc1 timeout 60 $PY scripts/e2e_traffic.py echo-connect 10.0.3.2 5003 >"$LOGS/cli3.log" 2>&1; R3=$?
wait $S3
sed 's/^/    | /' "$LOGS/cli3.log"
[ $R3 = 0 ] && ok "all echoed messages identical" || bad "echo test failed"

sleep 1
stop_captures $CA $CB $CC

step "Capture analysis (what is on the wire where)"
if $PY scripts/e2e_analyze.py "$LOGS/A.pcap" "$LOGS/B.pcap" "$LOGS/C.pcap" | tee "$LOGS/analysis.txt" | sed 's/^/  /' | grep -v '^$'; then :; fi
grep -q "ANALYSIS: ALL PASS" "$LOGS/analysis.txt" || FAILS=$((FAILS + 1))

step "Device counters (SIGUSR1): nothing may have been dropped on legitimate traffic"
dump_stats
E1=$(stats_block "$LOGS/device1.log" encrypted); X1=$(stats_block "$LOGS/device1.log" decrypted)
E2=$(stats_block "$LOGS/device2.log" encrypted); X2=$(stats_block "$LOGS/device2.log" decrypted)
echo "    Device1: encrypted=$E1 decrypted=$X1     Device2: encrypted=$E2 decrypted=$X2"
[ "$E1" = "$X2" ] && [ "$E2" = "$X1" ] && [ "$E1" -gt 0 ] && [ "$E2" -gt 0 ] \
    && ok "every packet Device1 encrypted was decrypted by Device2, and vice versa" || bad "encrypt/decrypt counters differ"
DROPS=0
for f in device1 device2; do
    for k in auth replay malformed other; do
        v=$(tail -n 12 "$LOGS/$f.log" | grep -o " $k=[0-9]*" | tail -1 | cut -d= -f2); DROPS=$((DROPS + ${v:-0}))
    done
done
[ $DROPS = 0 ] && ok "zero authentication/replay/malformed drops on legitimate traffic" || bad "unexpected drops: $DROPS"
M1=$(stats_block "$LOGS/device1.log" mss_clamped)
[ "${M1:-0}" -ge 6 ] && ok "Device1 clamped the MSS on $M1 SYN/SYN-ACK packets (3 connections)" || bad "MSS clamp count $M1"

# --------------------------------------------------------------------------
step "Attacks on the protected link (injected from Device1's side of link B)"
# a fresh recent genuine packet to replay
start_capture sic-d1 veth-d1b B3; CB3=$CAPPID
nsx sic-pc2 $PY scripts/e2e_traffic.py echo-serve 10.0.3.2 5004 >/dev/null 2>&1 &
S4=$!; sleep 0.4
nsx sic-pc1 timeout 30 $PY scripts/e2e_traffic.py echo-connect 10.0.3.2 5004 >/dev/null 2>&1
wait $S4; sleep 0.5; stop_captures $CB3
dump_stats; BEFORE_AUTH=$(stats_block "$LOGS/device2.log" auth); BEFORE_REPLAY=$(stats_block "$LOGS/device2.log" replay)
BEFORE_MAL=$(stats_block "$LOGS/device2.log" malformed)

start_capture sic-d2 veth-d2c C4; CC4=$CAPPID
for m in plain replay tamper splice; do nsx sic-d1 $PY scripts/inject.py $m "$LOGS/B3.pcap" | sed 's/^/    | /'; sleep 0.3; done
sleep 0.5; stop_captures $CC4
dump_stats
AFTER_AUTH=$(stats_block "$LOGS/device2.log" auth); AFTER_REPLAY=$(stats_block "$LOGS/device2.log" replay)
AFTER_MAL=$(stats_block "$LOGS/device2.log" malformed)
echo "    Device2 drops during attack: auth +$((AFTER_AUTH - BEFORE_AUTH))  replay +$((AFTER_REPLAY - BEFORE_REPLAY))  malformed +$((AFTER_MAL - BEFORE_MAL))"
[ $((AFTER_REPLAY - BEFORE_REPLAY)) -ge 1 ] && ok "replayed genuine packet rejected by the anti-replay window" || bad "replay not detected"
[ $((AFTER_AUTH - BEFORE_AUTH)) -ge 2 ] && ok "plaintext injection and bit-flipped ciphertext rejected by GCM tag verification" || bad "forgeries not detected"
TOTAL=$(( (AFTER_AUTH - BEFORE_AUTH) + (AFTER_REPLAY - BEFORE_REPLAY) + (AFTER_MAL - BEFORE_MAL) ))
[ $TOTAL -ge 4 ] && ok "all 4 attack packets (plain, replay, tamper, splice) were dropped by Device2" || bad "only $TOTAL of 4 attack packets dropped"
NDATA=$($PY - "$LOGS/C4.pcap" <<'EOF'
import struct, sys
d = open(sys.argv[1], "rb").read(); off = 24; n = 0
while off + 16 <= len(d):
    cl = struct.unpack("<I", d[off+8:off+12])[0]; f = d[off+16:off+16+cl]; off += 16 + cl
    if len(f) > 54 and f[12:14] == b"\x08\x00":
        p = f[14:]; ihl = (p[0] & 15) * 4; thl = (p[ihl+12] >> 4) * 4
        if p[9] == 6 and len(p) - ihl - thl > 0: n += 1
print(n)
EOF
)
[ "$NDATA" = 0 ] && ok "none of the forged/replayed packets reached PC2 (0 payload packets on link C)" || bad "$NDATA forged packets reached PC2"

# --------------------------------------------------------------------------
if nsx sic-d2 iptables -t raw -A PREROUTING -i veth-d2b -p tcp -m statistic --mode random --probability 0.03 -j DROP 2>/dev/null; then
    nsx sic-d1 iptables -t raw -A PREROUTING -i veth-d1b -p tcp -m statistic --mode random --probability 0.03 -j DROP
    step "Lossy link: 3% of protected packets dropped in both directions (TCP retransmits get fresh nonces)"
    start_capture sic-d1 veth-d1a A5; CA5=$CAPPID
    start_capture sic-d1 veth-d1b B5; CB5=$CAPPID
    start_capture sic-d2 veth-d2c C5; CC5=$CAPPID
    nsx sic-pc2 $PY scripts/e2e_traffic.py serve 10.0.3.2 5005 --me pc2 --n-pc1 1000000 --n-pc2 1000000 >"$LOGS/srv5.log" 2>&1 &
    S5=$!; sleep 0.5
    nsx sic-pc1 timeout 120 $PY scripts/e2e_traffic.py connect 10.0.3.2 5005 --me pc1 --n-pc1 1000000 --n-pc2 1000000 >"$LOGS/cli5.log" 2>&1; R5=$?
    wait $S5; R5S=$?
    sed 's/^/    | /' "$LOGS/cli5.log" "$LOGS/srv5.log"
    [ $R5 = 0 ] && [ $R5S = 0 ] && ok "transfer intact despite loss and retransmissions" || bad "lossy transfer failed"
    sleep 1; stop_captures $CA5 $CB5 $CC5
    $PY scripts/e2e_analyze.py --lossy "$LOGS/A5.pcap" "$LOGS/B5.pcap" "$LOGS/C5.pcap" | tee "$LOGS/analysis_lossy.txt" | sed 's/^/  /' | grep -v '^$'
    grep -q "ANALYSIS: ALL PASS" "$LOGS/analysis_lossy.txt" || FAILS=$((FAILS + 1))
else
    echo; echo "  (iptables 'statistic' match not available here: lossy-link phase skipped)"
fi

step "Shutdown"
kill -TERM "$D1PID" "$D2PID"; wait "$D1PID" "$D2PID" 2>/dev/null
grep -h -A2 "statistics" "$LOGS/device1.log" | tail -3 | sed 's/^/    | /'
grep -h -A2 "statistics" "$LOGS/device2.log" | tail -3 | sed 's/^/    | /'

echo
if [ $FAILS = 0 ]; then echo "END-TO-END TEST: ALL PASS"; else echo "END-TO-END TEST: $FAILS FAILED (logs in $LOGS)"; fi
exit $((FAILS > 0))
