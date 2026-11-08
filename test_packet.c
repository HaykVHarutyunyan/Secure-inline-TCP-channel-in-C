/*
 * Packet-layer tests: layout, header preservation, checksums, nonce
 * uniqueness, tamper/replay rejection, edge cases, MSS clamp.
 * Checksums are verified with an independent implementation in this file.
 */
#include "packet.h"
#include "crypto.h"
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
#define CHECK(cond, name) do { \
    if (cond) printf("  PASS  %s\n", name); \
    else { printf("  FAIL  %s\n", name); failures++; } } while (0)

/* ------------------------- independent checksum code ------------------- */

static uint32_t ones(const uint8_t *p, size_t n)
{
    uint32_t s = 0;
    for (size_t i = 0; i + 1 < n; i += 2) s += (uint32_t)(p[i] << 8 | p[i + 1]);
    if (n & 1) s += (uint32_t)p[n - 1] << 8;
    return s;
}
static uint16_t fold(uint32_t s) { while (s >> 16) s = (s & 0xffff) + (s >> 16); return (uint16_t)s; }

static int csum_valid(const uint8_t *pkt, size_t len)
{
    size_t ihl = (pkt[0] & 15) * 4, tl = len - ihl;
    if (fold(ones(pkt, ihl)) != 0xffff) return 0;
    uint8_t ph[12];
    memcpy(ph, pkt + 12, 8); ph[8] = 0; ph[9] = 6; ph[10] = (uint8_t)(tl >> 8); ph[11] = (uint8_t)tl;
    return fold(ones(ph, 12) + ones(pkt + ihl, tl)) == 0xffff;
}

static void csum_set(uint8_t *pkt, size_t len)
{
    size_t ihl = (pkt[0] & 15) * 4, tl = len - ihl;
    pkt[10] = pkt[11] = 0;
    uint16_t c = (uint16_t)~fold(ones(pkt, ihl));
    pkt[10] = (uint8_t)(c >> 8); pkt[11] = (uint8_t)c;
    uint8_t *t = pkt + ihl; t[16] = t[17] = 0;
    uint8_t ph[12];
    memcpy(ph, pkt + 12, 8); ph[8] = 0; ph[9] = 6; ph[10] = (uint8_t)(tl >> 8); ph[11] = (uint8_t)tl;
    c = (uint16_t)~fold(ones(ph, 12) + ones(t, tl));
    t[16] = (uint8_t)(c >> 8); t[17] = (uint8_t)c;
}

/* ------------------------------ packet builder -------------------------- */

typedef struct {
    uint32_t seq, ack;
    uint16_t sport, dport;
    uint8_t flags;
    unsigned ip_opt_bytes;          /* multiple of 4 */
    const uint8_t *tcp_opts;        /* multiple of 4 bytes */
    unsigned tcp_opt_bytes;
} spec_t;

static size_t build(uint8_t *b, size_t cap, const spec_t *s, const uint8_t *pl, size_t plen)
{
    size_t ihl = 20 + s->ip_opt_bytes, thl = 20 + s->tcp_opt_bytes, tot = ihl + thl + plen;
    if (tot > cap) abort();
    memset(b, 0, cap);
    b[0] = (uint8_t)(0x40 | (ihl / 4));
    b[2] = (uint8_t)(tot >> 8); b[3] = (uint8_t)tot;
    b[4] = 0x12; b[5] = 0x34; b[6] = 0x40;                     /* DF */
    b[8] = 63; b[9] = 6;
    b[12] = 10; b[13] = 0; b[14] = 1; b[15] = 2;               /* 10.0.1.2 */
    b[16] = 10; b[17] = 0; b[18] = 3; b[19] = 2;               /* 10.0.3.2 */
    for (unsigned i = 0; i < s->ip_opt_bytes; i++) b[20 + i] = 1;   /* NOPs */
    uint8_t *t = b + ihl;
    t[0] = (uint8_t)(s->sport >> 8); t[1] = (uint8_t)s->sport;
    t[2] = (uint8_t)(s->dport >> 8); t[3] = (uint8_t)s->dport;
    for (int i = 0; i < 4; i++) { t[4 + i] = (uint8_t)(s->seq >> (24 - 8 * i)); t[8 + i] = (uint8_t)(s->ack >> (24 - 8 * i)); }
    t[12] = (uint8_t)((thl / 4) << 4); t[13] = s->flags;
    t[14] = 0xff; t[15] = 0xff;
    if (s->tcp_opt_bytes) memcpy(t + 20, s->tcp_opts, s->tcp_opt_bytes);
    if (plen) memcpy(t + thl, pl, plen);
    csum_set(b, tot);
    return tot;
}

static spec_t dflt(void)
{
    spec_t s = { .seq = 0x11223344, .ack = 0x55667788, .sport = 40000, .dport = 5001,
                 .flags = 0x18 /* PSH|ACK */ };
    return s;
}

#define CAP 2048
static uint8_t KEY[32], SALT[4] = { 0xde, 0xad, 0xbe, 0xef };

static void fresh(tx_state_t *tx, rx_state_t *rx)
{
    tx_state_init(tx, KEY, SALT);
    rx_state_init(rx, KEY, SALT);
}

/* ---------------------------------- tests -------------------------------- */

static void test_roundtrip_layout(void)
{
    puts("Round trip, layout and header preservation:");
    static const size_t sizes[] = { 1, 2, 15, 16, 17, 100, 536, 1000, 1432, 1460 };
    int rt_ok = 1, csum_ok = 1, hdr_ok = 1, len_ok = 1, fmt_ok = 1;

    for (size_t k = 0; k < sizeof(sizes) / sizeof(*sizes); k++) {
        for (int variant = 0; variant < 3; variant++) {
            spec_t s = dflt();
            static const uint8_t ts_opts[12] = { 1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2 };
            if (variant == 1) { s.tcp_opts = ts_opts; s.tcp_opt_bytes = 12; }
            if (variant == 2) { s.tcp_opts = ts_opts; s.tcp_opt_bytes = 12; s.ip_opt_bytes = 8; }
            size_t plen = sizes[k];
            uint8_t pl[1500], pkt[CAP], orig[CAP];
            RAND_bytes(pl, (int)plen);
            size_t len = build(pkt, CAP, &s, pl, plen), olen = len;
            memcpy(orig, pkt, len);
            size_t ihl = 20 + s.ip_opt_bytes, hdrs = ihl + 20 + s.tcp_opt_bytes;

            tx_state_t tx; rx_state_t rx; fresh(&tx, &rx);

            int r = encrypt_packet(pkt, &len, CAP, &tx);
            if (r != PKT_MODIFIED) { rt_ok = 0; continue; }
            if (len != olen + PACKET_OVERHEAD) len_ok = 0;
            if (((pkt[2] << 8) | pkt[3]) != (int)len) len_ok = 0;
            if (!csum_valid(pkt, len)) csum_ok = 0;

            /* IP header (except total length / checksum) and TCP header (except checksum) intact */
            for (size_t i = 0; i < hdrs; i++) {
                int skip = (i == 2 || i == 3 || i == 10 || i == 11 || i == ihl + 16 || i == ihl + 17);
                if (!skip && pkt[i] != orig[i]) hdr_ok = 0;
            }

            /* Payload = nonce8(counter 0) || AES-GCM ciphertext || tag, built independently. */
            uint8_t nonce[12], aad[16], ct[1500], tag[16], expect_ctr[8] = { 0 };
            memcpy(nonce, SALT, 4); memset(nonce + 4, 0, 8);
            memcpy(aad, orig + 12, 8); memcpy(aad + 8, orig + ihl, 4); memcpy(aad + 12, orig + ihl + 4, 4);
            encrypt_payload(KEY, nonce, aad, 16, pl, plen, ct, tag);
            if (memcmp(pkt + hdrs, expect_ctr, 8) != 0 ||
                memcmp(pkt + hdrs + 8, ct, plen) != 0 ||
                memcmp(pkt + hdrs + 8 + plen, tag, 16) != 0 ||
                memcmp(pkt + hdrs + 8, pl, plen) == 0)
                fmt_ok = 0;

            r = decrypt_packet(pkt, &len, CAP, &rx);
            if (r != PKT_MODIFIED || len != olen || memcmp(pkt, orig, olen) != 0) rt_ok = 0;
            if (!csum_valid(pkt, len)) csum_ok = 0;
        }
    }
    CHECK(rt_ok,  "decrypt(encrypt(p)) restores the exact original packet (1..1460 B, TCP/IP options)");
    CHECK(len_ok, "length grows by exactly 24 bytes (8 nonce + 16 tag); IP total length updated");
    CHECK(hdr_ok, "IP and TCP headers preserved (only length + checksums differ)");
    CHECK(fmt_ok, "payload layout is counter8 || AES-256-GCM ciphertext || tag16, ciphertext != plaintext");
    CHECK(csum_ok, "IP and TCP checksums valid after encryption and after decryption");
}

static void test_nonce_uniqueness(void)
{
    puts("Nonce uniqueness:");
    enum { N = 200000 };
    tx_state_t tx; rx_state_t rx; fresh(&tx, &rx);
    spec_t s = dflt();
    uint8_t pl[64] = "identical payload every time, identical headers, identical seq";
    int seq_ok = 1, ct_distinct = 1;
    uint8_t prev_ct[64] = { 0 };

    for (uint64_t i = 0; i < N; i++) {
        uint8_t pkt[CAP];
        size_t len = build(pkt, CAP, &s, pl, sizeof(pl));
        if (encrypt_packet(pkt, &len, CAP, &tx) != PKT_MODIFIED) { seq_ok = 0; break; }
        const uint8_t *c = pkt + 40;
        uint64_t ctr = 0;
        for (int b = 0; b < 8; b++) ctr = (ctr << 8) | c[b];
        if (ctr != i) seq_ok = 0;
        if (i > 0 && memcmp(prev_ct, c + 8, 64) == 0) ct_distinct = 0;
        memcpy(prev_ct, c + 8, 64);
    }
    CHECK(seq_ok, "200000 packets use counters 0..199999: no nonce ever repeats");
    CHECK(ct_distinct, "identical plaintext/headers never yield identical ciphertext");
    CHECK(tx.counter == N, "counter advanced once per encrypted packet");

    /* A retransmission (same seq, same data) is a new packet -> new nonce. */
    uint8_t a[CAP], b[CAP]; size_t la = build(a, CAP, &s, pl, 64), lb = build(b, CAP, &s, pl, 64);
    encrypt_packet(a, &la, CAP, &tx); encrypt_packet(b, &lb, CAP, &tx);
    CHECK(memcmp(a + 40, b + 40, 8) != 0, "retransmission of same segment gets a fresh nonce");

    /* Packets without payload consume no nonce. */
    uint64_t before = tx.counter;
    spec_t ack = dflt(); ack.flags = 0x10;
    uint8_t p[CAP]; size_t lp = build(p, CAP, &ack, NULL, 0);
    int r = encrypt_packet(p, &lp, CAP, &tx);
    CHECK(r == PKT_UNCHANGED && tx.counter == before, "payload-less ACK passes through, no nonce consumed");

    /* Exhaustion: refuse rather than wrap. */
    tx.counter = UINT64_MAX - 1;
    lp = build(p, CAP, &s, pl, 64); r = encrypt_packet(p, &lp, CAP, &tx);
    int r2 = (lp = build(p, CAP, &s, pl, 64), encrypt_packet(p, &lp, CAP, &tx));
    CHECK(r == PKT_MODIFIED && r2 == PKT_ERR_EXHAUSTED, "counter exhaustion is refused (never wraps)");
}

static void test_tamper(void)
{
    puts("Authentication / tamper detection:");
    spec_t s = dflt();
    uint8_t pl[200]; RAND_bytes(pl, sizeof(pl));
    uint8_t good[CAP]; size_t glen = build(good, CAP, &s, pl, sizeof(pl));
    tx_state_t tx; rx_state_t rx; fresh(&tx, &rx);
    encrypt_packet(good, &glen, CAP, &tx);
    size_t hdrs = 40;

    struct { const char *name; size_t off; uint8_t xor; } muts[] = {
        { "flipped ciphertext bit",           hdrs + 8 + 5,     0x01 },
        { "flipped tag bit",                  glen - 1,         0x80 },
        { "modified explicit nonce/counter",  hdrs + 7,         0x01 },
        { "TCP sequence number changed (AAD)", 20 + 7,          0x01 },
        { "TCP destination port changed (AAD)", 20 + 3,         0x01 },
        { "TCP source port changed (AAD)",    20 + 1,           0x01 },
        { "IP source address changed (AAD)",  15,               0x01 },
        { "IP destination address changed (AAD)", 19,           0x01 },
    };
    for (size_t i = 0; i < sizeof(muts) / sizeof(*muts); i++) {
        uint8_t p[CAP]; size_t l = glen; memcpy(p, good, glen);
        p[muts[i].off] ^= muts[i].xor;
        rx_state_t r2; fresh(&tx, &r2);
        char name[96]; snprintf(name, sizeof(name), "%s rejected", muts[i].name);
        CHECK(decrypt_packet(p, &l, CAP, &r2) == PKT_ERR_AUTH, name);
    }

    { uint8_t p[CAP]; size_t l = glen; memcpy(p, good, glen);
      rx_state_t r2; uint8_t k2[32]; memcpy(k2, KEY, 32); k2[0] ^= 1; rx_state_init(&r2, k2, SALT);
      CHECK(decrypt_packet(p, &l, CAP, &r2) == PKT_ERR_AUTH, "wrong key rejected"); }
    { uint8_t p[CAP]; size_t l = glen; memcpy(p, good, glen);
      rx_state_t r2; uint8_t s2[4] = { 0, 0, 0, 0 }; rx_state_init(&r2, KEY, s2);
      CHECK(decrypt_packet(p, &l, CAP, &r2) == PKT_ERR_AUTH, "wrong nonce salt rejected"); }

    { /* unprotected (plaintext) data injected on the protected link */
      uint8_t p[CAP]; size_t l = build(p, CAP, &s, pl, sizeof(pl)); rx_state_t r2; fresh(&tx, &r2);
      CHECK(decrypt_packet(p, &l, CAP, &r2) == PKT_ERR_AUTH, "plaintext payload on protected link rejected");
      l = build(p, CAP, &s, pl, 10);
      CHECK(decrypt_packet(p, &l, CAP, &r2) == PKT_ERR_MALFORMED, "payload shorter than nonce+tag rejected");
      l = build(p, CAP, &s, pl, PACKET_OVERHEAD);
      CHECK(decrypt_packet(p, &l, CAP, &r2) == PKT_ERR_MALFORMED, "empty ciphertext (nonce+tag only) rejected"); }

    { /* the intact packet still decrypts */
      uint8_t p[CAP]; size_t l = glen; memcpy(p, good, glen); rx_state_t r2; fresh(&tx, &r2);
      CHECK(decrypt_packet(p, &l, CAP, &r2) == PKT_MODIFIED && memcmp(p + hdrs, pl, sizeof(pl)) == 0,
            "untampered packet decrypts correctly"); }
}

static void test_replay(void)
{
    puts("Replay protection:");
    enum { N = 2000 };
    static uint8_t pk[N][128]; static size_t pl_[N];
    spec_t s = dflt(); uint8_t pl[40] = "replay window test payload";
    tx_state_t tx; rx_state_t rx; fresh(&tx, &rx);
    for (int i = 0; i < N; i++) {
        s.seq = 1000 + (uint32_t)i * 40;
        pl_[i] = build(pk[i], sizeof(pk[i]), &s, pl, sizeof(pl));
        encrypt_packet(pk[i], &pl_[i], sizeof(pk[i]), &tx);
    }
    uint8_t w[128]; size_t l;
#define TRY(i) (memcpy(w, pk[i], pl_[i]), l = pl_[i], decrypt_packet(w, &l, sizeof(w), &rx))

    CHECK(TRY(0) == PKT_MODIFIED && TRY(1) == PKT_MODIFIED, "in-order packets accepted");
    CHECK(TRY(1) == PKT_ERR_REPLAY, "duplicate of a delivered packet rejected");
    CHECK(TRY(0) == PKT_ERR_REPLAY, "duplicate of the first packet rejected");

    { /* reordering inside the window */
      tx_state_t t2; rx_state_t r2; fresh(&t2, &r2);
      int ok = 1;
      for (int i = 9; i >= 0; i--) { memcpy(w, pk[i], pl_[i]); l = pl_[i]; if (decrypt_packet(w, &l, sizeof(w), &r2) != PKT_MODIFIED) ok = 0; }
      for (int i = 0; i < 10; i++)  { memcpy(w, pk[i], pl_[i]); l = pl_[i]; if (decrypt_packet(w, &l, sizeof(w), &r2) != PKT_ERR_REPLAY) ok = 0; }
      CHECK(ok, "reordered packets accepted once, then rejected as replays"); }

    { /* forged high counter must not move the window */
      tx_state_t t2; rx_state_t r2; fresh(&t2, &r2);
      memcpy(w, pk[5], pl_[5]); l = pl_[5];
      w[40 + 3] = 0xff;                                   /* counter -> huge */
      int bad = decrypt_packet(w, &l, sizeof(w), &r2);
      memcpy(w, pk[6], pl_[6]); l = pl_[6];
      CHECK(bad == PKT_ERR_AUTH && decrypt_packet(w, &l, sizeof(w), &r2) == PKT_MODIFIED,
            "forged packet does not advance the replay window"); }

    { /* window edge: 1024 packets */
      tx_state_t t2; rx_state_t r2; fresh(&t2, &r2);
      memcpy(w, pk[1999], pl_[1999]); l = pl_[1999];
      int a = decrypt_packet(w, &l, sizeof(w), &r2);
      memcpy(w, pk[0], pl_[0]); l = pl_[0];
      int old = decrypt_packet(w, &l, sizeof(w), &r2);
      memcpy(w, pk[975], pl_[975]); l = pl_[975];
      int edge_out = decrypt_packet(w, &l, sizeof(w), &r2);
      memcpy(w, pk[976], pl_[976]); l = pl_[976];
      int edge_in = decrypt_packet(w, &l, sizeof(w), &r2);
      CHECK(a == PKT_MODIFIED && old == PKT_ERR_REPLAY && edge_out == PKT_ERR_REPLAY && edge_in == PKT_MODIFIED,
            "packets older than the 1024-packet window rejected, newer ones accepted"); }
#undef TRY
}

static void test_edge_cases(void)
{
    puts("Edge cases:");
    tx_state_t tx; rx_state_t rx; fresh(&tx, &rx);
    spec_t s = dflt(); uint8_t pl[100]; RAND_bytes(pl, sizeof(pl));
    uint8_t p[CAP], o[CAP]; size_t l, ol;

    /* non-TCP / non-IPv4 */
    l = build(p, CAP, &s, pl, 100); p[9] = 17; ol = l; memcpy(o, p, l);
    CHECK(encrypt_packet(p, &l, CAP, &tx) == PKT_UNCHANGED && l == ol && !memcmp(p, o, l), "UDP packet left untouched");
    l = build(p, CAP, &s, pl, 100); p[0] = 0x65; ol = l; memcpy(o, p, l);
    CHECK(decrypt_packet(p, &l, CAP, &rx) == PKT_UNCHANGED && l == ol && !memcmp(p, o, l), "non-IPv4 packet left untouched");

    /* fragments are refused rather than leaked */
    l = build(p, CAP, &s, pl, 100); p[6] = 0x20;                        /* MF */
    CHECK(encrypt_packet(p, &l, CAP, &tx) == PKT_ERR_MALFORMED, "IP fragment (MF) refused");
    l = build(p, CAP, &s, pl, 100); p[6] = 0x00; p[7] = 0x10;           /* offset */
    CHECK(encrypt_packet(p, &l, CAP, &tx) == PKT_ERR_MALFORMED, "IP fragment (offset) refused");

    /* malformed lengths */
    l = build(p, CAP, &s, pl, 100); l -= 30;
    CHECK(encrypt_packet(p, &l, CAP, &tx) == PKT_ERR_MALFORMED, "packet shorter than IP total length refused");
    l = build(p, CAP, &s, pl, 100); p[0] = 0x44;
    CHECK(encrypt_packet(p, &l, CAP, &tx) == PKT_ERR_MALFORMED, "IP header length < 20 refused");
    l = build(p, CAP, &s, pl, 100); p[20 + 12] = 0x40;
    CHECK(encrypt_packet(p, &l, CAP, &tx) == PKT_ERR_MALFORMED, "TCP data offset < 5 refused");
    l = 10;
    CHECK(encrypt_packet(p, &l, CAP, &tx) == PKT_ERR_MALFORMED, "10-byte buffer refused");

    /* capacity */
    l = build(p, CAP, &s, pl, 100);
    CHECK(encrypt_packet(p, &l, l + 10, &tx) == PKT_ERR_CAPACITY, "insufficient buffer capacity refused");
    {
        static uint8_t big[70000]; static uint8_t bp[65535];
        memset(bp, 'A', sizeof(bp));
        size_t bl = 65535; spec_t b = dflt();
        /* build manually: 20+20+65495 payload = 65535 */
        memset(big, 0, sizeof(big));
        bl = build(big, sizeof(big), &b, bp, 65535 - 40);
        CHECK(encrypt_packet(big, &bl, sizeof(big), &tx) == PKT_ERR_CAPACITY, "packet that would exceed 65535 bytes refused");
    }

    /* link-layer padding after the IP datagram is dropped, not encrypted */
    {
        spec_t sp = dflt(); size_t pl_len = 1;
        l = build(p, CAP, &sp, pl, pl_len); ol = l;
        memset(p + l, 0, 18); l += 18;                                  /* Ethernet padding */
        tx_state_t t2; rx_state_t r2; fresh(&t2, &r2);
        int r = encrypt_packet(p, &l, CAP, &t2);
        int okc = csum_valid(p, l);
        int r3 = decrypt_packet(p, &l, CAP, &r2);
        CHECK(r == PKT_MODIFIED && okc && r3 == PKT_MODIFIED && l == ol && p[40] == pl[0],
              "trailing link-layer padding is trimmed; round trip still exact");
    }

    /* payload-carrying FIN / PSH / SYN-with-data are protected too */
    {
        int ok = 1;
        for (unsigned f = 0; f < 3; f++) {
            spec_t sp = dflt(); sp.flags = (uint8_t[]){ 0x19, 0x18, 0x02 }[f];
            l = build(p, CAP, &sp, pl, 50); ol = l; memcpy(o, p, l);
            tx_state_t t2; rx_state_t r2; fresh(&t2, &r2);
            if (encrypt_packet(p, &l, CAP, &t2) != PKT_MODIFIED || memcmp(p + 40 + 8, pl, 50) == 0) ok = 0;
            if (decrypt_packet(p, &l, CAP, &r2) != PKT_MODIFIED || memcmp(p, o, ol) != 0) ok = 0;
        }
        CHECK(ok, "FIN+data, PSH+data and SYN+data segments are protected and restored");
    }
}

static void test_mss(void)
{
    puts("MSS clamping:");
    static const uint8_t opts[20] = { 2, 4, 0x05, 0xb4,  4, 2,  8, 10, 1, 2, 3, 4, 5, 6, 7, 8,  1,  3, 3, 7 };
    uint8_t p[CAP], o[CAP]; size_t ol;
    spec_t s = dflt(); s.tcp_opts = opts; s.tcp_opt_bytes = 20;

    s.flags = 0x02;
    ol = build(p, CAP, &s, NULL, 0); memcpy(o, p, ol);
    int r = adjust_tcp_mss(p, ol, PACKET_OVERHEAD);
    unsigned mss = (p[40 + 2] << 8) | p[40 + 3];
    int rest = memcmp(p + 40 + 4, o + 40 + 4, 16) == 0;
    CHECK(r == PKT_MODIFIED && mss == 1460 - PACKET_OVERHEAD && rest && csum_valid(p, ol),
          "SYN: MSS 1460 -> 1436, other options intact, checksum valid");

    s.flags = 0x12;
    ol = build(p, CAP, &s, NULL, 0);
    r = adjust_tcp_mss(p, ol, PACKET_OVERHEAD);
    CHECK(r == PKT_MODIFIED && ((p[42] << 8) | p[43]) == 1436 && csum_valid(p, ol), "SYN-ACK is clamped too");

    s.flags = 0x10;
    ol = build(p, CAP, &s, NULL, 0); memcpy(o, p, ol);
    CHECK(adjust_tcp_mss(p, ol, PACKET_OVERHEAD) == PKT_UNCHANGED && !memcmp(p, o, ol), "non-SYN packet untouched");

    spec_t n = dflt(); n.flags = 0x02;
    ol = build(p, CAP, &n, NULL, 0);
    CHECK(adjust_tcp_mss(p, ol, PACKET_OVERHEAD) == PKT_UNCHANGED, "SYN without MSS option untouched");

    static const uint8_t bad[4] = { 2, 40, 0, 0 };
    spec_t b = dflt(); b.flags = 0x02; b.tcp_opts = bad; b.tcp_opt_bytes = 4;
    ol = build(p, CAP, &b, NULL, 0);
    CHECK(adjust_tcp_mss(p, ol, PACKET_OVERHEAD) == PKT_ERR_MALFORMED, "option with overrunning length refused");

    /* A full-size segment after clamping fits a 1500-byte MTU once protected. */
    uint8_t pl[1500]; memset(pl, 'x', sizeof(pl));
    spec_t d = dflt(); size_t seg = 1460 - PACKET_OVERHEAD;      /* sender honours clamped MSS */
    size_t l = build(p, CAP, &d, pl, seg);
    tx_state_t tx; rx_state_t rx; fresh(&tx, &rx);
    encrypt_packet(p, &l, CAP, &tx);
    CHECK(l == 1500, "clamped full-size segment becomes exactly 1500 bytes on the wire (fits MTU)");
}

int main(void)
{
    RAND_bytes(KEY, sizeof(KEY));
    test_roundtrip_layout();
    test_nonce_uniqueness();
    test_tamper();
    test_replay();
    test_edge_cases();
    test_mss();
    puts(failures ? "\nPacket tests: FAIL" : "\nPacket tests: ALL PASS");
    return failures ? 1 : 0;
}
