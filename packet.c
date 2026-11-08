#include "packet.h"
#include "crypto.h"

#include <openssl/crypto.h>
#include <string.h>

#define IPPROTO_TCP_NUM 6
#define AAD_LEN         16      /* saddr, daddr, sport, dport, seq */

/* ------------------------------------------------------------- helpers */

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static void     wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

static uint64_t rd64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}
static void wr64(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--) { p[i] = (uint8_t)v; v >>= 8; }
}

static uint32_t csum_add(uint32_t sum, const uint8_t *d, size_t n)
{
    while (n > 1) { sum += ((uint32_t)d[0] << 8) | d[1]; d += 2; n -= 2; }
    if (n) sum += (uint32_t)d[0] << 8;
    return sum;
}

static uint16_t csum_fold(uint32_t sum)
{
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

/*
 * Recompute IP header checksum and TCP checksum from scratch.
 * (A mangled NFQUEUE packet is sent out as-is, so the full, final checksum
 * must be written - not a pseudo-header partial sum.)
 */
static void fix_checksums(uint8_t *pkt, size_t len, size_t ihl)
{
    uint8_t *tcp = pkt + ihl;
    size_t tcp_len = len - ihl;

    wr16(pkt + 10, 0);
    wr16(pkt + 10, csum_fold(csum_add(0, pkt, ihl)));

    wr16(tcp + 16, 0);
    uint8_t pseudo[4] = { 0, IPPROTO_TCP_NUM,
                          (uint8_t)(tcp_len >> 8), (uint8_t)tcp_len };
    uint32_t sum = csum_add(0, pkt + 12, 8);        /* saddr + daddr */
    sum = csum_add(sum, pseudo, sizeof(pseudo));
    sum = csum_add(sum, tcp, tcp_len);
    wr16(tcp + 16, csum_fold(sum));
}

int ipv4_tcp_checksums_ok(const uint8_t *pkt, size_t len)
{
    if (len < 40) return 0;
    size_t ihl = (size_t)(pkt[0] & 0x0f) * 4;
    if (ihl < 20 || len < ihl + 20) return 0;
    size_t tcp_len = len - ihl;

    if (csum_fold(csum_add(0, pkt, ihl)) != 0) return 0;

    uint8_t pseudo[4] = { 0, IPPROTO_TCP_NUM,
                          (uint8_t)(tcp_len >> 8), (uint8_t)tcp_len };
    uint32_t sum = csum_add(0, pkt + 12, 8);
    sum = csum_add(sum, pseudo, sizeof(pseudo));
    sum = csum_add(sum, pkt + ihl, tcp_len);
    return csum_fold(sum) == 0;
}

/* -------------------------------------------------------- packet parse */

typedef struct {
    size_t ihl;             /* IP header length in bytes            */
    size_t tcp_hl;          /* TCP header length in bytes           */
    size_t off;             /* offset of TCP payload                */
    size_t plen;            /* TCP payload length                   */
} view_t;

/*
 * Returns 1 for a well-formed IPv4/TCP packet, 0 for anything that is not
 * IPv4/TCP (left alone by the caller), PKT_ERR_MALFORMED otherwise.
 * Also trims *len to the IP total length (drops link-layer padding).
 */
static int parse_tcp(const uint8_t *pkt, size_t *len, view_t *v)
{
    if (*len < 1) return PKT_ERR_MALFORMED;
    if ((pkt[0] >> 4) != 4) return 0;
    if (*len < 20) return PKT_ERR_MALFORMED;
    if (pkt[9] != IPPROTO_TCP_NUM) return 0;

    size_t ihl = (size_t)(pkt[0] & 0x0f) * 4;
    size_t tot = rd16(pkt + 2);

    if (ihl < 20 || tot > *len || tot < ihl + 20)
        return PKT_ERR_MALFORMED;

    /* Fragments cannot be protected safely: fail closed. */
    if (rd16(pkt + 6) & 0x3fff)
        return PKT_ERR_MALFORMED;

    size_t tcp_hl = (size_t)(pkt[ihl + 12] >> 4) * 4;
    if (tcp_hl < 20 || tot < ihl + tcp_hl)
        return PKT_ERR_MALFORMED;

    *len = tot;
    v->ihl = ihl;
    v->tcp_hl = tcp_hl;
    v->off = ihl + tcp_hl;
    v->plen = tot - v->off;
    return 1;
}

/* AAD = IP saddr || IP daddr || TCP sport || TCP dport || TCP seq */
static void build_aad(const uint8_t *pkt, const view_t *v, uint8_t aad[AAD_LEN])
{
    memcpy(aad, pkt + 12, 8);
    memcpy(aad + 8, pkt + v->ihl, 4);
    memcpy(aad + 12, pkt + v->ihl + 4, 4);
}

static void build_nonce(uint8_t nonce[NONCE_SIZE],
                        const uint8_t salt[NONCE_SALT_SIZE], uint64_t counter)
{
    memcpy(nonce, salt, NONCE_SALT_SIZE);
    wr64(nonce + NONCE_SALT_SIZE, counter);
}

/* ---------------------------------------------------------- state init */

void tx_state_init(tx_state_t *tx, const uint8_t key[KEY_SIZE],
                   const uint8_t salt[NONCE_SALT_SIZE])
{
    memset(tx, 0, sizeof(*tx));
    memcpy(tx->key, key, KEY_SIZE);
    memcpy(tx->salt, salt, NONCE_SALT_SIZE);
}

void rx_state_init(rx_state_t *rx, const uint8_t key[KEY_SIZE],
                   const uint8_t salt[NONCE_SALT_SIZE])
{
    memset(rx, 0, sizeof(*rx));
    memcpy(rx->key, key, KEY_SIZE);
    memcpy(rx->salt, salt, NONCE_SALT_SIZE);
}

/* -------------------------------------------------------- replay window */

static int replay_ok(const rx_state_t *rx, uint64_t c)
{
    if (!rx->started || c > rx->highest) return 1;
    if (rx->highest - c >= REPLAY_WINDOW) return 0;         /* too old */
    unsigned i = (unsigned)(c % REPLAY_WINDOW);
    return !((rx->bitmap[i / 64] >> (i % 64)) & 1);
}

static void replay_mark(rx_state_t *rx, uint64_t c)
{
    if (!rx->started) {
        memset(rx->bitmap, 0, sizeof(rx->bitmap));
        rx->started = 1;
        rx->highest = c;
    } else if (c > rx->highest) {
        uint64_t d = c - rx->highest;
        if (d >= REPLAY_WINDOW) {
            memset(rx->bitmap, 0, sizeof(rx->bitmap));
        } else {
            for (uint64_t k = 1; k <= d; k++) {
                unsigned j = (unsigned)((rx->highest + k) % REPLAY_WINDOW);
                rx->bitmap[j / 64] &= ~(1ULL << (j % 64));
            }
        }
        rx->highest = c;
    }
    unsigned i = (unsigned)(c % REPLAY_WINDOW);
    rx->bitmap[i / 64] |= 1ULL << (i % 64);
}

/* ------------------------------------------------------------- encrypt */

int encrypt_packet(uint8_t *pkt, size_t *len, size_t capacity, tx_state_t *tx)
{
    view_t v;
    int r = parse_tcp(pkt, len, &v);
    if (r < 0) return r;
    if (r == 0 || v.plen == 0) return PKT_UNCHANGED;

    if (*len + PACKET_OVERHEAD > capacity || *len + PACKET_OVERHEAD > 65535)
        return PKT_ERR_CAPACITY;

    /* Never wrap: counter value 2^64-1 is not used. */
    if (tx->counter == UINT64_MAX)
        return PKT_ERR_EXHAUSTED;

    /* Take the nonce first and burn it even if encryption later fails. */
    uint64_t counter = tx->counter++;
    uint8_t nonce[NONCE_SIZE], aad[AAD_LEN], tag[TAG_SIZE];
    build_nonce(nonce, tx->salt, counter);
    build_aad(pkt, &v, aad);

    uint8_t *payload = pkt + v.off;

    /* Make room for the explicit nonce, then encrypt in place behind it. */
    memmove(payload + EXPLICIT_NONCE_SIZE, payload, v.plen);
    wr64(payload, counter);

    uint8_t *cipher = payload + EXPLICIT_NONCE_SIZE;
    if (encrypt_payload(tx->key, nonce, aad, sizeof(aad),
                        cipher, v.plen, cipher, tag) != 0)
        return PKT_ERR_CRYPTO;

    memcpy(cipher + v.plen, tag, TAG_SIZE);

    *len += PACKET_OVERHEAD;
    wr16(pkt + 2, (uint16_t)*len);
    fix_checksums(pkt, *len, v.ihl);
    return PKT_MODIFIED;
}

/* ------------------------------------------------------------- decrypt */

int decrypt_packet(uint8_t *pkt, size_t *len, size_t capacity, rx_state_t *rx)
{
    (void)capacity;     /* the packet only shrinks */

    view_t v;
    int r = parse_tcp(pkt, len, &v);
    if (r < 0) return r;
    if (r == 0 || v.plen == 0) return PKT_UNCHANGED;

    /* Every honest payload is nonce + at least 1 byte + tag. */
    if (v.plen <= PACKET_OVERHEAD)
        return PKT_ERR_MALFORMED;

    uint8_t *payload = pkt + v.off;
    uint64_t counter = rd64(payload);

    if (!replay_ok(rx, counter))
        return PKT_ERR_REPLAY;

    size_t clen = v.plen - PACKET_OVERHEAD;
    uint8_t *cipher = payload + EXPLICIT_NONCE_SIZE;
    uint8_t tag[TAG_SIZE], nonce[NONCE_SIZE], aad[AAD_LEN];

    memcpy(tag, cipher + clen, TAG_SIZE);
    build_nonce(nonce, rx->salt, counter);
    build_aad(pkt, &v, aad);

    if (decrypt_payload(rx->key, nonce, aad, sizeof(aad),
                        cipher, clen, tag, cipher) != 0)
        return PKT_ERR_AUTH;

    /* Only authenticated packets may move the replay window. */
    replay_mark(rx, counter);

    memmove(payload, cipher, clen);
    *len -= PACKET_OVERHEAD;
    wr16(pkt + 2, (uint16_t)*len);
    fix_checksums(pkt, *len, v.ihl);
    return PKT_MODIFIED;
}

/* ------------------------------------------------------------ MSS clamp */

int adjust_tcp_mss(uint8_t *pkt, size_t len, unsigned delta)
{
    view_t v;
    int r = parse_tcp(pkt, &len, &v);
    if (r < 0) return r;
    if (r == 0) return PKT_UNCHANGED;

    uint8_t *tcp = pkt + v.ihl;
    if (!(tcp[13] & 0x02))              /* SYN flag (also set on SYN-ACK) */
        return PKT_UNCHANGED;

    uint8_t *opt = tcp + 20;
    size_t opt_len = v.tcp_hl - 20;
    int changed = 0;

    for (size_t i = 0; i < opt_len;) {
        uint8_t kind = opt[i];
        if (kind == 0) break;           /* end of options */
        if (kind == 1) { i++; continue; }
        if (i + 1 >= opt_len || opt[i + 1] < 2 || i + opt[i + 1] > opt_len)
            return PKT_ERR_MALFORMED;

        uint8_t olen = opt[i + 1];
        if (kind == 2 && olen == 4) {
            unsigned mss = rd16(opt + i + 2);
            if (mss > delta) {
                wr16(opt + i + 2, (uint16_t)(mss - delta));
                changed = 1;
            }
        }
        i += olen;
    }

    if (changed)
        fix_checksums(pkt, len, v.ihl);
    return changed ? PKT_MODIFIED : PKT_UNCHANGED;
}
