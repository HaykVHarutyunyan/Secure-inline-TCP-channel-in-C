/*
 * Shared NFQUEUE packet engine used by both devices.
 *
 * The Linux kernel routes the packets (ip_forward=1); an iptables rule in the
 * FORWARD chain hands the selected TCP packets to this program, which rewrites
 * them and returns them with an ACCEPT verdict, so they leave through the
 * normal routing path towards the peer device / destination host.
 */
#include "engine.h"
#include "cli.h"
#include "common.h"
#include "packet.h"

#include <arpa/inet.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef enum { DIR_NONE = 0, DIR_FWD, DIR_REV } flow_dir_t;   /* FWD = PC1->PC2 */

typedef struct {
    unsigned long long encrypted, decrypted, passed, unselected, mss_clamped;
    unsigned long long drop_malformed, drop_auth, drop_replay, drop_other;
    unsigned long long queue_overruns;
} stats_t;

typedef struct {
    const engine_config_t *cfg;
    tx_state_t tx;
    rx_state_t rx;
    stats_t st;
    uint8_t buf[MAX_PACKET_SIZE + 64] __attribute__((aligned(8)));
    unsigned logged_drops;
} engine_t;

static uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

/* Decide whether (and in which direction) a packet belongs to the channel. */
static flow_dir_t classify(const engine_t *e, const uint8_t *pkt, size_t len)
{
    if (len < 20 || (pkt[0] >> 4) != 4 || pkt[9] != 6 /* TCP */)
        return DIR_NONE;

    struct in_addr src, dst;
    memcpy(&src, pkt + 12, 4);
    memcpy(&dst, pkt + 16, 4);

    flow_dir_t dir = DIR_NONE;
    if (src.s_addr == e->cfg->pc1.s_addr && dst.s_addr == e->cfg->pc2.s_addr)
        dir = DIR_FWD;
    else if (src.s_addr == e->cfg->pc2.s_addr && dst.s_addr == e->cfg->pc1.s_addr)
        dir = DIR_REV;
    else
        return DIR_NONE;

    if (e->cfg->tcp_port) {
        size_t ihl = (size_t)(pkt[0] & 0x0f) * 4;
        /* Fragments carry no (reliable) port: keep them selected so that the
         * packet layer rejects them instead of leaking them in clear text. */
        if ((be16(pkt + 6) & 0x3fff) == 0 && ihl >= 20 && len >= ihl + 4) {
            uint16_t sport = be16(pkt + ihl), dport = be16(pkt + ihl + 2);
            uint16_t server_port = (dir == DIR_FWD) ? dport : sport;
            if (server_port != e->cfg->tcp_port)
                return DIR_NONE;
        }
    }
    return dir;
}

static const char *result_name(int r)
{
    switch (r) {
    case PKT_ERR_MALFORMED: return "malformed/fragmented packet";
    case PKT_ERR_AUTH:      return "authentication tag mismatch";
    case PKT_ERR_REPLAY:    return "replayed or too old packet";
    case PKT_ERR_EXHAUSTED: return "nonce counter exhausted (restart devices to re-key)";
    case PKT_ERR_CAPACITY:  return "packet too large";
    default:                return "crypto error";
    }
}

static void note_drop(engine_t *e, int r, int encrypting)
{
    switch (r) {
    case PKT_ERR_MALFORMED: e->st.drop_malformed++; break;
    case PKT_ERR_AUTH:      e->st.drop_auth++;      break;
    case PKT_ERR_REPLAY:    e->st.drop_replay++;    break;
    default:                e->st.drop_other++;     break;
    }
    if (e->cfg->verbose || e->logged_drops < 20) {
        e->logged_drops++;
        fprintf(stderr, "drop (%s): %s\n", encrypting ? "encrypt" : "decrypt",
                result_name(r));
    }
}

static int on_packet(struct nfq_q_handle *qh, struct nfgenmsg *msg,
                     struct nfq_data *nfa, void *user)
{
    (void)msg;
    engine_t *e = user;

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph)
        return -1;
    uint32_t id = ntohl(ph->packet_id);

    unsigned char *data = NULL;
    int n = nfq_get_payload(nfa, &data);
    if (n <= 0 || (size_t)n > MAX_PACKET_SIZE) {
        e->st.drop_malformed++;
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }

    uint8_t *pkt = e->buf;
    size_t len = (size_t)n;
    memcpy(pkt, data, len);

    flow_dir_t dir = classify(e, pkt, len);
    if (dir == DIR_NONE) {
        e->st.unselected++;
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    int changed = 0, r;

    /*
     * Device1 sees the SYN and SYN-ACK of every connection (in both
     * directions).  Reducing the MSS by the 24 added bytes keeps the
     * protected packets within the path MTU, so nothing is fragmented and no
     * TCP sequence/ACK translation is needed: the peer device removes the
     * extra bytes again before the packet reaches the end host.
     */
    if (e->cfg->role == ROLE_DEVICE1) {
        r = adjust_tcp_mss(pkt, len, PACKET_OVERHEAD);
        if (r < 0) {
            note_drop(e, r, 0);
            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        }
        if (r == PKT_MODIFIED) { changed = 1; e->st.mss_clamped++; }
    }

    int encrypting = (e->cfg->role == ROLE_DEVICE1) == (dir == DIR_FWD);

    if (encrypting)
        r = encrypt_packet(pkt, &len, sizeof(e->buf), &e->tx);
    else
        r = decrypt_packet(pkt, &len, sizeof(e->buf), &e->rx);

    if (r < 0) {
        note_drop(e, r, encrypting);
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }

    if (r == PKT_MODIFIED) {
        changed = 1;
        if (encrypting) e->st.encrypted++; else e->st.decrypted++;
    } else {
        e->st.passed++;
    }

    if (!changed)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    return nfq_set_verdict(qh, id, NF_ACCEPT, (uint32_t)len, pkt);
}

static void print_stats(const engine_t *e)
{
    const stats_t *s = &e->st;
    fprintf(stderr,
        "\nstatistics[Device%d]: encrypted=%llu decrypted=%llu passed(no payload)=%llu "
        "mss_clamped=%llu unselected=%llu\n"
        "            dropped: auth=%llu replay=%llu malformed=%llu other=%llu "
        "queue_overruns=%llu\n"
        "            next tx nonce counter=%llu\n",
        (int)e->cfg->role,
        s->encrypted, s->decrypted, s->passed, s->mss_clamped, s->unselected,
        s->drop_auth, s->drop_replay, s->drop_malformed, s->drop_other,
        s->queue_overruns, (unsigned long long)e->tx.counter);
}

int engine_run(const engine_config_t *cfg, volatile sig_atomic_t *stop)
{
    static engine_t engine;             /* large buffer: keep off the stack */
    engine_t *e = &engine;
    memset(e, 0, sizeof(*e));
    e->cfg = cfg;

    if (cfg->role == ROLE_DEVICE1) {
        tx_state_init(&e->tx, cfg->keys->pc1_to_pc2.key, cfg->keys->pc1_to_pc2.salt);
        rx_state_init(&e->rx, cfg->keys->pc2_to_pc1.key, cfg->keys->pc2_to_pc1.salt);
    } else {
        tx_state_init(&e->tx, cfg->keys->pc2_to_pc1.key, cfg->keys->pc2_to_pc1.salt);
        rx_state_init(&e->rx, cfg->keys->pc1_to_pc2.key, cfg->keys->pc1_to_pc2.salt);
    }

    struct nfq_handle *h = nfq_open();
    if (!h) {
        fprintf(stderr, "nfq_open failed (need root and the nfnetlink_queue module)\n");
        return -1;
    }

    /* No-ops on current kernels; kept for old ones. Errors are not fatal. */
    nfq_unbind_pf(h, AF_INET);
    if (nfq_bind_pf(h, AF_INET) < 0)
        fprintf(stderr, "warning: nfq_bind_pf failed (continuing)\n");

    struct nfq_q_handle *qh = nfq_create_queue(h, cfg->queue_num, on_packet, e);
    if (!qh) {
        fprintf(stderr, "cannot create NFQUEUE %u (already in use?)\n", cfg->queue_num);
        nfq_close(h);
        return -1;
    }
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "cannot set NFQUEUE copy mode\n");
        nfq_destroy_queue(qh);
        nfq_close(h);
        return -1;
    }
    nfq_set_queue_maxlen(qh, 4096);

    int fd = nfq_fd(h);
    int rcvbuf = 4 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf)) < 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    fprintf(stderr, "Device%d running on NFQUEUE %u: session established, "
            "protected traffic enabled.\n", (int)cfg->role, cfg->queue_num);

    static char rbuf[MAX_PACKET_SIZE + 8192];
    while (!*stop) {
        if (g_dump_stats) { g_dump_stats = 0; print_stats(e); }
        ssize_t got = recv(fd, rbuf, sizeof(rbuf), 0);
        if (got >= 0) {
            nfq_handle_packet(h, rbuf, (int)got);
        } else if (errno == EINTR) {
            continue;
        } else if (errno == ENOBUFS) {
            e->st.queue_overruns++;     /* kernel dropped packets: fail closed */
        } else {
            perror("recv(nfqueue)");
            break;
        }
    }

    print_stats(e);
    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}
