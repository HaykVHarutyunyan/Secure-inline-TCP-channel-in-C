/*
 * Device1: sits next to PC1.
 *   PC1 -> [Device1] -> Device2 -> PC2   : TCP payload is encrypted here
 *   PC1 <- [Device1] <- Device2 <- PC2   : TCP payload is decrypted here
 *
 * Device1 is the handshake initiator (client).
 */
#include "cli.h"
#include "common.h"
#include "engine.h"
#include "handshake.h"

#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: sudo %s [options] DEVICE2_IP PC1_IP PC2_IP [PSK]\n"
        "\n"
        "  DEVICE2_IP  address of Device2 on the inter-device link\n"
        "  PC1_IP      address of PC1 (protected flow source side)\n"
        "  PC2_IP      address of PC2 (protected flow destination side)\n"
        "  PSK         pre-shared key (min 8 chars); safer: -f FILE or SIC_PSK\n"
        "\n"
        "Options:\n"
        "  -p PORT     protect only flows whose PC2-side TCP port is PORT (0 = all)\n"
        "  -q NUM      NFQUEUE number (default 0)\n"
        "  -H PORT     handshake TCP port on Device2 (default %d)\n"
        "  -f FILE     read PSK from first line of FILE\n"
        "  -v          log every dropped packet\n",
        prog, HANDSHAKE_PORT);
}

int main(int argc, char **argv)
{
    unsigned port = 0, queue = 0, hs_port = HANDSHAKE_PORT;
    const char *psk_file = NULL;
    int verbose = 0, opt;

    while ((opt = getopt(argc, argv, "p:q:H:f:vh")) != -1) {
        switch (opt) {
        case 'p': if (cli_parse_port(optarg, &port))    { usage(argv[0]); return 1; } break;
        case 'q': if (cli_parse_port(optarg, &queue))   { usage(argv[0]); return 1; } break;
        case 'H': if (cli_parse_port(optarg, &hs_port)) { usage(argv[0]); return 1; } break;
        case 'f': psk_file = optarg; break;
        case 'v': verbose = 1; break;
        default:  usage(argv[0]); return opt == 'h' ? 0 : 1;
        }
    }

    int n = argc - optind;
    if (n < 3 || n > 4) { usage(argv[0]); return 1; }

    const char *device2_ip = argv[optind];
    engine_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = ROLE_DEVICE1;
    if (cli_parse_ipv4(argv[optind + 1], &cfg.pc1) ||
        cli_parse_ipv4(argv[optind + 2], &cfg.pc2)) {
        fprintf(stderr, "Invalid PC1/PC2 IP address\n");
        return 1;
    }
    cfg.tcp_port = (uint16_t)port;
    cfg.queue_num = (uint16_t)queue;
    cfg.verbose = verbose;

    char psk[256];
    if (cli_load_psk(n == 4 ? argv[optind + 3] : NULL, psk_file, psk, sizeof(psk)))
        return 1;

    cli_install_signals();

    static session_keys_t keys;
    fprintf(stderr, "Device1: handshake with Device2 (%s:%u) ...\n", device2_ip, hs_port);
    if (handshake_client(device2_ip, (uint16_t)hs_port, psk, &keys, 60, &g_stop) != 0) {
        fprintf(stderr, "Handshake failed\n");
        OPENSSL_cleanse(psk, sizeof(psk));
        return 1;
    }
    OPENSSL_cleanse(psk, sizeof(psk));
    fprintf(stderr, "Device1: X25519 handshake complete, session keys derived.\n");

    cfg.keys = &keys;
    int rc = engine_run(&cfg, &g_stop) == 0 ? 0 : 1;

    OPENSSL_cleanse(&keys, sizeof(keys));
    return rc;
}
