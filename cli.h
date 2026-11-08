#ifndef CLI_H
#define CLI_H

#include <netinet/in.h>
#include <signal.h>
#include <stddef.h>

/* Set to 1 by SIGINT/SIGTERM. */
extern volatile sig_atomic_t g_stop;

/* Set to 1 by SIGUSR1: ask the engine to print its statistics. */
extern volatile sig_atomic_t g_dump_stats;

/* Install SIGINT/SIGTERM/SIGUSR1 handlers (without SA_RESTART so blocking calls
 * return EINTR) and ignore SIGPIPE. */
void cli_install_signals(void);

/* Parse a dotted-quad IPv4 address. Returns 0 on success. */
int cli_parse_ipv4(const char *text, struct in_addr *out);

/* Parse a TCP/UDP port number 0..65535. Returns 0 on success. */
int cli_parse_port(const char *text, unsigned *out);

/*
 * PSK lookup order: explicit argument, then file (first line), then the
 * SIC_PSK environment variable.  (Command-line arguments are visible to every
 * user through `ps`, so the file / environment routes are preferred.)
 * Returns 0 on success.
 */
int cli_load_psk(const char *arg, const char *file, char *out, size_t out_size);

#endif
