#include "cli.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

volatile sig_atomic_t g_stop = 0;
volatile sig_atomic_t g_dump_stats = 0;

static void on_signal(int sig)
{
    if (sig == SIGUSR1)
        g_dump_stats = 1;
    else
        g_stop = 1;
}

void cli_install_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;                    /* no SA_RESTART on purpose */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
}

int cli_parse_ipv4(const char *text, struct in_addr *out)
{
    return inet_pton(AF_INET, text, out) == 1 ? 0 : -1;
}

int cli_parse_port(const char *text, unsigned *out)
{
    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul(text, &end, 10);
    if (errno || end == text || *end != '\0' || v > 65535)
        return -1;
    *out = (unsigned)v;
    return 0;
}

int cli_load_psk(const char *arg, const char *file, char *out, size_t out_size)
{
    const char *src = NULL;

    if (arg && *arg) {
        src = arg;
    } else if (file && *file) {
        FILE *f = fopen(file, "r");
        if (!f) {
            fprintf(stderr, "cannot open PSK file '%s': %s\n", file, strerror(errno));
            return -1;
        }
        if (!fgets(out, (int)out_size, f)) {
            fclose(f);
            fprintf(stderr, "PSK file '%s' is empty\n", file);
            return -1;
        }
        fclose(f);
        out[strcspn(out, "\r\n")] = '\0';
        return 0;
    } else if (getenv("SIC_PSK") && *getenv("SIC_PSK")) {
        src = getenv("SIC_PSK");
    }

    if (!src) {
        fprintf(stderr, "no PSK given (argument, -f FILE or SIC_PSK)\n");
        return -1;
    }
    if (strlen(src) >= out_size) {
        fprintf(stderr, "PSK too long\n");
        return -1;
    }
    strcpy(out, src);
    return 0;
}
