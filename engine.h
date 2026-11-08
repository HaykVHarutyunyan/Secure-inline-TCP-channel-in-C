#ifndef ENGINE_H
#define ENGINE_H

#include "handshake.h"
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>

typedef enum {
    ROLE_DEVICE1 = 1,   /* PC1 side: encrypts PC1->PC2, decrypts PC2->PC1 */
    ROLE_DEVICE2 = 2    /* PC2 side: decrypts PC1->PC2, encrypts PC2->PC1 */
} device_role_t;

typedef struct {
    device_role_t role;
    struct in_addr pc1;             /* network order */
    struct in_addr pc2;
    uint16_t tcp_port;              /* 0 = every TCP port between PC1 and PC2;
                                       otherwise only flows whose PC2-side
                                       port (server port) equals this value  */
    uint16_t queue_num;             /* NFQUEUE number                         */
    int verbose;                    /* log every dropped packet               */
    const session_keys_t *keys;
} engine_config_t;

/*
 * Run the NFQUEUE packet loop until *stop becomes non-zero.
 * Returns 0 on clean shutdown, -1 on setup failure.  Prints statistics on exit.
 */
int engine_run(const engine_config_t *cfg, volatile sig_atomic_t *stop);

#endif
