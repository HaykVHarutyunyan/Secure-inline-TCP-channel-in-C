#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include "common.h"
#include <signal.h>
#include <stdint.h>

/* Key material for ONE traffic direction. */
typedef struct {
    uint8_t key[KEY_SIZE];              /* AES-256-GCM key                  */
    uint8_t salt[NONCE_SALT_SIZE];      /* fixed 4-byte nonce prefix        */
} direction_keys_t;

/*
 * Session keys shared by Device1 and Device2.
 * Each direction has its own key, so a (key, nonce) pair is only ever used by
 * a single sender.
 */
typedef struct {
    direction_keys_t pc1_to_pc2;        /* Device1 encrypts, Device2 decrypts */
    direction_keys_t pc2_to_pc1;        /* Device2 encrypts, Device1 decrypts */
} session_keys_t;

/*
 * Diffie-Hellman handshake (X25519, ephemeral keys on both sides).
 *
 *   Device1 (client)                              Device2 (server)
 *   ---------------------------------------------------------------
 *   "SIC2" || pubC                      ------->
 *                                       <-------  pubS || salt || MAC_s
 *   MAC_c                               ------->
 *
 *   MAC_s / MAC_c = HMAC-SHA256(PSK, transcript || "server"/"client")
 *   session keys  = HKDF-SHA256(X25519(privA, pubB), salt, pubC||pubS)
 *
 * The PSK only authenticates the exchange (stops a man in the middle); the
 * traffic keys come from the ephemeral DH secret, so they are fresh for
 * every session.
 *
 * `stop` may be NULL; when it becomes non-zero the call returns -1.
 * handshake_client retries connecting for `connect_timeout_s` seconds.
 * handshake_server keeps accepting until one peer authenticates successfully,
 * so a stray or malicious connection cannot abort the device;
 * `accept_timeout_s` == 0 means wait forever.
 */
int handshake_client(const char *device2_ip, uint16_t port, const char *psk,
                     session_keys_t *out, unsigned connect_timeout_s,
                     volatile sig_atomic_t *stop);

int handshake_server(uint16_t port, const char *psk, session_keys_t *out,
                     unsigned accept_timeout_s,
                     volatile sig_atomic_t *stop);

#endif
