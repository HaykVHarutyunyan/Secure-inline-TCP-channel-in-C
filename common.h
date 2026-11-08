#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

/* AES-256-GCM parameters */
#define KEY_SIZE        32      /* AES-256 key                               */
#define NONCE_SIZE      12      /* full GCM IV = salt(4) || counter(8)        */
#define TAG_SIZE        16      /* GCM authentication tag                     */

/*
 * Nonce construction (same idea as RFC 4106, AES-GCM in IPsec ESP):
 *
 *     nonce[12] = salt[4]  ||  counter[8, big endian]
 *
 *  - salt    : 4 bytes derived from the DH exchange, per direction, never sent
 *  - counter : 64-bit per-direction packet counter, starts at 0 for every new
 *              session and is incremented for every encrypted packet.  It is
 *              the only nonce part that travels in the packet.
 *
 * A new DH handshake gives fresh keys, so (key, nonce) can never repeat.
 */
#define NONCE_SALT_SIZE     4
#define EXPLICIT_NONCE_SIZE 8

/*
 * Protected TCP payload on the wire:
 *
 *     explicit_nonce[8]  ||  ciphertext[n]  ||  tag[16]
 *
 * i.e. n + 24 bytes for an n byte plaintext payload.  The IP and TCP headers
 * are untouched (only IP total length and the two checksums are recomputed).
 */
#define PACKET_OVERHEAD (EXPLICIT_NONCE_SIZE + TAG_SIZE)

#define MAX_PACKET_SIZE   65535
#define HANDSHAKE_PORT    39001

#endif
