#ifndef PACKET_H
#define PACKET_H

#include "common.h"
#include <stddef.h>
#include <stdint.h>

/* Anti-replay window size in packets (RFC 6479 style bitmap ring). */
#define REPLAY_WINDOW 1024

/* Results of encrypt_packet() / decrypt_packet(). */
enum {
    PKT_UNCHANGED       =  0,   /* not IPv4/TCP, or TCP without payload      */
    PKT_MODIFIED        =  1,   /* packet was rewritten, forward the new one */
    PKT_ERR_MALFORMED   = -1,   /* truncated, fragmented, bad lengths        */
    PKT_ERR_AUTH        = -2,   /* GCM tag did not verify                    */
    PKT_ERR_REPLAY      = -3,   /* counter already seen / too old            */
    PKT_ERR_EXHAUSTED   = -4,   /* 64-bit nonce counter used up              */
    PKT_ERR_CAPACITY    = -5,   /* packet would exceed buffer / 65535 bytes  */
    PKT_ERR_CRYPTO      = -6    /* crypto library failure                    */
};

/* Sender side of one direction. */
typedef struct {
    uint8_t  key[KEY_SIZE];
    uint8_t  salt[NONCE_SALT_SIZE];
    uint64_t counter;           /* next nonce counter; starts at 0 per session */
} tx_state_t;

/* Receiver side of one direction. */
typedef struct {
    uint8_t  key[KEY_SIZE];
    uint8_t  salt[NONCE_SALT_SIZE];
    int      started;
    uint64_t highest;           /* highest authenticated counter so far */
    uint64_t bitmap[REPLAY_WINDOW / 64];
} rx_state_t;

void tx_state_init(tx_state_t *tx, const uint8_t key[KEY_SIZE],
                   const uint8_t salt[NONCE_SALT_SIZE]);
void rx_state_init(rx_state_t *rx, const uint8_t key[KEY_SIZE],
                   const uint8_t salt[NONCE_SALT_SIZE]);

/*
 * Protect the TCP payload of an IPv4 packet in place:
 *
 *   IP hdr | TCP hdr | payload            (unchanged headers)
 *   IP hdr | TCP hdr | nonce8 | ciphertext | tag16
 *
 * The 12-byte GCM nonce is salt[4] || counter[8]; the counter is incremented
 * for every call that encrypts, so no nonce is ever used twice per session.
 * The IP source/destination, TCP ports and TCP sequence number are fed to
 * GCM as additional authenticated data, so a protected payload cannot be
 * moved to another flow or sequence position.
 *
 * IP total length, IP header checksum and TCP checksum are recomputed.
 * On error the buffer content is undefined and the packet must be dropped.
 */
int encrypt_packet(uint8_t *packet, size_t *packet_len, size_t capacity,
                   tx_state_t *tx);

/*
 * Inverse of encrypt_packet(): checks the replay window, verifies the GCM tag,
 * restores the original packet and recomputes IP total length and checksums.
 * A packet with TCP payload that does not authenticate is an error.
 */
int decrypt_packet(uint8_t *packet, size_t *packet_len, size_t capacity,
                   rx_state_t *rx);

/*
 * Lower the MSS option of a TCP SYN / SYN-ACK by `delta` bytes so that the
 * added nonce+tag still fit into the path MTU.  Returns PKT_MODIFIED if an
 * option was changed.
 */
int adjust_tcp_mss(uint8_t *packet, size_t packet_len, unsigned delta);

/* Helpers (also used by tests). */
int ipv4_tcp_checksums_ok(const uint8_t *packet, size_t packet_len);

#endif
