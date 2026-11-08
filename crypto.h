#ifndef CRYPTO_H
#define CRYPTO_H

#include "common.h"
#include <stddef.h>
#include <stdint.h>

/*
 * AES-256-GCM.  `aad` is authenticated but not encrypted (may be NULL when
 * aad_len == 0).  `plain` and `cipher` may be the same buffer (in-place).
 * Returns 0 on success, -1 on failure.
 */
int encrypt_payload(const uint8_t key[KEY_SIZE],
                    const uint8_t nonce[NONCE_SIZE],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *plain, size_t plain_len,
                    uint8_t *cipher, uint8_t tag[TAG_SIZE]);

/*
 * Returns 0 only if the tag verifies.  On failure the contents of `plain`
 * must be discarded.
 */
int decrypt_payload(const uint8_t key[KEY_SIZE],
                    const uint8_t nonce[NONCE_SIZE],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *cipher, size_t cipher_len,
                    const uint8_t tag[TAG_SIZE],
                    uint8_t *plain);

#endif
