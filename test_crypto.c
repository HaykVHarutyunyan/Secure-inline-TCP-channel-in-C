#include "crypto.h"
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>

static int hex(const char *s, uint8_t *out)
{
    size_t n = strlen(s) / 2;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(s + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
    return (int)n;
}

static int failures;
#define CHECK(cond, name) do { \
    if (cond) printf("  PASS  %s\n", name); \
    else { printf("  FAIL  %s\n", name); failures++; } } while (0)

int main(void)
{
    puts("AES-256-GCM:");

    /* NIST/McGrew-Viega GCM test case 16 (AES-256, 96-bit IV, with AAD). */
    uint8_t key[32], iv[12], aad[20], pt[60], ct_exp[60], tag_exp[16];
    hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", key);
    hex("cafebabefacedbaddecaf888", iv);
    hex("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad);
    hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", pt);
    hex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
        "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662", ct_exp);
    hex("76fc6ece0f4e1768cddf8853bb2d551b", tag_exp);

    uint8_t ct[60], tag[16], back[60];
    CHECK(encrypt_payload(key, iv, aad, sizeof(aad), pt, sizeof(pt), ct, tag) == 0 &&
          memcmp(ct, ct_exp, 60) == 0 && memcmp(tag, tag_exp, 16) == 0,
          "known-answer vector (ciphertext and tag)");
    CHECK(decrypt_payload(key, iv, aad, sizeof(aad), ct, sizeof(ct), tag, back) == 0 &&
          memcmp(back, pt, 60) == 0, "decrypt known-answer vector");

    /* Tamper detection: ciphertext, tag, AAD, nonce, key. */
    uint8_t bad[60];
    memcpy(bad, ct, 60); bad[0] ^= 1;
    CHECK(decrypt_payload(key, iv, aad, sizeof(aad), bad, 60, tag, back) != 0,
          "flipped ciphertext bit rejected");
    uint8_t badtag[16]; memcpy(badtag, tag, 16); badtag[15] ^= 0x80;
    CHECK(decrypt_payload(key, iv, aad, sizeof(aad), ct, 60, badtag, back) != 0,
          "flipped tag bit rejected");
    uint8_t badaad[20]; memcpy(badaad, aad, 20); badaad[3] ^= 1;
    CHECK(decrypt_payload(key, iv, badaad, sizeof(badaad), ct, 60, tag, back) != 0,
          "modified AAD rejected");
    uint8_t badiv[12]; memcpy(badiv, iv, 12); badiv[11] ^= 1;
    CHECK(decrypt_payload(key, badiv, aad, sizeof(aad), ct, 60, tag, back) != 0,
          "wrong nonce rejected");
    uint8_t badkey[32]; memcpy(badkey, key, 32); badkey[0] ^= 1;
    CHECK(decrypt_payload(badkey, iv, aad, sizeof(aad), ct, 60, tag, back) != 0,
          "wrong key rejected");

    /* In-place operation and odd sizes (what the packet layer relies on). */
    int inplace_ok = 1;
    for (size_t n = 1; n <= 1500; n += 37) {
        uint8_t buf[1500], orig[1500], t[16];
        RAND_bytes(orig, (int)n);
        memcpy(buf, orig, n);
        if (encrypt_payload(key, iv, aad, 20, buf, n, buf, t) != 0 ||
            memcmp(buf, orig, n) == 0 ||
            decrypt_payload(key, iv, aad, 20, buf, n, t, buf) != 0 ||
            memcmp(buf, orig, n) != 0)
            inplace_ok = 0;
    }
    CHECK(inplace_ok, "in-place encrypt/decrypt for many payload sizes");

    /* Empty plaintext still authenticates the AAD. */
    uint8_t t0[16];
    CHECK(encrypt_payload(key, iv, aad, 20, NULL, 0, ct, t0) == 0 &&
          decrypt_payload(key, iv, aad, 20, NULL, 0, t0, back) == 0,
          "empty plaintext with AAD");

    puts(failures ? "AES-GCM tests: FAIL" : "AES-GCM tests: ALL PASS");
    return failures ? 1 : 0;
}
