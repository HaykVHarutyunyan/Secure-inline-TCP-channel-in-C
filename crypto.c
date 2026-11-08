#include "crypto.h"

#include <limits.h>
#include <openssl/evp.h>

int encrypt_payload(const uint8_t key[KEY_SIZE],
                    const uint8_t nonce[NONCE_SIZE],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *plain, size_t plain_len,
                    uint8_t *cipher, uint8_t tag[TAG_SIZE])
{
    if (plain_len > INT_MAX || aad_len > INT_MAX)
        return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;

    int len = 0, total = 0, result = -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, NULL) != 1)
        goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto done;

    if (aad_len > 0 &&
        EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1)
        goto done;

    if (plain_len > 0) {
        if (EVP_EncryptUpdate(ctx, cipher, &len, plain, (int)plain_len) != 1)
            goto done;
        total = len;
    }

    if (EVP_EncryptFinal_ex(ctx, cipher + total, &len) != 1)
        goto done;
    total += len;
    if ((size_t)total != plain_len)
        goto done;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1)
        goto done;

    result = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

int decrypt_payload(const uint8_t key[KEY_SIZE],
                    const uint8_t nonce[NONCE_SIZE],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *cipher, size_t cipher_len,
                    const uint8_t tag[TAG_SIZE],
                    uint8_t *plain)
{
    if (cipher_len > INT_MAX || aad_len > INT_MAX)
        return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;

    int len = 0, total = 0, result = -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, NULL) != 1)
        goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto done;

    if (aad_len > 0 &&
        EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1)
        goto done;

    if (cipher_len > 0) {
        if (EVP_DecryptUpdate(ctx, plain, &len, cipher, (int)cipher_len) != 1)
            goto done;
        total = len;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
                            (void *)tag) != 1)
        goto done;

    /* Succeeds only if the authentication tag is valid. */
    if (EVP_DecryptFinal_ex(ctx, plain + total, &len) != 1)
        goto done;
    total += len;
    if ((size_t)total != cipher_len)
        goto done;

    result = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    return result;
}
