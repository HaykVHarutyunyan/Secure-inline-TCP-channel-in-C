#include "handshake.h"
#include "common.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define IO_TIMEOUT_S  5
#define PSK_MIN_LEN   8

static const uint8_t HELLO_MAGIC[4] = { 'S', 'I', 'C', '2' };
static const char    KDF_LABEL[]    = "SIC2 session keys";

/* ------------------------------------------------------------------ I/O */

static int send_all(int fd, const void *data, size_t length)
{
    const unsigned char *p = data;
    while (length > 0) {
        ssize_t n = send(fd, p, length, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        p += n;
        length -= (size_t)n;
    }
    return 0;
}

static int receive_all(int fd, void *data, size_t length)
{
    unsigned char *p = data;
    while (length > 0) {
        ssize_t n = recv(fd, p, length, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        p += n;
        length -= (size_t)n;
    }
    return 0;
}

static void set_io_timeout(int fd)
{
    struct timeval tv = { .tv_sec = IO_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* ------------------------------------------------------------- crypto */

static int generate_x25519(uint8_t private_key[32], uint8_t public_key[32])
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *key = NULL;
    size_t private_len = 32, public_len = 32;
    int result = -1;

    if (!ctx) return -1;
    if (EVP_PKEY_keygen_init(ctx) <= 0) goto done;
    if (EVP_PKEY_keygen(ctx, &key) <= 0) goto done;
    if (EVP_PKEY_get_raw_private_key(key, private_key, &private_len) <= 0) goto done;
    if (EVP_PKEY_get_raw_public_key(key, public_key, &public_len) <= 0) goto done;
    if (private_len == 32 && public_len == 32)
        result = 0;
done:
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return result;
}

/*
 * X25519 shared secret -> HKDF-SHA256 -> 72 bytes:
 *   [ 0..31] key  Device1 -> Device2      [64..67] salt Device1 -> Device2
 *   [32..63] key  Device2 -> Device1      [68..71] salt Device2 -> Device1
 */
static int derive_keys(const uint8_t private_key[32],
                       const uint8_t pub_client[32],
                       const uint8_t pub_server[32],
                       int is_server,
                       const uint8_t salt[32],
                       session_keys_t *out)
{
    const uint8_t *peer_public = is_server ? pub_client : pub_server;
    EVP_PKEY *local = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_key, 32);
    EVP_PKEY *peer  = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_public, 32);
    EVP_PKEY_CTX *dh = NULL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kdf_ctx = NULL;
    uint8_t secret[32], okm[72], info[sizeof(KDF_LABEL) - 1 + 64];
    uint8_t zero[32] = { 0 };
    size_t secret_len = sizeof(secret);
    int result = -1;

    if (!local || !peer) goto done;

    dh = EVP_PKEY_CTX_new(local, NULL);
    if (!dh || EVP_PKEY_derive_init(dh) <= 0 ||
        EVP_PKEY_derive_set_peer(dh, peer) <= 0 ||
        EVP_PKEY_derive(dh, secret, &secret_len) <= 0 ||
        secret_len != 32)
        goto done;

    /* Reject low-order peer points (all-zero shared secret). */
    if (CRYPTO_memcmp(secret, zero, 32) == 0) goto done;

    memcpy(info, KDF_LABEL, sizeof(KDF_LABEL) - 1);
    memcpy(info + sizeof(KDF_LABEL) - 1, pub_client, 32);
    memcpy(info + sizeof(KDF_LABEL) - 1 + 32, pub_server, 32);

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    kdf_ctx = kdf ? EVP_KDF_CTX_new(kdf) : NULL;
    if (!kdf_ctx) goto done;

    char digest[] = "SHA256";
    char mode[]   = "EXTRACT_AND_EXPAND";
    OSSL_PARAM params[6];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, mode, 0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, secret, sizeof(secret));
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, 32);
    params[4] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, sizeof(info));
    params[5] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kdf_ctx, okm, sizeof(okm), params) != 1)
        goto done;

    memcpy(out->pc1_to_pc2.key,  okm,      KEY_SIZE);
    memcpy(out->pc2_to_pc1.key,  okm + 32, KEY_SIZE);
    memcpy(out->pc1_to_pc2.salt, okm + 64, NONCE_SALT_SIZE);
    memcpy(out->pc2_to_pc1.salt, okm + 68, NONCE_SALT_SIZE);
    result = 0;

done:
    OPENSSL_cleanse(secret, sizeof(secret));
    OPENSSL_cleanse(okm, sizeof(okm));
    EVP_KDF_CTX_free(kdf_ctx);
    EVP_KDF_free(kdf);
    EVP_PKEY_CTX_free(dh);
    EVP_PKEY_free(local);
    EVP_PKEY_free(peer);
    return result;
}

/* HMAC-SHA256(psk, transcript || role) */
static int make_mac(const char *psk, const uint8_t transcript[104],
                    const char *role, uint8_t mac[32])
{
    uint8_t msg[104 + 6];
    unsigned int mac_len = 0;

    memcpy(msg, transcript, 104);
    memcpy(msg + 104, role, 6);             /* "server" or "client" */
    return HMAC(EVP_sha256(), psk, (int)strlen(psk), msg, sizeof(msg),
                mac, &mac_len) && mac_len == 32 ? 0 : -1;
}

static void build_transcript(uint8_t t[104], const uint8_t pub_client[32],
                             const uint8_t pub_server[32], const uint8_t salt[32])
{
    static const uint8_t label[8] = { 'S', 'I', 'C', '-', 'v', '2', 0, 0 };
    memcpy(t, label, 8);
    memcpy(t + 8, pub_client, 32);
    memcpy(t + 40, pub_server, 32);
    memcpy(t + 72, salt, 32);
}

/* -------------------------------------------------------- protocol run */

static int run_client(int fd, const char *psk, session_keys_t *out)
{
    uint8_t priv[32], pub_c[32], pub_s[32], salt[32], t[104];
    uint8_t mac_s[32], mac_s_rx[32], mac_c[32];
    uint8_t hello[36];
    int result = -1;

    if (generate_x25519(priv, pub_c) != 0) goto done;

    memcpy(hello, HELLO_MAGIC, 4);
    memcpy(hello + 4, pub_c, 32);
    if (send_all(fd, hello, sizeof(hello)) != 0 ||
        receive_all(fd, pub_s, 32) != 0 ||
        receive_all(fd, salt, 32) != 0 ||
        receive_all(fd, mac_s_rx, 32) != 0)
        goto done;

    build_transcript(t, pub_c, pub_s, salt);
    if (make_mac(psk, t, "server", mac_s) != 0 ||
        CRYPTO_memcmp(mac_s, mac_s_rx, 32) != 0) {
        fprintf(stderr, "handshake: server authentication failed (wrong PSK?)\n");
        goto done;
    }

    if (make_mac(psk, t, "client", mac_c) != 0 ||
        send_all(fd, mac_c, 32) != 0)
        goto done;

    if (derive_keys(priv, pub_c, pub_s, 0, salt, out) != 0) goto done;
    result = 0;
done:
    OPENSSL_cleanse(priv, sizeof(priv));
    return result;
}

static int run_server(int fd, const char *psk, session_keys_t *out)
{
    uint8_t priv[32], pub_s[32], pub_c[32], salt[32], t[104];
    uint8_t mac_s[32], mac_c[32], mac_c_rx[32];
    uint8_t hello[36];
    int result = -1;

    if (receive_all(fd, hello, sizeof(hello)) != 0 ||
        memcmp(hello, HELLO_MAGIC, 4) != 0)
        goto done;
    memcpy(pub_c, hello + 4, 32);

    if (generate_x25519(priv, pub_s) != 0 || RAND_bytes(salt, 32) != 1)
        goto done;

    build_transcript(t, pub_c, pub_s, salt);
    if (make_mac(psk, t, "server", mac_s) != 0 ||
        send_all(fd, pub_s, 32) != 0 ||
        send_all(fd, salt, 32) != 0 ||
        send_all(fd, mac_s, 32) != 0)
        goto done;

    if (make_mac(psk, t, "client", mac_c) != 0 ||
        receive_all(fd, mac_c_rx, 32) != 0 ||
        CRYPTO_memcmp(mac_c, mac_c_rx, 32) != 0) {
        fprintf(stderr, "handshake: client authentication failed\n");
        goto done;
    }

    if (derive_keys(priv, pub_c, pub_s, 1, salt, out) != 0) goto done;
    result = 0;
done:
    OPENSSL_cleanse(priv, sizeof(priv));
    return result;
}

/* ----------------------------------------------------------- sockets */

static int check_psk(const char *psk)
{
    if (!psk || strlen(psk) < PSK_MIN_LEN) {
        fprintf(stderr, "handshake: PSK must be at least %d characters\n", PSK_MIN_LEN);
        return -1;
    }
    return 0;
}

static int stopped(volatile sig_atomic_t *stop)
{
    return stop && *stop;
}

int handshake_client(const char *device2_ip, uint16_t port, const char *psk,
                     session_keys_t *out, unsigned connect_timeout_s,
                     volatile sig_atomic_t *stop)
{
    struct sockaddr_in addr;
    time_t deadline = time(NULL) + connect_timeout_s;

    if (check_psk(psk) != 0) return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, device2_ip, &addr.sin_addr) != 1) {
        fprintf(stderr, "handshake: bad Device2 address '%s'\n", device2_ip);
        return -1;
    }

    for (;;) {
        if (stopped(stop)) return -1;

        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        set_io_timeout(fd);

        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            int r = run_client(fd, psk, out);
            close(fd);
            return r;
        }
        close(fd);

        if (time(NULL) >= deadline) {
            fprintf(stderr, "handshake: cannot reach Device2 at %s:%u\n",
                    device2_ip, port);
            return -1;
        }
        usleep(500 * 1000);     /* Device2 may still be starting */
    }
}

int handshake_server(uint16_t port, const char *psk, session_keys_t *out,
                     unsigned accept_timeout_s,
                     volatile sig_atomic_t *stop)
{
    struct sockaddr_in addr;
    time_t deadline = accept_timeout_s ? time(NULL) + accept_timeout_s : 0;
    int one = 1, result = -1;

    if (check_psk(psk) != 0) return -1;

    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) return -1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(server, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(server, 4) < 0) {
        perror("handshake: bind/listen");
        close(server);
        return -1;
    }

    while (!stopped(stop)) {
        if (deadline && time(NULL) >= deadline) break;

        struct pollfd pfd = { .fd = server, .events = POLLIN };
        int pr = poll(&pfd, 1, 250);
        if (pr <= 0) continue;                  /* timeout or EINTR */

        int fd = accept(server, NULL, NULL);
        if (fd < 0) continue;
        set_io_timeout(fd);

        /* A failed attempt (garbage, wrong PSK, port scan) just waits for
         * the next connection instead of killing the device. */
        int r = run_server(fd, psk, out);
        close(fd);
        if (r == 0) { result = 0; break; }
    }

    close(server);
    return result;
}
