#include "handshake.h"
#include <openssl/crypto.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define PORT_OK    39555
#define PORT_BADPS 39556
#define PORT_JUNK  39557

static int failures;
#define CHECK(cond, name) do { \
    if (cond) printf("  PASS  %s\n", name); \
    else { printf("  FAIL  %s\n", name); failures++; } } while (0)

typedef struct { uint16_t port; const char *psk; unsigned timeout; session_keys_t keys; int result; } srv_t;

static srv_t make_srv(uint16_t port, const char *psk, unsigned timeout)
{
    srv_t s;
    memset(&s, 0, sizeof(s));
    s.port = port; s.psk = psk; s.timeout = timeout; s.result = -1;
    return s;
}

static void *server_thread(void *arg)
{
    srv_t *s = arg;
    s->result = handshake_server(s->port, s->psk, &s->keys, s->timeout, NULL);
    return NULL;
}

static int all_zero(const void *p, size_t n)
{
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++) if (b[i]) return 0;
    return 1;
}

int main(void)
{
    puts("X25519 handshake:");

    /* 1. Matching PSK: both sides derive identical, distinct directional keys. */
    {
        srv_t s = make_srv(PORT_OK, "classroom-demo-password", 10);
        session_keys_t c;
        pthread_t th;
        pthread_create(&th, NULL, server_thread, &s);
        int cr = handshake_client("127.0.0.1", PORT_OK, "classroom-demo-password", &c, 10, NULL);
        pthread_join(th, NULL);

        CHECK(cr == 0 && s.result == 0, "handshake succeeds with matching PSK");
        CHECK(CRYPTO_memcmp(&c, &s.keys, sizeof(c)) == 0, "both devices derive identical session keys");
        CHECK(CRYPTO_memcmp(c.pc1_to_pc2.key, c.pc2_to_pc1.key, KEY_SIZE) != 0,
              "the two directions use different keys");
        CHECK(!all_zero(c.pc1_to_pc2.key, KEY_SIZE) && !all_zero(c.pc2_to_pc1.salt, NONCE_SALT_SIZE),
              "keys and salts are populated");
    }

    /* 2. Fresh keys for every session (ephemeral DH). */
    {
        session_keys_t k1, k2;
        srv_t s1 = make_srv(PORT_OK, "classroom-demo-password", 10);
        pthread_t th;
        pthread_create(&th, NULL, server_thread, &s1);
        handshake_client("127.0.0.1", PORT_OK, "classroom-demo-password", &k1, 10, NULL);
        pthread_join(th, NULL);
        srv_t s2 = make_srv(PORT_OK, "classroom-demo-password", 10);
        pthread_create(&th, NULL, server_thread, &s2);
        handshake_client("127.0.0.1", PORT_OK, "classroom-demo-password", &k2, 10, NULL);
        pthread_join(th, NULL);
        CHECK(CRYPTO_memcmp(k1.pc1_to_pc2.key, k2.pc1_to_pc2.key, KEY_SIZE) != 0,
              "a new session yields new keys");
    }

    /* 3. Wrong PSK: client rejects the server and no keys are accepted. */
    {
        srv_t s = make_srv(PORT_BADPS, "server-side-secret-1", 3);
        session_keys_t c;
        memset(&c, 0, sizeof(c));
        pthread_t th;
        pthread_create(&th, NULL, server_thread, &s);
        int cr = handshake_client("127.0.0.1", PORT_BADPS, "different-secret-22", &c, 5, NULL);
        pthread_join(th, NULL);
        CHECK(cr != 0 && s.result != 0, "handshake fails with different PSKs on both sides");
        CHECK(all_zero(&c, sizeof(c)), "no key material released on authentication failure");
    }

    /* 4. Junk connection must not abort the server; a real client still works. */
    {
        srv_t s = make_srv(PORT_JUNK, "classroom-demo-password", 10);
        pthread_t th;
        pthread_create(&th, NULL, server_thread, &s);
        usleep(300 * 1000);

        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(PORT_JUNK) };
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        if (connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0) {
            const char junk[] = "GET / HTTP/1.0\r\n\r\n";
            send(fd, junk, sizeof(junk) - 1, 0);
            close(fd);
        }

        session_keys_t c;
        int cr = handshake_client("127.0.0.1", PORT_JUNK, "classroom-demo-password", &c, 10, NULL);
        pthread_join(th, NULL);
        CHECK(cr == 0 && s.result == 0 && CRYPTO_memcmp(&c, &s.keys, sizeof(c)) == 0,
              "garbage connection is ignored, real handshake still succeeds");
    }

    /* 5. Short PSK refused. */
    {
        session_keys_t c;
        CHECK(handshake_client("127.0.0.1", PORT_OK, "short", &c, 1, NULL) != 0,
              "PSK shorter than 8 characters refused");
    }

    puts(failures ? "Handshake tests: FAIL" : "Handshake tests: ALL PASS");
    return failures ? 1 : 0;
}
