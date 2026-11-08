CC      ?= gcc
CFLAGS  ?= -O2
CFLAGS  += -Wall -Wextra -Wshadow -std=gnu11 -D_GNU_SOURCE

CORE    = crypto.c handshake.c packet.c
NFQ_CFLAGS := $(shell pkg-config --cflags libnetfilter_queue 2>/dev/null)
NFQ_LIBS   := $(shell pkg-config --libs libnetfilter_queue 2>/dev/null || echo -lnetfilter_queue -lnfnetlink)

all: device1 device2

device1: device1.c engine.c cli.c $(CORE) $(wildcard *.h)
	$(CC) $(CFLAGS) $(NFQ_CFLAGS) -o $@ device1.c engine.c cli.c $(CORE) $(NFQ_LIBS) -lcrypto

device2: device2.c engine.c cli.c $(CORE) $(wildcard *.h)
	$(CC) $(CFLAGS) $(NFQ_CFLAGS) -o $@ device2.c engine.c cli.c $(CORE) $(NFQ_LIBS) -lcrypto

# Unit tests need only OpenSSL (no libnetfilter_queue, no root).
test_crypto: test_crypto.c crypto.c $(wildcard *.h)
	$(CC) $(CFLAGS) -o $@ test_crypto.c crypto.c -lcrypto

test_handshake: test_handshake.c handshake.c $(wildcard *.h)
	$(CC) $(CFLAGS) -o $@ test_handshake.c handshake.c -lcrypto -pthread

test_packet: test_packet.c packet.c crypto.c $(wildcard *.h)
	$(CC) $(CFLAGS) -o $@ test_packet.c packet.c crypto.c -lcrypto

test: test_crypto test_handshake test_packet
	./test_crypto
	./test_handshake
	./test_packet

# End-to-end test in four network namespaces (needs root, iptables, iproute2).
e2e: all
	sudo scripts/e2e_test.sh

clean:
	rm -f device1 device2 test_crypto test_handshake test_packet *.o

.PHONY: all test e2e clean
