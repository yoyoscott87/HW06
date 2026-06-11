CC      = gcc
CFLAGS  = -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto -lpthread

all: vpn_server vpn_client

vpn_server: vpn_server.c common.h
	$(CC) $(CFLAGS) -o $@ vpn_server.c $(LDFLAGS)

vpn_client: vpn_client.c common.h
	$(CC) $(CFLAGS) -o $@ vpn_client.c $(LDFLAGS)

clean:
	rm -f vpn_server vpn_client

.PHONY: all clean
