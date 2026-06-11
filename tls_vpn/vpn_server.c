/*
 * vpn_server.c - TLS VPN gateway (VM2, 192.168.2.1 / 172.16.0.0/24 side)
 *
 * Usage:
 *   sudo ./vpn_server [listen_port]
 *
 * Files expected in the current directory:
 *   server-cert.pem, server-key.pem  - this server's certificate/key
 *   ca-cert.pem                      - CA used to verify the client cert
 *
 * The program:
 *   1. Creates/configures the "tap0" device as 10.10.10.3/24
 *   2. Enables IP forwarding and adds FORWARD rules for the tunnel
 *   3. Listens for a TLS connection (mutual TLS) from vpn_client
 *   4. Relays Ethernet frames between tap0 and the TLS connection
 */
#include "common.h"

#define TAP_NAME    "tap0"
#define TAP_ADDR    "10.10.10.3/24"
#define DEFAULT_PORT 4433

#define SERVER_CERT "server-cert.pem"
#define SERVER_KEY  "server-key.pem"
#define CA_CERT     "ca-cert.pem"

static SSL_CTX *create_server_ctx(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "[!] server private key does not match certificate\n");
        exit(EXIT_FAILURE);
    }

    /* Mutual TLS: trust CA_CERT to verify the client certificate, and
     * reject any client that does not present one. */
    if (SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL) != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    return ctx;
}

static int setup_tap(void) {
    char dev[IFNAMSIZ];
    memset(dev, 0, sizeof(dev));
    strncpy(dev, TAP_NAME, IFNAMSIZ - 1);

    int fd = tun_alloc(dev, IFF_TAP | IFF_NO_PI);
    if (fd < 0) {
        fprintf(stderr, "[!] failed to create TAP device (are you root?)\n");
        exit(EXIT_FAILURE);
    }
    printf("[*] created TAP device: %s\n", dev);

    run_cmd("ip link set dev %s up", dev);
    run_cmd("ip addr add %s dev %s", TAP_ADDR, dev);

    return fd;
}

/* Enable IP forwarding and allow traffic between the VPN subnet and the
 * internal 172.16.0.0/24 network behind this gateway. */
static void setup_forwarding(void) {
    run_cmd("sysctl -w net.ipv4.ip_forward=1");
    run_cmd("iptables -C FORWARD -i %s -s 10.10.10.0/24 -d 172.16.0.0/24 -j ACCEPT 2>/dev/null "
            "|| iptables -A FORWARD -i %s -s 10.10.10.0/24 -d 172.16.0.0/24 -j ACCEPT",
            TAP_NAME, TAP_NAME);
    run_cmd("iptables -C FORWARD -o %s -d 10.10.10.0/24 -s 172.16.0.0/24 -j ACCEPT 2>/dev/null "
            "|| iptables -A FORWARD -o %s -d 10.10.10.0/24 -s 172.16.0.0/24 -j ACCEPT",
            TAP_NAME, TAP_NAME);
}

static int tcp_listen(int port) {
    int sockfd;
    struct sockaddr_in addr;
    int opt = 1;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); exit(EXIT_FAILURE); }

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((uint16_t)port);

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); exit(EXIT_FAILURE);
    }
    if (listen(sockfd, 1) < 0) {
        perror("listen"); exit(EXIT_FAILURE);
    }
    return sockfd;
}

int main(int argc, char **argv) {
    int port = DEFAULT_PORT;
    if (argc >= 2) port = atoi(argv[1]);

    signal(SIGPIPE, SIG_IGN);

    SSL_CTX *ctx = create_server_ctx();

    int tap_fd = setup_tap();
    setup_forwarding();

    int listen_fd = tcp_listen(port);
    printf("[*] VPN server listening on 0.0.0.0:%d\n", port);

    for (;;) {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);

        int client_fd = accept(listen_fd, (struct sockaddr *)&peer, &peer_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }
        printf("[*] client connected from %s:%d\n",
               inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0) {
            fprintf(stderr, "[!] TLS handshake failed\n");
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_fd);
            continue;
        }
        printf("[*] TLS handshake OK (cipher: %s)\n", SSL_get_cipher(ssl));

        run_relay(tap_fd, ssl);

        printf("[*] client disconnected, waiting for new connection...\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    close(listen_fd);
    SSL_CTX_free(ctx);
    return 0;
}
