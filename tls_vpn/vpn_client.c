/*
 * vpn_client.c - TLS VPN client (VM1, 192.168.2.3 -> VM2 192.168.2.1)
 *
 * Usage:
 *   sudo ./vpn_client <server_ip> [server_port]
 *
 * Files expected in the current directory:
 *   client-cert.pem, client-key.pem  - this client's certificate/key
 *   ca-cert.pem                      - CA used to verify the server cert
 *
 * The program:
 *   1. Creates/configures the "tap0" device as 10.10.10.2/24
 *   2. Connects to the VPN gateway and performs a mutual TLS handshake,
 *      verifying the server certificate against <server_ip>
 *   3. Adds a route to 172.16.0.0/24 via tap0
 *   4. Relays Ethernet frames between tap0 and the TLS connection
 */
#include "common.h"
#include <openssl/x509v3.h>

#define TAP_NAME    "tap0"
#define TAP_ADDR    "10.10.10.2/24"
#define DEFAULT_PORT 4433

#define CLIENT_CERT "client-cert.pem"
#define CLIENT_KEY  "client-key.pem"
#define CA_CERT     "ca-cert.pem"

#define REMOTE_NET  "172.16.0.0/24"
#define VPN_GATEWAY "10.10.10.3"   /* server's tap0 IP, used as next-hop */

static SSL_CTX *create_client_ctx(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    /* CA used to verify the server's certificate */
    if (SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL) != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* Mutual TLS: present our own certificate to the server */
    if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "[!] client private key does not match certificate\n");
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

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

    /* Route the gateway's internal network through the tunnel.
     * A gateway (via) is required: tap0 is an Ethernet device, so without
     * "via" the kernel would try to ARP for the remote host (172.16.0.2)
     * directly on the 10.10.10.0/24 segment and fail with "Host
     * Unreachable". Using the server's tap IP as next-hop makes the
     * kernel ARP for 10.10.10.3 instead, which is reachable through the
     * tunnel. */
    run_cmd("ip route add %s via %s dev %s", REMOTE_NET, VPN_GATEWAY, dev);

    return fd;
}

static int tcp_connect(const char *server_ip, int port) {
    int sockfd;
    struct sockaddr_in addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); exit(EXIT_FAILURE); }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);

    if (inet_pton(AF_INET, server_ip, &addr.sin_addr) != 1) {
        fprintf(stderr, "[!] invalid server IP: %s\n", server_ip);
        exit(EXIT_FAILURE);
    }

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        exit(EXIT_FAILURE);
    }
    return sockfd;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <server_ip> [server_port]\n", argv[0]);
        return EXIT_FAILURE;
    }
    const char *server_ip = argv[1];
    int port = (argc >= 3) ? atoi(argv[2]) : DEFAULT_PORT;

    signal(SIGPIPE, SIG_IGN);

    SSL_CTX *ctx = create_client_ctx();

    int tap_fd = setup_tap();

    int sockfd = tcp_connect(server_ip, port);
    printf("[*] connected to %s:%d (TCP)\n", server_ip, port);

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    /* Verify the server certificate's IP/hostname against server_ip
     * (requires the server cert to contain a matching subjectAltName). */
    X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set1_ip_asc(param, server_ip);

    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "[!] TLS handshake failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sockfd);
        return EXIT_FAILURE;
    }
    printf("[*] TLS handshake OK (cipher: %s)\n", SSL_get_cipher(ssl));

    run_relay(tap_fd, ssl);

    printf("[*] connection closed\n");
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sockfd);
    close(tap_fd);
    return 0;
}
