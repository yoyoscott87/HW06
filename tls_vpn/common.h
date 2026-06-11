/*
 * common.h - shared helpers for vpn_client / vpn_server
 *
 *  - tun_alloc(): create/attach a TAP device
 *  - run_cmd():   run a shell command (used to configure the interface)
 *  - read_n/write_n:       reliable I/O on plain fds
 *  - ssl_read_n/ssl_write_n: reliable I/O on an SSL*
 *  - run_relay():  spawn the two relay threads (tap<->tls) and wait
 *
 * Wire format between client and server:
 *   [2-byte big-endian length][raw Ethernet frame from the TAP device]
 */
#ifndef VPN_COMMON_H
#define VPN_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUF_SIZE  2048   /* must be > MTU_SIZE + 2 */
#define MTU_SIZE  1500

/* ------------------------------------------------------------------ */
/* TAP device                                                          */
/* ------------------------------------------------------------------ */

/* Create (or attach to) a TAP device. `dev` must point to a buffer of
 * at least IFNAMSIZ bytes; pass an empty string ("") to let the kernel
 * pick a name, or a fixed name such as "tap0". On return `dev` holds
 * the actual interface name. Returns the fd, or -1 on error. */
static inline int tun_alloc(char *dev, int flags) {
    struct ifreq ifr;
    int fd, err;
    const char *clonedev = "/dev/net/tun";

    if ((fd = open(clonedev, O_RDWR)) < 0) {
        perror("open /dev/net/tun");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = flags; /* IFF_TAP | IFF_NO_PI */

    if (*dev)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return err;
    }

    strncpy(dev, ifr.ifr_name, IFNAMSIZ - 1);
    return fd;
}

/* Run a shell command (e.g. `ip addr add ...`). Aborts the program if
 * the command fails, since the VPN cannot work correctly otherwise. */
static inline void run_cmd(const char *fmt, ...) {
    char cmd[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, ap);
    va_end(ap);

    printf("[*] %s\n", cmd);
    if (system(cmd) != 0) {
        fprintf(stderr, "[!] command failed: %s\n", cmd);
        exit(EXIT_FAILURE);
    }
}

/* ------------------------------------------------------------------ */
/* Reliable I/O helpers                                                */
/* ------------------------------------------------------------------ */

static inline ssize_t read_n(int fd, void *buf, size_t len) {
    size_t total = 0;
    char *p = (char *)buf;
    while (total < len) {
        ssize_t n = read(fd, p + total, len - total);
        if (n == 0) return 0;
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        total += (size_t)n;
    }
    return (ssize_t)total;
}

static inline ssize_t write_n(int fd, const void *buf, size_t len) {
    size_t total = 0;
    const char *p = (const char *)buf;
    while (total < len) {
        ssize_t n = write(fd, p + total, len - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        total += (size_t)n;
    }
    return (ssize_t)total;
}

/* Returns 0 on clean TLS shutdown, -1 on error, >0 (== len) on success. */
static inline int ssl_read_n(SSL *ssl, void *buf, size_t len) {
    size_t total = 0;
    char *p = (char *)buf;
    while (total < len) {
        int n = SSL_read(ssl, p + total, (int)(len - total));
        if (n > 0) {
            total += (size_t)n;
            continue;
        }
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            continue;
        if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL)
            return 0;
        return -1;
    }
    return (int)total;
}

static inline int ssl_write_n(SSL *ssl, const void *buf, size_t len) {
    size_t total = 0;
    const char *p = (const char *)buf;
    while (total < len) {
        int n = SSL_write(ssl, p + total, (int)(len - total));
        if (n > 0) {
            total += (size_t)n;
            continue;
        }
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            continue;
        return -1;
    }
    return (int)total;
}

/* ------------------------------------------------------------------ */
/* TAP <-> TLS relay                                                   */
/* ------------------------------------------------------------------ */

typedef struct {
    int      tap_fd;
    SSL     *ssl;
    pthread_t t1; /* tap_to_tls  */
    pthread_t t2; /* tls_to_tap  */
} relay_ctx_t;

/* Read one Ethernet frame from the TAP device and forward it over TLS,
 * prefixed with a 2-byte length. */
static inline void *tap_to_tls(void *arg) {
    relay_ctx_t *ctx = (relay_ctx_t *)arg;
    unsigned char frame[2 + BUF_SIZE];

    for (;;) {
        ssize_t n = read(ctx->tap_fd, frame + 2, MTU_SIZE);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            fprintf(stderr, "[tap->tls] tap read error/EOF (%s)\n", strerror(errno));
            break;
        }

        uint16_t net_len = htons((uint16_t)n);
        memcpy(frame, &net_len, 2);

        if (ssl_write_n(ctx->ssl, frame, (size_t)n + 2) < 0) {
            fprintf(stderr, "[tap->tls] SSL_write error\n");
            break;
        }
    }

    if (ctx->t2) pthread_cancel(ctx->t2);
    return NULL;
}

/* Read one length-prefixed frame from TLS and write it to the TAP device. */
static inline void *tls_to_tap(void *arg) {
    relay_ctx_t *ctx = (relay_ctx_t *)arg;
    unsigned char buf[BUF_SIZE];

    for (;;) {
        uint16_t net_len;
        int rc = ssl_read_n(ctx->ssl, &net_len, 2);
        if (rc <= 0) {
            fprintf(stderr, "[tls->tap] TLS connection closed\n");
            break;
        }

        uint16_t len = ntohs(net_len);
        if (len == 0 || len > BUF_SIZE) {
            fprintf(stderr, "[tls->tap] invalid frame length %u\n", len);
            break;
        }

        rc = ssl_read_n(ctx->ssl, buf, len);
        if (rc <= 0) {
            fprintf(stderr, "[tls->tap] TLS connection closed while reading payload\n");
            break;
        }

        if (write_n(ctx->tap_fd, buf, len) < 0) {
            fprintf(stderr, "[tls->tap] tap write error\n");
            break;
        }
    }

    if (ctx->t1) pthread_cancel(ctx->t1);
    return NULL;
}

/* Spawn the two relay threads and block until the connection is closed. */
static inline void run_relay(int tap_fd, SSL *ssl) {
    relay_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.tap_fd = tap_fd;
    ctx.ssl    = ssl;

    pthread_create(&ctx.t1, NULL, tap_to_tls, &ctx);
    pthread_create(&ctx.t2, NULL, tls_to_tap, &ctx);

    pthread_join(ctx.t1, NULL);
    pthread_join(ctx.t2, NULL);
}

#endif /* VPN_COMMON_H */
