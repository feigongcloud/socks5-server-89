/*
 * Utility Functions
 */

#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "socks5_proto.h"

/* XOR key for encryption/decryption */
#define XOR_KEY 0xac

/* Buffer size for I/O operations */
#define BUFFER_SIZE 65536

/* Timeout values (seconds) */
#define SOCKET_TIMEOUT_SEC      30
#define CONNECT_TIMEOUT_SEC     10
#define KEEPALIVE_IDLE_SEC      60
#define KEEPALIVE_INTERVAL_SEC  10
#define KEEPALIVE_COUNT         3

/* XOR encrypt/decrypt - symmetric operation */
void bufxor(void *buf, size_t len);

/* Read exactly n bytes from fd */
ssize_t read_exact(int fd, void *buf, size_t n);

/* Write exactly n bytes to fd */
ssize_t write_exact(int fd, const void *buf, size_t n);

/* Format SOCKS5 address for logging */
void format_addr(const Socks5Addr *addr, char *buf, size_t len);

/* Resolve SOCKS5 address to sockaddr */
int resolve_addr(const Socks5Addr *addr, struct sockaddr_storage *ss,
                 socklen_t *ss_len);

/* Set socket read/write timeout */
int socket_set_timeout(int fd, int timeout_sec);

/* Set TCP keepalive options */
int socket_set_keepalive(int fd);

/* Connect with timeout (returns fd on success, -1 on failure) */
int connect_with_timeout(int family, int type, int protocol,
                         const struct sockaddr *addr, socklen_t addrlen,
                         int timeout_sec);

#endif /* UTIL_H */
