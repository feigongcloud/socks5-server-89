/*
 * Utility Functions Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "util.h"
#include "socks5_proto.h"

/* XOR encrypt/decrypt - symmetric operation */
void bufxor(void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    for (size_t i = 0; i < len; i++) {
        p[i] ^= XOR_KEY;
    }
}

/* Read exactly n bytes */
ssize_t read_exact(int fd, void *buf, size_t n)
{
    size_t total = 0;
    while (total < n) {
        ssize_t r = read(fd, (char *)buf + total, n - total);
        if (r <= 0) {
            if (r < 0 && (errno == EINTR || errno == EAGAIN))
                continue;
            return r;
        }
        total += r;
    }
    return total;
}

/* Write exactly n bytes */
ssize_t write_exact(int fd, const void *buf, size_t n)
{
    size_t total = 0;
    while (total < n) {
        ssize_t w = write(fd, (const char *)buf + total, n - total);
        if (w <= 0) {
            if (w < 0 && (errno == EINTR || errno == EAGAIN))
                continue;
            return w;
        }
        total += w;
    }
    return total;
}

/* Format address for logging */
void format_addr(const Socks5Addr *addr, char *buf, size_t len)
{
    char ip[INET6_ADDRSTRLEN];
    uint16_t port;

    switch (addr->atype) {
    case SOCKS5_ATYPE_IPV4:
        inet_ntop(AF_INET, addr->ipv4.addr, ip, sizeof(ip));
        port = ntohs(addr->ipv4.port);
        snprintf(buf, len, "%s:%u", ip, port);
        break;
    case SOCKS5_ATYPE_IPV6:
        inet_ntop(AF_INET6, addr->ipv6.addr, ip, sizeof(ip));
        port = ntohs(addr->ipv6.port);
        snprintf(buf, len, "[%s]:%u", ip, port);
        break;
    case SOCKS5_ATYPE_DOMAIN: {
        char domain[256];
        memcpy(domain, addr->domain.data, addr->domain.len);
        domain[addr->domain.len] = '\0';
        memcpy(&port, addr->domain.data + addr->domain.len, 2);
        port = ntohs(port);
        snprintf(buf, len, "%s:%u", domain, port);
        break;
    }
    default:
        snprintf(buf, len, "unknown");
    }
}

/* Resolve SOCKS5 address to sockaddr */
int resolve_addr(const Socks5Addr *addr, struct sockaddr_storage *ss,
                 socklen_t *ss_len)
{
    memset(ss, 0, sizeof(*ss));

    switch (addr->atype) {
    case SOCKS5_ATYPE_IPV4: {
        struct sockaddr_in *sin = (struct sockaddr_in *)ss;
        sin->sin_family = AF_INET;
        memcpy(&sin->sin_addr, addr->ipv4.addr, 4);
        sin->sin_port = addr->ipv4.port;
        *ss_len = sizeof(*sin);
        return 0;
    }
    case SOCKS5_ATYPE_IPV6: {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
        sin6->sin6_family = AF_INET6;
        memcpy(&sin6->sin6_addr, addr->ipv6.addr, 16);
        sin6->sin6_port = addr->ipv6.port;
        *ss_len = sizeof(*sin6);
        return 0;
    }
    case SOCKS5_ATYPE_DOMAIN: {
        char domain[256];
        uint16_t port;
        struct addrinfo hints, *res;

        memcpy(domain, addr->domain.data, addr->domain.len);
        domain[addr->domain.len] = '\0';
        memcpy(&port, addr->domain.data + addr->domain.len, 2);

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(domain, NULL, &hints, &res) != 0)
            return -1;

        memcpy(ss, res->ai_addr, res->ai_addrlen);
        *ss_len = res->ai_addrlen;

        if (ss->ss_family == AF_INET)
            ((struct sockaddr_in *)ss)->sin_port = port;
        else
            ((struct sockaddr_in6 *)ss)->sin6_port = port;

        freeaddrinfo(res);
        return 0;
    }
    default:
        return -1;
    }
}
