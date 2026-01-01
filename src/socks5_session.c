/*
 * SOCKS5 Session Handler
 * Handles authentication, commands, and data relay
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "socks5_server.h"
#include "socks5_proto.h"
#include "util.h"
#include "log.h"

/* UDP NAT Table Configuration */
#define UDP_NAT_MAX_ENTRIES 256
#define UDP_NAT_TIMEOUT_SEC 120

/* UDP NAT Table Entry */
typedef struct {
    int fd;                             /* Forward socket fd, -1 = unused */
    struct sockaddr_storage dest_addr;  /* Destination address */
    socklen_t dest_len;
    struct sockaddr_storage client_addr; /* Client address for reply */
    socklen_t client_len;
    time_t last_active;                 /* Last activity time */
} UdpNatEntry;

/* Forward declarations */
static int handle_auth(Socks5Session *sess);
static int handle_request(Socks5Session *sess);
static int handle_connect(Socks5Session *sess, const Socks5Addr *addr);
static int handle_udp_associate(Socks5Session *sess, const Socks5Addr *addr);
static int handle_fwd_udp(Socks5Session *sess, const Socks5Addr *addr);
static int send_reply(int fd, uint8_t rep, const struct sockaddr_storage *addr);
static void tcp_relay(int client_fd, int remote_fd);
static int connect_upstream(UpstreamConfig *upstream);
static int upstream_connect(int upstream_fd, const Socks5Addr *addr);

/* Send SOCKS5 reply */
static int send_reply(int fd, uint8_t rep, const struct sockaddr_storage *addr)
{
    uint8_t buf[32];
    int len = 0;

    buf[len++] = SOCKS5_VERSION;
    buf[len++] = rep;
    buf[len++] = 0x00; /* reserved */

    if (addr && addr->ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        buf[len++] = SOCKS5_ATYPE_IPV4;
        memcpy(buf + len, &sin->sin_addr, 4);
        len += 4;
        memcpy(buf + len, &sin->sin_port, 2);
        len += 2;
    } else if (addr && addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        buf[len++] = SOCKS5_ATYPE_IPV6;
        memcpy(buf + len, &sin6->sin6_addr, 16);
        len += 16;
        memcpy(buf + len, &sin6->sin6_port, 2);
        len += 2;
    } else {
        /* Default: 0.0.0.0:0 */
        buf[len++] = SOCKS5_ATYPE_IPV4;
        memset(buf + len, 0, 6);
        len += 6;
    }

    /* Encrypt response: first 4 bytes (ver+rep+rsv+atype), then address */
    bufxor(buf, 4);           /* ver + rep + rsv + atype */
    bufxor(buf + 4, len - 4); /* address (without atype) */

    return write_exact(fd, buf, len) == len ? 0 : -1;
}

/* Handle authentication negotiation */
static int handle_auth(Socks5Session *sess)
{
    uint8_t buf[258];
    uint8_t ver, nmethods;
    uint8_t selected_method = SOCKS5_AUTH_DENIED;
    int need_auth = (sess->config->username && sess->config->password);

    /* Read version and method count */
    if (read_exact(sess->client_fd, buf, 2) != 2)
        return -1;

    ver = buf[0];
    nmethods = buf[1];

    if (ver != SOCKS5_VERSION) {
        log_error("Invalid SOCKS version: %d", ver);
        return -1;
    }

    /* Read methods */
    if (nmethods == 0 || read_exact(sess->client_fd, buf, nmethods) != nmethods)
        return -1;

    /* Select method */
    for (int i = 0; i < nmethods; i++) {
        if (!need_auth && buf[i] == SOCKS5_AUTH_NONE) {
            selected_method = SOCKS5_AUTH_NONE;
            break;
        }
        if (need_auth && (buf[i] == SOCKS5_AUTH_USER_HEV ||
                          buf[i] == SOCKS5_AUTH_PASSWORD)) {
            selected_method = buf[i];
            break;
        }
    }

    /* Send method selection */
    buf[0] = SOCKS5_VERSION;
    buf[1] = selected_method;
    if (write_exact(sess->client_fd, buf, 2) != 2)
        return -1;

    if (selected_method == SOCKS5_AUTH_DENIED) {
        log_error("No acceptable auth method");
        return -1;
    }

    /* Handle user/password auth */
    if (selected_method == SOCKS5_AUTH_USER_HEV ||
        selected_method == SOCKS5_AUTH_PASSWORD) {
        uint8_t ulen, plen;
        char username[256], password[256];

        /* Read auth request */
        if (read_exact(sess->client_fd, buf, 2) != 2)
            return -1;

        if (buf[0] != SOCKS5_AUTH_VERSION) {
            log_error("Invalid auth version: %d", buf[0]);
            return -1;
        }

        ulen = buf[1];
        if (read_exact(sess->client_fd, username, ulen) != ulen)
            return -1;
        username[ulen] = '\0';

        if (read_exact(sess->client_fd, &plen, 1) != 1)
            return -1;
        if (read_exact(sess->client_fd, password, plen) != plen)
            return -1;
        password[plen] = '\0';

        /* Verify credentials */
        uint8_t status = 0x01; /* failure */
        if (strcmp(username, sess->config->username) == 0 &&
            strcmp(password, sess->config->password) == 0) {
            status = 0x00; /* success */
            sess->authenticated = true;
            log_debug("Auth success for user: %s", username);
        } else {
            log_error("Auth failed for user: %s", username);
        }

        /* Send auth response */
        buf[0] = SOCKS5_AUTH_VERSION;
        buf[1] = status;
        if (write_exact(sess->client_fd, buf, 2) != 2)
            return -1;

        if (status != 0x00)
            return -1;
    } else {
        sess->authenticated = true;
    }

    return 0;
}

/* TCP relay between client (encrypted) and remote (plain) */
static void tcp_relay(int client_fd, int remote_fd)
{
    struct pollfd fds[2];
    uint8_t buf[BUFFER_SIZE];

    fds[0].fd = client_fd;
    fds[0].events = POLLIN;
    fds[1].fd = remote_fd;
    fds[1].events = POLLIN;

    while (socks5_server_is_running()) {
        int ret = poll(fds, 2, 30000);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (ret == 0)
            continue;

        /* client -> remote: decrypt then forward */
        if (fds[0].revents & POLLIN) {
            ssize_t n = read(client_fd, buf, sizeof(buf));
            if (n <= 0)
                break;
            bufxor(buf, n);  /* Decrypt data from client */
            if (write_exact(remote_fd, buf, n) != n)
                break;
        }
        if (fds[0].revents & (POLLERR | POLLHUP))
            break;

        /* remote -> client: encrypt then forward */
        if (fds[1].revents & POLLIN) {
            ssize_t n = read(remote_fd, buf, sizeof(buf));
            if (n <= 0)
                break;
            bufxor(buf, n);  /* Encrypt data to client */
            if (write_exact(client_fd, buf, n) != n)
                break;
        }
        if (fds[1].revents & (POLLERR | POLLHUP))
            break;
    }
}

/* Connect to upstream SOCKS5 proxy and authenticate */
static int connect_upstream(UpstreamConfig *upstream)
{
    struct sockaddr_in sin;
    int fd;
    uint8_t buf[512];

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        log_error("upstream socket: %s", strerror(errno));
        return -1;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(upstream->port);
    if (inet_pton(AF_INET, upstream->addr, &sin.sin_addr) <= 0) {
        log_error("Invalid upstream address: %s", upstream->addr);
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        log_error("upstream connect: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* SOCKS5 handshake with upstream */
    int need_auth = (upstream->username && upstream->password);

    if (need_auth) {
        buf[0] = SOCKS5_VERSION;
        buf[1] = 2; /* 2 methods */
        buf[2] = SOCKS5_AUTH_NONE;
        buf[3] = SOCKS5_AUTH_PASSWORD;
    } else {
        buf[0] = SOCKS5_VERSION;
        buf[1] = 1; /* 1 method */
        buf[2] = SOCKS5_AUTH_NONE;
    }

    if (write_exact(fd, buf, need_auth ? 4 : 3) < 0) {
        log_error("upstream write auth methods: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* Read method selection */
    if (read_exact(fd, buf, 2) != 2) {
        log_error("upstream read method selection failed");
        close(fd);
        return -1;
    }

    if (buf[0] != SOCKS5_VERSION) {
        log_error("upstream invalid SOCKS version: %d", buf[0]);
        close(fd);
        return -1;
    }

    if (buf[1] == SOCKS5_AUTH_DENIED) {
        log_error("upstream no acceptable auth method");
        close(fd);
        return -1;
    }

    /* Handle user/password authentication if required */
    if (buf[1] == SOCKS5_AUTH_PASSWORD) {
        if (!need_auth) {
            log_error("upstream requires auth but no credentials configured");
            close(fd);
            return -1;
        }

        size_t ulen = strlen(upstream->username);
        size_t plen = strlen(upstream->password);

        buf[0] = SOCKS5_AUTH_VERSION;
        buf[1] = ulen;
        memcpy(buf + 2, upstream->username, ulen);
        buf[2 + ulen] = plen;
        memcpy(buf + 3 + ulen, upstream->password, plen);

        if (write_exact(fd, buf, 3 + ulen + plen) < 0) {
            log_error("upstream write auth: %s", strerror(errno));
            close(fd);
            return -1;
        }

        if (read_exact(fd, buf, 2) != 2) {
            log_error("upstream read auth response failed");
            close(fd);
            return -1;
        }

        if (buf[1] != 0x00) {
            log_error("upstream authentication failed");
            close(fd);
            return -1;
        }
    }

    return fd;
}

/* Send SOCKS5 CONNECT request to upstream and get reply */
static int upstream_connect(int upstream_fd, const Socks5Addr *addr)
{
    uint8_t buf[512];
    int len = 0;

    /* Build CONNECT request */
    buf[len++] = SOCKS5_VERSION;
    buf[len++] = SOCKS5_CMD_CONNECT;
    buf[len++] = 0x00; /* reserved */

    /* Add address */
    switch (addr->atype) {
    case SOCKS5_ATYPE_IPV4:
        buf[len++] = SOCKS5_ATYPE_IPV4;
        memcpy(buf + len, addr->ipv4.addr, 4);
        len += 4;
        memcpy(buf + len, &addr->ipv4.port, 2);
        len += 2;
        break;
    case SOCKS5_ATYPE_IPV6:
        buf[len++] = SOCKS5_ATYPE_IPV6;
        memcpy(buf + len, addr->ipv6.addr, 16);
        len += 16;
        memcpy(buf + len, &addr->ipv6.port, 2);
        len += 2;
        break;
    case SOCKS5_ATYPE_DOMAIN:
        buf[len++] = SOCKS5_ATYPE_DOMAIN;
        buf[len++] = addr->domain.len;
        memcpy(buf + len, addr->domain.data, addr->domain.len);
        len += addr->domain.len;
        memcpy(buf + len, addr->domain.data + addr->domain.len, 2);
        len += 2;
        break;
    default:
        return -1;
    }

    if (write_exact(upstream_fd, buf, len) != len) {
        log_error("upstream write connect request: %s", strerror(errno));
        return -1;
    }

    /* Read reply header: VER + REP + RSV + ATYPE */
    if (read_exact(upstream_fd, buf, 4) != 4) {
        log_error("upstream read reply header failed");
        return -1;
    }

    if (buf[0] != SOCKS5_VERSION) {
        log_error("upstream invalid reply version: %d", buf[0]);
        return -1;
    }

    if (buf[1] != SOCKS5_REP_SUCCESS) {
        log_error("upstream connect failed: rep=%d", buf[1]);
        return -1;
    }

    /* Skip bind address */
    uint8_t atype = buf[3];
    switch (atype) {
    case SOCKS5_ATYPE_IPV4:
        if (read_exact(upstream_fd, buf, 6) != 6)
            return -1;
        break;
    case SOCKS5_ATYPE_IPV6:
        if (read_exact(upstream_fd, buf, 18) != 18)
            return -1;
        break;
    case SOCKS5_ATYPE_DOMAIN: {
        uint8_t dlen;
        if (read_exact(upstream_fd, &dlen, 1) != 1)
            return -1;
        if (read_exact(upstream_fd, buf, dlen + 2) != dlen + 2)
            return -1;
        break;
    }
    default:
        return -1;
    }

    return 0;
}

/* Handle TCP CONNECT command */
static int handle_connect(Socks5Session *sess, const Socks5Addr *addr)
{
    struct sockaddr_storage ss;
    socklen_t ss_len;
    char addr_str[280];
    int remote_fd;

    format_addr(addr, addr_str, sizeof(addr_str));

    /* Check if upstream is enabled */
    if (sess->config->upstream.enable && sess->config->upstream.addr) {
        log_info("CONNECT to %s (via upstream %s:%d)", addr_str,
                 sess->config->upstream.addr, sess->config->upstream.port);

        /* Connect to upstream proxy */
        remote_fd = connect_upstream(&sess->config->upstream);
        if (remote_fd < 0) {
            send_reply(sess->client_fd, SOCKS5_REP_GENERAL_ERR, NULL);
            return -1;
        }

        /* Send CONNECT request to upstream */
        if (upstream_connect(remote_fd, addr) < 0) {
            close(remote_fd);
            send_reply(sess->client_fd, SOCKS5_REP_HOST_UNREACH, NULL);
            return -1;
        }

        sess->remote_fd = remote_fd;

        /* Get local address for reply */
        struct sockaddr_storage bound;
        socklen_t bound_len = sizeof(bound);
        getsockname(remote_fd, (struct sockaddr *)&bound, &bound_len);

        if (send_reply(sess->client_fd, SOCKS5_REP_SUCCESS, &bound) < 0) {
            close(remote_fd);
            return -1;
        }

        log_debug("CONNECT established to %s via upstream", addr_str);

        /* Start TCP relay */
        tcp_relay(sess->client_fd, remote_fd);

        return 0;
    }

    /* Direct connection (no upstream) */
    log_info("CONNECT to %s", addr_str);

    if (resolve_addr(addr, &ss, &ss_len) < 0) {
        log_error("Failed to resolve address");
        send_reply(sess->client_fd, SOCKS5_REP_HOST_UNREACH, NULL);
        return -1;
    }

    remote_fd = socket(ss.ss_family, SOCK_STREAM, 0);
    if (remote_fd < 0) {
        log_error("socket: %s", strerror(errno));
        send_reply(sess->client_fd, SOCKS5_REP_GENERAL_ERR, NULL);
        return -1;
    }

    if (connect(remote_fd, (struct sockaddr *)&ss, ss_len) < 0) {
        log_error("connect: %s", strerror(errno));
        close(remote_fd);
        send_reply(sess->client_fd, SOCKS5_REP_HOST_UNREACH, NULL);
        return -1;
    }

    sess->remote_fd = remote_fd;

    /* Get bound address */
    struct sockaddr_storage bound;
    socklen_t bound_len = sizeof(bound);
    getsockname(remote_fd, (struct sockaddr *)&bound, &bound_len);

    if (send_reply(sess->client_fd, SOCKS5_REP_SUCCESS, &bound) < 0) {
        close(remote_fd);
        return -1;
    }

    log_debug("CONNECT established to %s", addr_str);

    /* Start TCP relay */
    tcp_relay(sess->client_fd, remote_fd);

    return 0;
}

/* NAT table helper functions */
static int nat_find_by_dest(UdpNatEntry *table, int count,
                            const struct sockaddr_storage *dest, socklen_t dest_len)
{
    for (int i = 0; i < count; i++) {
        if (table[i].fd < 0)
            continue;
        if (table[i].dest_len == dest_len &&
            memcmp(&table[i].dest_addr, dest, dest_len) == 0)
            return i;
    }
    return -1;
}

static int nat_find_by_fd(UdpNatEntry *table, int count, int fd)
{
    for (int i = 0; i < count; i++) {
        if (table[i].fd == fd)
            return i;
    }
    return -1;
}

static int nat_find_free(UdpNatEntry *table, int count, time_t now)
{
    int oldest_idx = -1;
    time_t oldest_time = now;

    for (int i = 0; i < count; i++) {
        if (table[i].fd < 0)
            return i;
        /* Check for expired entry */
        if (now - table[i].last_active > UDP_NAT_TIMEOUT_SEC) {
            close(table[i].fd);
            table[i].fd = -1;
            return i;
        }
        /* Track oldest for LRU eviction */
        if (table[i].last_active < oldest_time) {
            oldest_time = table[i].last_active;
            oldest_idx = i;
        }
    }

    /* Evict oldest entry if no free slot */
    if (oldest_idx >= 0) {
        close(table[oldest_idx].fd);
        table[oldest_idx].fd = -1;
        return oldest_idx;
    }

    return -1;
}

static void nat_cleanup(UdpNatEntry *table, int count, time_t now)
{
    for (int i = 0; i < count; i++) {
        if (table[i].fd >= 0 &&
            now - table[i].last_active > UDP_NAT_TIMEOUT_SEC) {
            close(table[i].fd);
            table[i].fd = -1;
        }
    }
}

/* Handle UDP ASSOCIATE command - Async Version */
static int handle_udp_associate(Socks5Session *sess, const Socks5Addr *addr)
{
    int udp_fd;
    (void)addr;
    struct sockaddr_storage bind_addr;
    socklen_t bind_len = sizeof(bind_addr);

    log_info("UDP ASSOCIATE request (async mode)");

    /* Create UDP socket for client communication */
    udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd < 0) {
        log_error("socket: %s", strerror(errno));
        send_reply(sess->client_fd, SOCKS5_REP_GENERAL_ERR, NULL);
        return -1;
    }

    /* Bind to any available port */
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = 0;

    if (bind(udp_fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        log_error("bind: %s", strerror(errno));
        close(udp_fd);
        send_reply(sess->client_fd, SOCKS5_REP_GENERAL_ERR, NULL);
        return -1;
    }

    getsockname(udp_fd, (struct sockaddr *)&bind_addr, &bind_len);

    /* Set external IP address for UDP ASSOCIATE reply */
    if (bind_addr.ss_family == AF_INET && sess->config->external_ip) {
        struct sockaddr_in *s = (struct sockaddr_in *)&bind_addr;
        inet_pton(AF_INET, sess->config->external_ip, &s->sin_addr);
    }

    sess->udp_fd = udp_fd;

    if (send_reply(sess->client_fd, SOCKS5_REP_SUCCESS, &bind_addr) < 0) {
        close(udp_fd);
        return -1;
    }

    log_debug("UDP ASSOCIATE bound to port %d",
              ntohs(((struct sockaddr_in *)&bind_addr)->sin_port));

    /* Initialize NAT table */
    UdpNatEntry nat_table[UDP_NAT_MAX_ENTRIES];
    for (int i = 0; i < UDP_NAT_MAX_ENTRIES; i++) {
        nat_table[i].fd = -1;
    }

    /* Async UDP relay loop */
    uint8_t buf[BUFFER_SIZE];
    time_t last_cleanup = time(NULL);

    while (socks5_server_is_running()) {
        /* Build poll array: TCP + client UDP + all NAT forward sockets */
        struct pollfd fds[2 + UDP_NAT_MAX_ENTRIES];
        int nfds = 0;

        fds[nfds].fd = sess->client_fd;
        fds[nfds].events = POLLIN;
        nfds++;

        fds[nfds].fd = udp_fd;
        fds[nfds].events = POLLIN;
        int udp_fd_idx = nfds;
        nfds++;

        /* Add all active NAT forward sockets */
        int nat_fd_start = nfds;
        for (int i = 0; i < UDP_NAT_MAX_ENTRIES; i++) {
            if (nat_table[i].fd >= 0) {
                fds[nfds].fd = nat_table[i].fd;
                fds[nfds].events = POLLIN;
                nfds++;
            }
        }

        int ret = poll(fds, nfds, 1000); /* 1s timeout for cleanup */
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        time_t now = time(NULL);

        /* Periodic cleanup of expired NAT entries */
        if (now - last_cleanup > 10) {
            nat_cleanup(nat_table, UDP_NAT_MAX_ENTRIES, now);
            last_cleanup = now;
        }

        if (ret == 0)
            continue;

        /* TCP connection closed = end UDP session */
        if (fds[0].revents & (POLLIN | POLLERR | POLLHUP)) {
            char tmp[1];
            if (recv(sess->client_fd, tmp, 1, MSG_PEEK) <= 0)
                break;
        }

        /* UDP packet from client -> forward to destination */
        if (fds[udp_fd_idx].revents & POLLIN) {
            struct sockaddr_storage from;
            socklen_t from_len = sizeof(from);

            ssize_t n = recvfrom(udp_fd, buf, sizeof(buf), 0,
                                 (struct sockaddr *)&from, &from_len);
            if (n > 0) {
                /* Decrypt received UDP data */
                bufxor(buf, n);

                /* Parse SOCKS5 UDP header */
                if (n >= 4) {
                    Socks5UdpHdr *hdr = (Socks5UdpHdr *)buf;
                    if (hdr->frag == 0) {
                        int addr_len = socks5_addr_len(&hdr->addr);
                        int hdr_len = 3 + addr_len;

                        if (addr_len > 0 && n >= hdr_len) {
                            struct sockaddr_storage dest;
                            socklen_t dest_len;

                            if (resolve_addr(&hdr->addr, &dest, &dest_len) == 0) {
                                /* Find or create NAT entry */
                                int idx = nat_find_by_dest(nat_table, UDP_NAT_MAX_ENTRIES,
                                                           &dest, dest_len);

                                if (idx < 0) {
                                    /* Create new NAT entry */
                                    idx = nat_find_free(nat_table, UDP_NAT_MAX_ENTRIES, now);
                                    if (idx >= 0) {
                                        int fwd_fd = socket(dest.ss_family, SOCK_DGRAM, 0);
                                        if (fwd_fd >= 0) {
                                            if (connect(fwd_fd, (struct sockaddr *)&dest,
                                                        dest_len) == 0) {
                                                nat_table[idx].fd = fwd_fd;
                                                memcpy(&nat_table[idx].dest_addr, &dest, dest_len);
                                                nat_table[idx].dest_len = dest_len;
                                            } else {
                                                close(fwd_fd);
                                                idx = -1;
                                            }
                                        } else {
                                            idx = -1;
                                        }
                                    }
                                }

                                if (idx >= 0) {
                                    /* Update client address and timestamp */
                                    memcpy(&nat_table[idx].client_addr, &from, from_len);
                                    nat_table[idx].client_len = from_len;
                                    nat_table[idx].last_active = now;

                                    /* Forward payload to destination (non-blocking) */
                                    send(nat_table[idx].fd, buf + hdr_len, n - hdr_len, MSG_DONTWAIT);

                                    char addr_str[280];
                                    format_addr(&hdr->addr, addr_str, sizeof(addr_str));
                                    log_debug("UDP fwd: %zd bytes -> %s", n - hdr_len, addr_str);
                                }
                            }
                        }
                    }
                }
            }
        }

        /* Check all NAT forward sockets for incoming responses */
        for (int i = nat_fd_start; i < nfds; i++) {
            if (fds[i].revents & POLLIN) {
                int nat_idx = nat_find_by_fd(nat_table, UDP_NAT_MAX_ENTRIES, fds[i].fd);
                if (nat_idx >= 0) {
                    ssize_t n = recv(fds[i].fd, buf + 32, sizeof(buf) - 32, MSG_DONTWAIT);
                    if (n > 0) {
                        nat_table[nat_idx].last_active = now;

                        /* Build UDP reply header */
                        uint8_t reply[BUFFER_SIZE];
                        int reply_len = 0;

                        reply[reply_len++] = 0; /* RSV */
                        reply[reply_len++] = 0; /* RSV */
                        reply[reply_len++] = 0; /* FRAG */

                        /* Add source address from NAT entry */
                        struct sockaddr_storage *dest = &nat_table[nat_idx].dest_addr;
                        if (dest->ss_family == AF_INET) {
                            struct sockaddr_in *s = (struct sockaddr_in *)dest;
                            reply[reply_len++] = SOCKS5_ATYPE_IPV4;
                            memcpy(reply + reply_len, &s->sin_addr, 4);
                            reply_len += 4;
                            memcpy(reply + reply_len, &s->sin_port, 2);
                            reply_len += 2;
                        } else {
                            struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)dest;
                            reply[reply_len++] = SOCKS5_ATYPE_IPV6;
                            memcpy(reply + reply_len, &s6->sin6_addr, 16);
                            reply_len += 16;
                            memcpy(reply + reply_len, &s6->sin6_port, 2);
                            reply_len += 2;
                        }

                        /* Add payload */
                        memcpy(reply + reply_len, buf + 32, n);
                        reply_len += n;

                        /* Encrypt before sending back */
                        bufxor(reply, reply_len);

                        /* Send back to client (non-blocking) */
                        sendto(udp_fd, reply, reply_len, MSG_DONTWAIT,
                               (struct sockaddr *)&nat_table[nat_idx].client_addr,
                               nat_table[nat_idx].client_len);

                        log_debug("UDP reply: %zd bytes <- NAT[%d]", n, nat_idx);
                    }
                }
            }
        }
    }

    /* Cleanup all NAT entries */
    for (int i = 0; i < UDP_NAT_MAX_ENTRIES; i++) {
        if (nat_table[i].fd >= 0) {
            close(nat_table[i].fd);
        }
    }

    return 0;
}

/* Handle FWD_UDP command (UDP-in-TCP, hev-socks5-tunnel extension) */
static int handle_fwd_udp(Socks5Session *sess, const Socks5Addr *addr)
{
    struct sockaddr_storage dest;
    socklen_t dest_len;
    char addr_str[280];
    int udp_fd;

    format_addr(addr, addr_str, sizeof(addr_str));
    log_info("FWD_UDP to %s", addr_str);

    if (resolve_addr(addr, &dest, &dest_len) < 0) {
        log_error("Failed to resolve address");
        send_reply(sess->client_fd, SOCKS5_REP_HOST_UNREACH, NULL);
        return -1;
    }

    /* Create UDP socket */
    udp_fd = socket(dest.ss_family, SOCK_DGRAM, 0);
    if (udp_fd < 0) {
        log_error("socket: %s", strerror(errno));
        send_reply(sess->client_fd, SOCKS5_REP_GENERAL_ERR, NULL);
        return -1;
    }

    /* Connect UDP socket to destination */
    if (connect(udp_fd, (struct sockaddr *)&dest, dest_len) < 0) {
        log_error("connect: %s", strerror(errno));
        close(udp_fd);
        send_reply(sess->client_fd, SOCKS5_REP_HOST_UNREACH, NULL);
        return -1;
    }

    sess->udp_fd = udp_fd;

    /* Get bound address */
    struct sockaddr_storage bound;
    socklen_t bound_len = sizeof(bound);
    getsockname(udp_fd, (struct sockaddr *)&bound, &bound_len);

    if (send_reply(sess->client_fd, SOCKS5_REP_SUCCESS, &bound) < 0) {
        close(udp_fd);
        return -1;
    }

    log_debug("FWD_UDP established to %s", addr_str);

    /* UDP-in-TCP relay loop */
    struct pollfd fds[2];
    uint8_t buf[BUFFER_SIZE];

    fds[0].fd = sess->client_fd;
    fds[0].events = POLLIN;
    fds[1].fd = udp_fd;
    fds[1].events = POLLIN;

    while (socks5_server_is_running()) {
        int ret = poll(fds, 2, 30000);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (ret == 0)
            continue;

        /* TCP -> UDP: read FWD_UDP header + data from TCP, send to UDP */
        if (fds[0].revents & POLLIN) {
            /* Read header: datalen(2) + hdrlen(1) */
            uint8_t hdr_buf[3];
            if (read_exact(sess->client_fd, hdr_buf, 3) != 3)
                break;

            /* Decrypt header */
            bufxor(hdr_buf, 3);

            uint16_t datalen = (hdr_buf[0] << 8) | hdr_buf[1];
            uint8_t hdrlen = hdr_buf[2];

            if (hdrlen < 1)
                break;

            /* Read address header + data */
            int total = hdrlen - 1 + datalen; /* -1 for hdrlen byte already read */
            if (read_exact(sess->client_fd, buf, total) != total)
                break;

            /* Decrypt address header + data */
            bufxor(buf, total);

            /* Skip address header, send only payload */
            uint8_t *payload = buf + (hdrlen - 1);
            if (send(udp_fd, payload, datalen, 0) < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                    log_debug("UDP send error: %s", strerror(errno));
            }
        }
        if (fds[0].revents & (POLLERR | POLLHUP))
            break;

        /* UDP -> TCP: read from UDP, wrap with FWD_UDP header, send to TCP */
        if (fds[1].revents & POLLIN) {
            struct sockaddr_storage from;
            socklen_t from_len = sizeof(from);

            ssize_t n = recvfrom(udp_fd, buf + 32, sizeof(buf) - 32, 0,
                                 (struct sockaddr *)&from, &from_len);
            if (n < 0)
                continue;

            /* Build FWD_UDP header */
            uint8_t hdr[32];
            int hdr_len = 3; /* datalen(2) + hdrlen(1) */

            if (from.ss_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)&from;
                hdr[3] = SOCKS5_ATYPE_IPV4;
                memcpy(hdr + 4, &sin->sin_addr, 4);
                memcpy(hdr + 8, &sin->sin_port, 2);
                hdr_len += 1 + 4 + 2; /* atype + addr + port */
            } else {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&from;
                hdr[3] = SOCKS5_ATYPE_IPV6;
                memcpy(hdr + 4, &sin6->sin6_addr, 16);
                memcpy(hdr + 20, &sin6->sin6_port, 2);
                hdr_len += 1 + 16 + 2;
            }

            /* datalen (network byte order) */
            hdr[0] = (n >> 8) & 0xFF;
            hdr[1] = n & 0xFF;
            /* hdrlen (includes itself) */
            hdr[2] = hdr_len - 2; /* exclude datalen */

            /* Encrypt header + data before sending */
            bufxor(hdr, hdr_len);
            bufxor(buf + 32, n);

            /* Send header + data */
            if (write_exact(sess->client_fd, hdr, hdr_len) != hdr_len)
                break;
            if (write_exact(sess->client_fd, buf + 32, n) != n)
                break;
        }
    }

    return 0;
}

/* Handle SOCKS5 request */
static int handle_request(Socks5Session *sess)
{
    uint8_t buf[512];
    uint8_t ver, cmd, rsv;

    /* Read request header: VER + CMD + RSV */
    if (read_exact(sess->client_fd, buf, 3) != 3)
        return -1;

    /* Decrypt request header */
    bufxor(buf, 3);

    ver = buf[0];
    cmd = buf[1];
    rsv = buf[2];
    (void)rsv;

    if (ver != SOCKS5_VERSION) {
        log_error("Invalid SOCKS version in request: %d", ver);
        return -1;
    }

    /* Read address type */
    if (read_exact(sess->client_fd, buf, 1) != 1)
        return -1;

    /* Decrypt address type */
    bufxor(buf, 1);

    Socks5Addr addr;
    addr.atype = buf[0];

    /* Read address based on type */
    switch (addr.atype) {
    case SOCKS5_ATYPE_IPV4:
        if (read_exact(sess->client_fd, addr.ipv4.addr, 4) != 4)
            return -1;
        if (read_exact(sess->client_fd, &addr.ipv4.port, 2) != 2)
            return -1;
        /* Decrypt IPv4 address + port */
        bufxor(addr.ipv4.addr, 4);
        bufxor(&addr.ipv4.port, 2);
        break;

    case SOCKS5_ATYPE_IPV6:
        if (read_exact(sess->client_fd, addr.ipv6.addr, 16) != 16)
            return -1;
        if (read_exact(sess->client_fd, &addr.ipv6.port, 2) != 2)
            return -1;
        /* Decrypt IPv6 address + port */
        bufxor(addr.ipv6.addr, 16);
        bufxor(&addr.ipv6.port, 2);
        break;

    case SOCKS5_ATYPE_DOMAIN:
        if (read_exact(sess->client_fd, &addr.domain.len, 1) != 1)
            return -1;
        /* Decrypt domain length */
        bufxor(&addr.domain.len, 1);
        if (read_exact(sess->client_fd, addr.domain.data, addr.domain.len) !=
            addr.domain.len)
            return -1;
        if (read_exact(sess->client_fd, addr.domain.data + addr.domain.len, 2) != 2)
            return -1;
        /* Decrypt domain name + port */
        bufxor(addr.domain.data, addr.domain.len + 2);
        break;

    default:
        log_error("Unknown address type: %d", addr.atype);
        send_reply(sess->client_fd, SOCKS5_REP_ADDR_NOTSUP, NULL);
        return -1;
    }

    /* Handle command */
    switch (cmd) {
    case SOCKS5_CMD_CONNECT:
        return handle_connect(sess, &addr);

    case SOCKS5_CMD_UDP_ASSOC:
        return handle_udp_associate(sess, &addr);

    case SOCKS5_CMD_FWD_UDP:
        return handle_fwd_udp(sess, &addr);

    default:
        log_error("Unsupported command: %d", cmd);
        send_reply(sess->client_fd, SOCKS5_REP_CMD_NOTSUP, NULL);
        return -1;
    }
}

/* Session handler thread */
void *socks5_session_handler(void *arg)
{
    Socks5Session *sess = (Socks5Session *)arg;
    char client_ip[INET6_ADDRSTRLEN];

    /* Get client IP for logging */
    if (sess->client_addr.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&sess->client_addr;
        inet_ntop(AF_INET, &sin->sin_addr, client_ip, sizeof(client_ip));
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&sess->client_addr;
        inet_ntop(AF_INET6, &sin6->sin6_addr, client_ip, sizeof(client_ip));
    }

    log_debug("New connection from %s", client_ip);

    /* Handle authentication */
    if (handle_auth(sess) < 0) {
        log_error("Authentication failed for %s", client_ip);
        goto cleanup;
    }

    /* Handle request */
    handle_request(sess);

cleanup:
    log_debug("Connection closed from %s", client_ip);

    if (sess->client_fd >= 0)
        close(sess->client_fd);
    if (sess->remote_fd >= 0)
        close(sess->remote_fd);
    if (sess->udp_fd >= 0)
        close(sess->udp_fd);

    free(sess);
    return NULL;
}
