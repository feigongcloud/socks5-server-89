/*
 * SOCKS5 Protocol Definitions
 * Compatible with hev-socks5-tunnel
 */

#ifndef SOCKS5_PROTO_H
#define SOCKS5_PROTO_H

#include <stdint.h>

/* SOCKS5 Version */
#define SOCKS5_VERSION          5

/* Authentication Methods */
#define SOCKS5_AUTH_NONE        0x00
#define SOCKS5_AUTH_GSSAPI      0x01
#define SOCKS5_AUTH_PASSWORD    0x02
#define SOCKS5_AUTH_USER_HEV    0x89    /* hev-socks5-tunnel custom: 137 */
#define SOCKS5_AUTH_DENIED      0xFF

/* Auth sub-negotiation version */
#define SOCKS5_AUTH_VERSION     0x01

/* Request Commands */
#define SOCKS5_CMD_CONNECT      0x01
#define SOCKS5_CMD_BIND         0x02
#define SOCKS5_CMD_UDP_ASSOC    0x03
#define SOCKS5_CMD_FWD_UDP      0x05    /* hev-socks5-tunnel: UDP-in-TCP */

/* Reply Codes */
#define SOCKS5_REP_SUCCESS      0x00
#define SOCKS5_REP_GENERAL_ERR  0x01
#define SOCKS5_REP_NOT_ALLOWED  0x02
#define SOCKS5_REP_NET_UNREACH  0x03
#define SOCKS5_REP_HOST_UNREACH 0x04
#define SOCKS5_REP_REFUSED      0x05
#define SOCKS5_REP_TTL_EXPIRED  0x06
#define SOCKS5_REP_CMD_NOTSUP   0x07
#define SOCKS5_REP_ADDR_NOTSUP  0x08

/* Address Types */
#define SOCKS5_ATYPE_IPV4       0x01
#define SOCKS5_ATYPE_DOMAIN     0x03
#define SOCKS5_ATYPE_IPV6       0x04

/* SOCKS5 Address Structure */
typedef struct {
    uint8_t atype;
    union {
        struct {
            uint8_t addr[4];
            uint16_t port;
        } __attribute__((packed)) ipv4;
        struct {
            uint8_t addr[16];
            uint16_t port;
        } __attribute__((packed)) ipv6;
        struct {
            uint8_t len;
            uint8_t data[257]; /* domain + port */
        } domain;
    };
} __attribute__((packed)) Socks5Addr;

/* SOCKS5 Request/Response Header */
typedef struct {
    uint8_t ver;
    uint8_t cmd; /* or rep for response */
    uint8_t rsv;
    Socks5Addr addr;
} __attribute__((packed)) Socks5ReqRes;

/* SOCKS5 UDP Header (for UDP relay) */
typedef struct {
    uint16_t rsv;
    uint8_t frag;
    Socks5Addr addr;
} __attribute__((packed)) Socks5UdpHdr;

/* SOCKS5 FWD_UDP Header (for UDP-in-TCP) */
typedef struct {
    uint16_t datalen;   /* payload length */
    uint8_t hdrlen;     /* header length */
    Socks5Addr addr;
} __attribute__((packed)) Socks5FwdUdpHdr;

/* Helper function: get SOCKS5 address length */
static inline int socks5_addr_len(const Socks5Addr *addr)
{
    switch (addr->atype) {
    case SOCKS5_ATYPE_IPV4:
        return 1 + 4 + 2;
    case SOCKS5_ATYPE_IPV6:
        return 1 + 16 + 2;
    case SOCKS5_ATYPE_DOMAIN:
        return 1 + 1 + addr->domain.len + 2;
    default:
        return -1;
    }
}

#endif /* SOCKS5_PROTO_H */
