/*
 * SOCKS5 Server API
 * Compatible with hev-socks5-tunnel
 */

#ifndef SOCKS5_SERVER_H
#define SOCKS5_SERVER_H

#include <netinet/in.h>
#include <stdbool.h>

#include "config.h"

/* Client session */
typedef struct {
    int client_fd;
    int remote_fd;
    int udp_fd;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    bool authenticated;
    Socks5Config *config;
} Socks5Session;

/* Server lifecycle */
int socks5_server_init(Socks5Config *config);
int socks5_server_run(void);
void socks5_server_stop(void);

/* Check if server is running */
int socks5_server_is_running(void);

/* Session handler (called in separate thread) */
void *socks5_session_handler(void *arg);

#endif /* SOCKS5_SERVER_H */
