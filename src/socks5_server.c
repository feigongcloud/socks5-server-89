/*
 * SOCKS5 Server Core
 * Server lifecycle management and main accept loop
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "socks5_server.h"
#include "log.h"

#define MAX_CLIENTS 1024

static int server_fd = -1;
static volatile int running = 0;
static Socks5Config *g_config = NULL;

/* Check if server is running */
int socks5_server_is_running(void)
{
    return running;
}

/* Initialize server */
int socks5_server_init(Socks5Config *config)
{
    struct sockaddr_in sin;
    int opt = 1;

    g_config = config;

    /* Set verbose logging */
    log_set_verbose(config->verbose);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        log_error("socket: %s", strerror(errno));
        return -1;
    }

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(config->bind_port);

    if (config->bind_addr) {
        if (inet_pton(AF_INET, config->bind_addr, &sin.sin_addr) <= 0) {
            log_error("Invalid bind address: %s", config->bind_addr);
            close(server_fd);
            return -1;
        }
    } else {
        sin.sin_addr.s_addr = INADDR_ANY;
    }

    if (bind(server_fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        log_error("bind: %s", strerror(errno));
        close(server_fd);
        return -1;
    }

    if (listen(server_fd, config->max_clients) < 0) {
        log_error("listen: %s", strerror(errno));
        close(server_fd);
        return -1;
    }

    log_info("SOCKS5 server listening on %s:%d",
             config->bind_addr ? config->bind_addr : "0.0.0.0",
             config->bind_port);

    if (config->username && config->password) {
        log_info("Authentication enabled (user: %s)", config->username);
    } else {
        log_info("Authentication disabled (no-auth mode)");
    }

    if (config->upstream.enable && config->upstream.addr) {
        log_info("Upstream proxy enabled: %s:%d",
                 config->upstream.addr, config->upstream.port);
        if (config->upstream.username)
            log_info("Upstream auth: user=%s", config->upstream.username);
    }

    return 0;
}

/* Run server main loop */
int socks5_server_run(void)
{
    running = 1;

    while (running) {
        struct sockaddr_storage client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd;
        pthread_t tid;
        Socks5Session *sess;

        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR)
                continue;
            log_error("accept: %s", strerror(errno));
            continue;
        }

        sess = calloc(1, sizeof(Socks5Session));
        if (!sess) {
            close(client_fd);
            continue;
        }

        sess->client_fd = client_fd;
        sess->remote_fd = -1;
        sess->udp_fd = -1;
        memcpy(&sess->client_addr, &client_addr, client_len);
        sess->client_addr_len = client_len;
        sess->config = g_config;

        if (pthread_create(&tid, NULL, socks5_session_handler, sess) != 0) {
            log_error("pthread_create: %s", strerror(errno));
            close(client_fd);
            free(sess);
            continue;
        }

        pthread_detach(tid);
    }

    return 0;
}

/* Stop server */
void socks5_server_stop(void)
{
    running = 0;
    if (server_fd >= 0) {
        close(server_fd);
        server_fd = -1;
    }
}
