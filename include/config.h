/*
 * Configuration API
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stdbool.h>

/* Upstream proxy configuration */
typedef struct {
    bool enable;
    char *addr;
    uint16_t port;
    char *username;
    char *password;
} UpstreamConfig;

/* Server configuration (from file) */
typedef struct {
    char *bind_addr;
    uint16_t bind_port;
    char *external_ip;
    char *username;
    char *password;
    bool verbose;
    uint16_t udp_port;  /* 0 = use any available port */
    UpstreamConfig upstream;
} ServerConfig;

/* Runtime configuration (used by server) */
typedef struct {
    const char *bind_addr;
    uint16_t bind_port;
    const char *external_ip;
    const char *username;
    const char *password;
    int max_clients;
    bool verbose;
    uint16_t udp_port;  /* 0 = use any available port */
    UpstreamConfig upstream;
} Socks5Config;

/* Parse configuration file */
int config_load(const char *path, ServerConfig *cfg);

/* Free configuration resources */
void config_free(ServerConfig *cfg);

#endif /* CONFIG_H */
