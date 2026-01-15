/*
 * Configuration File Parser
 *
 * Format (simple key=value):
 *   bind_addr=0.0.0.0
 *   bind_port=6999
 *   external_ip=101.43.6.22
 *   username=demo
 *   password=demo123
 *   verbose=true
 *
 *   # UDP port range for UDP ASSOCIATE (optional)
 *   udp_port_min=10000
 *   udp_port_max=10100
 *
 *   # Upstream proxy (optional)
 *   upstream_enable=true
 *   upstream_addr=192.168.1.1
 *   upstream_port=1080
 *   upstream_user=user
 *   upstream_pass=pass
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "config.h"

/* Trim whitespace from both ends */
static char *trim(char *str)
{
    char *end;

    while (isspace((unsigned char)*str))
        str++;

    if (*str == 0)
        return str;

    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end))
        end--;

    end[1] = '\0';
    return str;
}

/* Duplicate string */
static char *strdup_safe(const char *s)
{
    if (!s || !*s)
        return NULL;
    return strdup(s);
}

int config_load(const char *path, ServerConfig *cfg)
{
    FILE *fp;
    char line[1024];

    /* Set defaults */
    memset(cfg, 0, sizeof(*cfg));
    cfg->bind_port = 1080;
    cfg->verbose = false;

    fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open config file: %s\n", path);
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *p = trim(line);
        char *key, *value;
        char *eq;

        /* Skip empty lines and comments */
        if (*p == '\0' || *p == '#')
            continue;

        /* Find '=' separator */
        eq = strchr(p, '=');
        if (!eq)
            continue;

        *eq = '\0';
        key = trim(p);
        value = trim(eq + 1);

        /* Remove quotes from value */
        if (*value == '"' || *value == '\'') {
            char quote = *value;
            value++;
            char *end = strrchr(value, quote);
            if (end)
                *end = '\0';
        }

        /* Parse key-value pairs */
        if (strcmp(key, "bind_addr") == 0 || strcmp(key, "listen") == 0) {
            free(cfg->bind_addr);
            cfg->bind_addr = strdup_safe(value);
        } else if (strcmp(key, "bind_port") == 0 || strcmp(key, "port") == 0) {
            cfg->bind_port = atoi(value);
        } else if (strcmp(key, "external_ip") == 0 || strcmp(key, "external") == 0) {
            free(cfg->external_ip);
            cfg->external_ip = strdup_safe(value);
        } else if (strcmp(key, "username") == 0 || strcmp(key, "user") == 0) {
            free(cfg->username);
            cfg->username = strdup_safe(value);
        } else if (strcmp(key, "password") == 0 || strcmp(key, "pass") == 0) {
            free(cfg->password);
            cfg->password = strdup_safe(value);
        } else if (strcmp(key, "verbose") == 0) {
            cfg->verbose = (strcmp(value, "true") == 0 ||
                           strcmp(value, "yes") == 0 ||
                           strcmp(value, "1") == 0);
        } else if (strcmp(key, "upstream_enable") == 0) {
            cfg->upstream.enable = (strcmp(value, "true") == 0 ||
                                   strcmp(value, "yes") == 0 ||
                                   strcmp(value, "1") == 0);
        } else if (strcmp(key, "upstream_addr") == 0) {
            free(cfg->upstream.addr);
            cfg->upstream.addr = strdup_safe(value);
        } else if (strcmp(key, "upstream_port") == 0) {
            cfg->upstream.port = atoi(value);
        } else if (strcmp(key, "upstream_user") == 0) {
            free(cfg->upstream.username);
            cfg->upstream.username = strdup_safe(value);
        } else if (strcmp(key, "upstream_pass") == 0) {
            free(cfg->upstream.password);
            cfg->upstream.password = strdup_safe(value);
        } else if (strcmp(key, "udp_port_min") == 0) {
            cfg->udp_port_min = atoi(value);
        } else if (strcmp(key, "udp_port_max") == 0) {
            cfg->udp_port_max = atoi(value);
        }
    }

    fclose(fp);
    return 0;
}

void config_free(ServerConfig *cfg)
{
    free(cfg->bind_addr);
    free(cfg->external_ip);
    free(cfg->username);
    free(cfg->password);
    free(cfg->upstream.addr);
    free(cfg->upstream.username);
    free(cfg->upstream.password);
    memset(cfg, 0, sizeof(*cfg));
}
