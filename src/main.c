/*
 * SOCKS5 Server Main Entry
 * Compatible with hev-socks5-tunnel
 *
 * Usage:
 *   socks5-server -c config.conf
 *   socks5-server [-l addr] [-p port] [-e external_ip] [-u user] [-P pass] [-v]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <sys/resource.h>

#include "socks5_server.h"
#include "config.h"
#include "log.h"

/* Increase file descriptor limit */
static void raise_fd_limit(void)
{
    struct rlimit rl;
    rlim_t target = 65535;

    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        if (rl.rlim_cur < target) {
            rl.rlim_cur = (rl.rlim_max < target) ? rl.rlim_max : target;
            if (setrlimit(RLIMIT_NOFILE, &rl) == 0) {
                printf("[INFO] Raised fd limit to %lu\n", (unsigned long)rl.rlim_cur);
            }
        }
    }
}

static void signal_handler(int sig)
{
    (void)sig;
    socks5_server_stop();
}

static void print_usage(const char *prog)
{
    printf("SOCKS5 Server - Compatible with hev-socks5-tunnel\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -c, --config FILE    Load configuration from file\n");
    printf("  -l, --listen ADDR    Bind address (default: 0.0.0.0)\n");
    printf("  -p, --port PORT      Bind port (default: 1080)\n");
    printf("  -e, --external IP    External IP for UDP ASSOCIATE\n");
    printf("  -u, --user USER      Username for authentication\n");
    printf("  -P, --pass PASS      Password for authentication\n");
    printf("  -v, --verbose        Enable verbose logging\n");
    printf("  -h, --help           Show this help message\n");
    printf("\n");
    printf("Config file format (key=value):\n");
    printf("  bind_addr=0.0.0.0\n");
    printf("  bind_port=6999\n");
    printf("  external_ip=101.43.6.22\n");
    printf("  username=demo\n");
    printf("  password=demo123\n");
    printf("  verbose=true\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -c /etc/socks5-server.conf\n", prog);
    printf("  %s -p 6999 -e 101.43.6.22 -u demo -P demo123\n", prog);
}

int main(int argc, char *argv[])
{
    Socks5Config config = {
        .bind_addr = NULL,
        .bind_port = 1080,
        .external_ip = NULL,
        .username = NULL,
        .password = NULL,
        .max_clients = 1024,
        .verbose = false
    };

    ServerConfig file_cfg = {0};
    const char *config_file = NULL;
    int use_file_config = 0;

    /* Try to raise file descriptor limit */
    raise_fd_limit();

    static struct option long_options[] = {
        {"config",   required_argument, 0, 'c'},
        {"listen",   required_argument, 0, 'l'},
        {"port",     required_argument, 0, 'p'},
        {"external", required_argument, 0, 'e'},
        {"user",     required_argument, 0, 'u'},
        {"pass",     required_argument, 0, 'P'},
        {"verbose",  no_argument,       0, 'v'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "c:l:p:e:u:P:vh", long_options, NULL)) != -1) {
        switch (opt) {
        case 'c':
            config_file = optarg;
            break;
        case 'l':
            config.bind_addr = optarg;
            break;
        case 'p': {
            int port = atoi(optarg);
            if (port <= 0 || port > 65535) {
                fprintf(stderr, "Invalid port: %s\n", optarg);
                return 1;
            }
            config.bind_port = (uint16_t)port;
            break;
        }
        case 'e':
            config.external_ip = optarg;
            break;
        case 'u':
            config.username = optarg;
            break;
        case 'P':
            config.password = optarg;
            break;
        case 'v':
            config.verbose = true;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Load config file if specified */
    if (config_file) {
        if (config_load(config_file, &file_cfg) < 0) {
            return 1;
        }
        use_file_config = 1;

        /* Use file config as base, command line overrides */
        if (!config.bind_addr && file_cfg.bind_addr)
            config.bind_addr = file_cfg.bind_addr;
        if (config.bind_port == 1080 && file_cfg.bind_port)
            config.bind_port = file_cfg.bind_port;
        if (!config.external_ip && file_cfg.external_ip)
            config.external_ip = file_cfg.external_ip;
        if (!config.username && file_cfg.username)
            config.username = file_cfg.username;
        if (!config.password && file_cfg.password)
            config.password = file_cfg.password;
        if (!config.verbose && file_cfg.verbose)
            config.verbose = file_cfg.verbose;

        /* Copy upstream config */
        config.upstream.enable = file_cfg.upstream.enable;
        config.upstream.addr = file_cfg.upstream.addr;
        config.upstream.port = file_cfg.upstream.port;
        config.upstream.username = file_cfg.upstream.username;
        config.upstream.password = file_cfg.upstream.password;
    }

    /* Validate auth config */
    if ((config.username && !config.password) ||
        (!config.username && config.password)) {
        fprintf(stderr, "Error: Both username and password must be provided\n");
        if (use_file_config)
            config_free(&file_cfg);
        return 1;
    }

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    /* Initialize and run server */
    if (socks5_server_init(&config) < 0) {
        if (use_file_config)
            config_free(&file_cfg);
        return 1;
    }

    int ret = socks5_server_run();

    if (use_file_config)
        config_free(&file_cfg);

    return ret;
}
