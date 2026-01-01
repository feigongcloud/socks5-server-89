# SOCKS5 Server

A standalone SOCKS5 proxy server compatible with [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel).

## Features

- TCP CONNECT (0x01)
- UDP ASSOCIATE (0x03)
- FWD_UDP / UDP-in-TCP (0x05) - hev-socks5-tunnel extension
- Authentication: No-auth (0x00), User/Pass (0x02), HEV custom (0x89)
- Upstream SOCKS5 proxy chaining
- XOR-based encryption layer (key: 0xac)

## Build

```bash
make
```

### Build Options

```bash
# Debug build
make CFLAGS="-Wall -Wextra -O0 -g3"

# Release build with LTO
make CFLAGS="-Wall -Wextra -O3 -flto" LDFLAGS="-lpthread -flto"

# Cross-compile
make CC=aarch64-linux-gnu-gcc
```

## Install

```bash
sudo make install
```

This installs:
- `/usr/local/bin/socks5-server`
- `/etc/socks5-server/server.conf.example`

## Usage

### Command Line

```bash
# Basic usage (no auth, default port 1080)
./socks5-server

# With config file
./socks5-server -c etc/server.conf

# Command line options
./socks5-server -l 0.0.0.0 -p 6999 -u demo -P demo123 -v

# Show help
./socks5-server -h
```

### Options

| Option | Description |
|--------|-------------|
| `-c, --config FILE` | Load configuration from file |
| `-l, --listen ADDR` | Bind address (default: 0.0.0.0) |
| `-p, --port PORT` | Bind port (default: 1080) |
| `-e, --external IP` | External IP for UDP ASSOCIATE |
| `-u, --user USER` | Username for authentication |
| `-P, --pass PASS` | Password for authentication |
| `-v, --verbose` | Enable verbose logging |
| `-h, --help` | Show help message |

### Configuration File

See `etc/server.conf` for a complete example:

```ini
# Bind settings
bind_addr=0.0.0.0
bind_port=6999

# External IP for UDP ASSOCIATE reply
external_ip=101.43.6.22

# Authentication
username=demo
password=demo123

# Logging
verbose=false

# Upstream proxy (optional)
#upstream_enable=true
#upstream_addr=192.168.1.1
#upstream_port=1080
#upstream_user=user
#upstream_pass=pass
```

## Development

### Continuous Integration

GitHub Actions workflow runs on every push/PR:
- Builds with GCC and Clang on Linux
- Builds on macOS

## Project Structure

```
socks5-server/
├── .github/
│   └── workflows/
│       └── build.yml     # CI workflow
├── Makefile              # Build system
├── README.md             # This file
├── etc/
│   └── server.conf       # Example configuration
├── include/
│   ├── config.h          # Configuration API
│   ├── log.h             # Logging API
│   ├── socks5_proto.h    # Protocol definitions
│   ├── socks5_server.h   # Server API
│   └── util.h            # Utility functions
└── src/
    ├── config.c          # Configuration parser
    ├── log.c             # Logging implementation
    ├── main.c            # Entry point
    ├── socks5_server.c   # Server lifecycle
    ├── socks5_session.c  # Session handling
    └── util.c            # Utilities
```

## License

Compatible with hev-socks5-tunnel licensing.
