# SOCKS5 Server Makefile
# Compatible with hev-socks5-tunnel

# Compiler and flags
CC       ?= gcc
CFLAGS   ?= -Wall -Wextra -O2 -g
LDFLAGS  ?= -lpthread

# Directories
SRCDIR   := src
INCDIR   := include
BUILDDIR := build

# Target
TARGET   := socks5-server

# Source files
SRCS     := $(wildcard $(SRCDIR)/*.c)
OBJS     := $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SRCS))
DEPS     := $(OBJS:.o=.d)

# Include path
CFLAGS   += -I$(INCDIR)

# Phony targets
.PHONY: all clean install uninstall distclean help

# Default target
all: $(TARGET)

# Create build directory
$(BUILDDIR):
	@mkdir -p $@

# Link target
$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
	@echo "Build complete: $@"

# Compile source files
$(BUILDDIR)/%.o: $(SRCDIR)/%.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

# Include dependency files
-include $(DEPS)

# Clean build artifacts
clean:
	rm -rf $(BUILDDIR) $(TARGET)

# Full clean (also removes backup files)
distclean: clean
	rm -f *~ $(SRCDIR)/*~ $(INCDIR)/*~

# Install
install: $(TARGET)
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 $(TARGET) $(DESTDIR)/usr/local/bin/
	install -d $(DESTDIR)/etc/socks5-server
	install -m 644 etc/server.conf $(DESTDIR)/etc/socks5-server/server.conf.example

# Uninstall
uninstall:
	rm -f $(DESTDIR)/usr/local/bin/$(TARGET)
	rm -rf $(DESTDIR)/etc/socks5-server

# Help
help:
	@echo "SOCKS5 Server Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build the server (default)"
	@echo "  clean        - Remove build artifacts"
	@echo "  distclean    - Remove all generated files"
	@echo "  install      - Install to system"
	@echo "  uninstall    - Remove from system"
	@echo ""
	@echo "Variables:"
	@echo "  CC         - C compiler (default: gcc)"
	@echo "  CFLAGS     - Compiler flags"
	@echo "  LDFLAGS    - Linker flags"
	@echo "  DESTDIR    - Installation prefix"
