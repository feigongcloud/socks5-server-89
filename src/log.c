/*
 * Logging Implementation
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>

#include "log.h"

static bool g_verbose = false;

void log_set_verbose(bool verbose)
{
    g_verbose = verbose;
}

bool log_is_verbose(void)
{
    return g_verbose;
}

void log_info(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    printf("[INFO] ");
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
}

void log_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[ERROR] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

void log_debug(const char *fmt, ...)
{
    if (!g_verbose)
        return;
    va_list ap;
    va_start(ap, fmt);
    printf("[DEBUG] ");
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
}
