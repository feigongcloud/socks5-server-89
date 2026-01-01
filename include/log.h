/*
 * Logging API
 */

#ifndef LOG_H
#define LOG_H

#include <stdbool.h>

/* Set verbose mode */
void log_set_verbose(bool verbose);

/* Check if verbose mode is enabled */
bool log_is_verbose(void);

/* Log functions */
void log_info(const char *fmt, ...);
void log_error(const char *fmt, ...);
void log_debug(const char *fmt, ...);

#endif /* LOG_H */
