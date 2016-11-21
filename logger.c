#include "logger.h"
#include <errno.h>
#include <slog.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "tcp_spy.h"

void logger(LogLevel lvl, const char *str, const char *file, int line) {
        int pid = getpid();
        switch (lvl) {
                case ALWAYS:
                        slog(lvl, SLOG_LIVE, "%d: %s", pid, str);
                        break;
                case ERROR:
                        slog(lvl, SLOG_ERROR, "%d (%s:%d) %s", pid, file, line,
                             str);
                        break;
                case WARN:
                        slog(lvl, SLOG_WARN, "%d (%s:%d) %s", pid, file, line,
                             str);
                        break;
                case INFO:
                        slog(lvl, SLOG_INFO, "%d: %s", pid, str);
                        break;
                case DEBUG:
                        slog(lvl, SLOG_DEBUG, "%d: %s", pid, str);
                        break;
        }
}
