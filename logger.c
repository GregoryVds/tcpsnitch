#include "logger.h"
#include <stdlib.h>
#include <unistd.h>
#include <slog.h>

int log_level_to_tag[] = {SLOG_LIVE, SLOG_ERROR, SLOG_WARN, SLOG_INFO,
                          SLOG_DEBUG};

void logger(LogLevel lvl, const char *str, const char *file, int line) {
        slog(lvl, log_level_to_tag[lvl], "%d (%s:%d) %s", getpid(), file, line,
             str);
}
