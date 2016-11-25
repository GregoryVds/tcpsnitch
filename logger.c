#include "logger.h"
#include <slog.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

int log_level_to_tag[] = {SLOG_LIVE, SLOG_ERROR, SLOG_WARN, SLOG_INFO,
                          SLOG_DEBUG};

void logger(LogLevel lvl, const char *str, const char *file, int line) {
        slog(lvl, log_level_to_tag[lvl], "%d-%d (%s:%d) %s", getpid(),
             syscall(SYS_gettid), file, line, str);

}
