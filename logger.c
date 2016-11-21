#include "logger.h"
#include <slog.h>
#include <unistd.h>

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
