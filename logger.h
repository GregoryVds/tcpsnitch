#ifndef LOGGER_H
#define LOGGER_H

#include <slog.h>

typedef enum LogLevel { ALWAYS, ERROR, WARN, INFO, DEBUG } LogLevel;

void logger(LogLevel lvl, const char *str, const char *file, int line);

#define LOG(lvl, format, args...)                           \
        {                                                   \
                char buf[1024];                             \
                snprintf(buf, sizeof(buf), format, ##args); \
                logger(lvl, buf, __FILE__, __LINE__);       \
        }

#define D(format, args...) LOG(DEBUG, format, ##args)

#define LOG_FUNC_FAIL LOG(ERROR, "%s failed.", __func__)

#endif
