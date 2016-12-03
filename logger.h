#ifndef LOGGER_H
#define LOGGER_H

#include "logger.h"
typedef enum LogLevel { ALWAYS, ERROR, WARN, INFO, DEBUG } LogLevel;

void logger_init(const char *path, LogLevel stdout_lvl, LogLevel file_lvl);

void logger(LogLevel lvl, const char *str, const char *file, int line);

#define LOG(lvl, format, args...)                           \
        {                                                   \
                char _buf[1024];                             \
                snprintf(_buf, sizeof(_buf), format, ##args); \
                logger(lvl, _buf, __FILE__, __LINE__);       \
        }

#define D(format, args...) LOG(DEBUG, format, ##args)

#define LOG_FUNC_FAIL LOG(ERROR, "%s failed.", __func__)

#endif
