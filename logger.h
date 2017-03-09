#ifndef LOGGER_H
#define LOGGER_H

#include "logger.h"

typedef enum LogLevel { ALWAYS, ERROR, WARN, INFO, DEBUG } LogLevel;

void logger_init(const char *path, LogLevel stdout_lvl, LogLevel file_lvl);

void logger(LogLevel lvl, const char *str, const char *file, int line);

#ifndef __ANDROID__
void print_trace(void);
#endif

#define LOG(lvl, format, args...)                             \
        {                                                     \
                char _buf[1024];                              \
                snprintf(_buf, sizeof(_buf), format, ##args); \
                logger(lvl, _buf, __FILE__, __LINE__);        \
        }

#ifdef __ANDROID__
#define LOG_FUNC_ERROR LOG(ERROR, "%s failed.", __func__)
#else
#define LOG_FUNC_ERROR {\
        LOG(ERROR, "%s failed.", __func__)\
        print_trace();\
}
#endif

#define LOG_FUNC_WARN LOG(WARN, "%s failed.", __func__)

#define D(format, args...) LOG(DEBUG, format, ##args)

#define LOG_FUNC_D D("%s", __func__)

#endif
