#define _GNU_SOURCE

#include "logger.h"
#ifdef __ANDROID__
#include <android/log.h>
#endif
#include <assert.h>
#include <errno.h>
#ifndef __ANDROID__
#include <execinfo.h>
#endif
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "constants.h"
#include "init.h"
#include "lib.h"
#include "sock_events.h"

#define ANSI_COLOR_WHITE "\x1b[37m"
#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_RESET "\x1b[0m"

typedef struct {
        int year;
        int mon;
        int day;
        int hour;
        int min;
        int sec;
        int usec;
} Timestamp;

static const char *colors[] = {ANSI_COLOR_GREEN, ANSI_COLOR_RED,
                               ANSI_COLOR_YELLOW, ANSI_COLOR_WHITE,
                               ANSI_COLOR_WHITE};

#ifdef __ANDROID__
static const int android_log_priorities_map[] = {
    ANDROID_LOG_FATAL, ANDROID_LOG_ERROR, ANDROID_LOG_WARN, ANDROID_LOG_INFO,
    ANDROID_LOG_DEBUG};
#endif

/* We do not want to open/close a new stream each time we log a single line to
   file. Closing the stream would always trigger a write to kernel space.
   Instead we open it once, and let the system automatically close the stream
   when the process ends. Not sure this is the best solution? */
static FILE *log_file = NULL;
static LogLevel stderr_lvl = WARN;
static LogLevel file_lvl = WARN;

/* Private functions */

static const char *log_level_str(LogLevel lvl) {
        static const char *strings[] = {"ALWAYS", "ERROR", "WARN", "INFO",
                                        "DEBUG"};
        assert(sizeof(strings) / sizeof(char *) == DEBUG + 1);
        return strings[lvl];
}

static void fill_timestamp(Timestamp *timestamp) {
        time_t rawtime;
        if ((rawtime = time(NULL)) == -1) return;

        struct tm timeinfo;
        if (!localtime_r(&rawtime, &timeinfo)) return;

        timestamp->year = timeinfo.tm_year + 1900;
        timestamp->mon = timeinfo.tm_mon + 1;
        timestamp->day = timeinfo.tm_mday;
        timestamp->hour = timeinfo.tm_hour;
        timestamp->min = timeinfo.tm_min;
        timestamp->sec = timeinfo.tm_sec;

        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) return;
        timestamp->usec = now.tv_nsec / 10000000;
}

static void log_to_stream(LogLevel log_lvl, const char *formated_str,
                          const char *file, int line, FILE *stream) {
        Timestamp ts;
        fill_timestamp(&ts);
        fprintf(stream,
                "%s%02d.%02d.%02d-%02d:%02d:%02d.%02d - [%s] - %d (%s:%d) "
                "%s%s\n",
                colors[log_lvl], ts.year, ts.mon, ts.day, ts.hour, ts.min,
                ts.sec, ts.usec, log_level_str(log_lvl), getpid(), file, line,
                formated_str, ANSI_COLOR_RESET);
}

#ifdef __ANDROID__
static void log_to_logcat(LogLevel log_lvl, const char *str, const char *file,
                          int line) {
        __android_log_print(android_log_priorities_map[log_lvl], "tcpsnitch",
                            "(%s:%d) %s", file, line, str);
}
#else
static void unbuffered_stderr(const char *str) {
        char *msg = malloc(sizeof(char) * (strlen(str) + 2));
        if (msg) {
                strcpy(msg, str);
                strcat(msg, "\n");
                write(STDOUT_FD, msg, strlen(msg));
                free(msg);
        } else
                write(STDOUT_FD, str, strlen(str));
}

static void log_to_stderr(LogLevel log_lvl, const char *str, const char *file,
                          int line) {
        if (_stderr)
                log_to_stream(log_lvl, str, file, line, _stderr);
        else
                unbuffered_stderr(str);
}
#endif

static void set_log_path(const char *path) {
        if (log_file != NULL) fclose(log_file);

        if (!path) {
                log_file = NULL;
                return;
        }

        log_file = fopen(path, "a");
        if (!log_file) {
                char str[1024];
                snprintf(str, sizeof(str), "fopen() failed on %s. %s.", path,
                         strerror(errno));
#ifdef __ANDROID__
                log_to_logcat(ERROR, str, __FILE__, __LINE__);
#else
                log_to_stderr(ERROR, str, __FILE__, __LINE__);
#endif
        }
}

/* Public functions */

void logger_init(const char *path, LogLevel _stdout_lvl, LogLevel _file_lvl) {
        set_log_path(path);
        stderr_lvl = _stdout_lvl;
        file_lvl = _file_lvl;
}

void logger(LogLevel log_lvl, const char *str, const char *file, int line) {
        if (log_lvl <= stderr_lvl)
#ifdef __ANDROID__
                log_to_logcat(log_lvl, str, file, line);
#else
                log_to_stderr(log_lvl, str, file, line);
#endif
        if (log_file && log_lvl <= file_lvl)
                log_to_stream(log_lvl, str, file, line, log_file);
}

#ifndef __ANDROID__
void print_trace(void) {
        void *array[10];
        size_t size;
        char **strings;
        size_t i;

        size = backtrace(array, 10);
        if (!(strings = backtrace_symbols(array, size))) return;

        printf("Obtained %zd stack frames.\n", size);
        for (i = 0; i < size; i++) fprintf(_stderr, "     %s\n", strings[i]);
        free(strings);
}
#endif
