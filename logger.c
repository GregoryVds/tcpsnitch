#include "logger.h"
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "config.h"
#include "init.h"
#include "lib.h"
#include "tcp_spy.h"

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

static const char *colors[] = {ANSI_COLOR_WHITE, ANSI_COLOR_RED,
                               ANSI_COLOR_YELLOW, ANSI_COLOR_WHITE,
                               ANSI_COLOR_GREEN};

/* We do not want to open/close a new stream each time we log a single line to
   file. Closing the stream would always trigger a write to kernel space.
   Instead we open it once, and let the system automatically close the stream
   when the process ends. Not sure this is the best solution? */
static FILE *log_file = NULL;
static LogLevel stderr_lvl = 0;
static LogLevel file_lvl = 0;

static const char *log_level_str(LogLevel lvl);
static void fill_timestamp(Timestamp *timestamp);
static void log_to_stream(LogLevel log_lvl, const char *formated_str,
                          const char *file, int line, FILE *stream);
static void set_log_path(const char *path);
static void unbuffered_stderr(const char *str);
static void log_to_stderr(LogLevel log_lvl, const char *str, const char *file,
                          int line);

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
                "%s%02d.%02d.%02d-%02d:%02d:%02d.%02d - [%s] - %d/%ld (%s:%d) "
                "%s%s\n",
                colors[log_lvl], ts.year, ts.mon, ts.day, ts.hour, ts.min,
                ts.sec, ts.usec, log_level_str(log_lvl), getpid(),
                syscall(SYS_gettid), file, line, formated_str,
                ANSI_COLOR_RESET);
}

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
                log_to_stderr(ERROR, str, __FILE__, __LINE__);
        }
}

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

/* Exposed functions */

void logger_init(const char *path, LogLevel _stdout_lvl, LogLevel _file_lvl) {
        set_log_path(path);
        stderr_lvl = _stdout_lvl;
        file_lvl = _file_lvl;
}

void logger(LogLevel log_lvl, const char *str, const char *file, int line) {
        if (log_file && log_lvl <= file_lvl)
                log_to_stream(log_lvl, str, file, line, log_file);
        if (log_lvl <= stderr_lvl) log_to_stderr(log_lvl, str, file, line);
}
