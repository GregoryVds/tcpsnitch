#include "logger.h"
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "tcp_spy.h"

#define LOG_TO_STDERR true
#define LOG_TO_FILE true

#define ANSI_COLOR_WHITE "\x1b[37m"
#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_RESET "\x1b[0m"

// We do not want to open/close a new stream each time we log a single line to
// file. Closing the stream would always trigger a write to kernel space.
// Instead we open it once, and let the system automatically close the stream
// when the process ends. Not sure this is the best way?
FILE *log_file = NULL;
static bool should_log_to_file = false;
const char *colors[] = {ANSI_COLOR_WHITE, ANSI_COLOR_YELLOW, ANSI_COLOR_RED};

//////////////////////////////////////////////////////////////////////////////

static const char *log_level_str(LogLevel lvl);
static unsigned long get_timestamp();
static void log_to_stream(LogLevel log_lvl, const char *formated_str,
			  const char *file, int line, FILE *stream);
static void log_to_file(LogLevel log_lvl, const char *formated_str,
			const char *file, int line);

//////////////////////////////////////////////////////////////////////////////

static const char *log_level_str(LogLevel lvl) {
	static const char *strings[] = {"INFO", "WARN", "ERROR"};
	return strings[lvl];
}

static unsigned long get_timestamp() {
	struct timeval tv;
	int ret = gettimeofday(&tv, NULL);
	if (ret == -1) return 0;
	unsigned long time_micros;
	time_micros = tv.tv_sec * (unsigned long)1000000 + tv.tv_usec;
	return time_micros;
}

static void log_to_stream(LogLevel log_lvl, const char *formated_str,
			  const char *file, int line, FILE *stream) {
	fprintf(stderr, "%s%s-%d(%s:%d): %s%s\n", colors[log_lvl],
		log_level_str(log_lvl), getpid(), file, line, formated_str,
		ANSI_COLOR_RESET);
}

static void log_to_file(LogLevel log_lvl, const char *formated_str,
			const char *file, int line) {
	if (!should_log_to_file) return;
	unsigned long time_micros = get_timestamp();
	fprintf(log_file, "%s-pid(%d)-usec(%lu)-file(%s:%d): %s\n",
		log_level_str(log_lvl), getpid(), time_micros, file, line,
		formated_str);
}

///////////////////////////////////////////////////////////////////////////////

void set_log_path(const char *path) {
	// Close any previsouly set log file.
	if (log_file != NULL) fclose(log_file);
	should_log_to_file = false;

	log_file = fopen(path, "a");
	if (log_file == NULL) {
		char str[1024];
		snprintf(str, sizeof(str),
			 "fopen() failed on %s. %s. Will not log to file.",
			 path, strerror(errno));
		log_to_stream(ERROR, str, __FILE__, __LINE__, stdout);
		return;
	}
	should_log_to_file = true;
}

void logger(LogLevel log_lvl, const char *formated_str, const char *file,
	    int line) {
	if (LOG_TO_FILE) log_to_file(log_lvl, formated_str, file, line);
	if (LOG_TO_STDERR)
		log_to_stream(log_lvl, formated_str, file, line, stderr);
}

///////////////////////////////////////////////////////////////////////////////
