#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include "logger.h"

#define LOG_TO_STDERR true 
#define LOG_TO_FILE true
#define LOG_PATH "/home/greg/host/log.txt"

#define ANSI_COLOR_WHITE "\x1b[37m"
#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_RESET "\x1b[0m"

// We do not want to open/close a new stream each time we log a single line to
// file. Closing the stream would always trigger a write to kernel space.
// Instead we open it once, and let the system automatically close the stream
// when the process ends. Not sure this is the best way?
FILE *log_file = NULL;

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
	pid_t pid = getpid();

	const char *color;
	switch (log_lvl) {
		case INFO:
			color = ANSI_COLOR_WHITE;
			break;
		case WARN:
			color = ANSI_COLOR_YELLOW;
			break;
		case ERROR:
			color = ANSI_COLOR_RED;
			break;
	}

	// Stderr is unbuffered.
	fprintf(stderr, "%s%s-%d(%s:%d): %s%s\n", color, log_level_str(log_lvl),
		pid, file, line, formated_str, ANSI_COLOR_RESET);
}

static void log_to_file(LogLevel log_lvl, const char *formated_str,
			const char *file, int line) {
	if (log_file == NULL) {
		log_file = fopen(LOG_PATH, "a");
		// If cannot open log file, just log to
		// stdout and do not log.
		if (log_file == NULL) {
			char str[1024];
			snprintf(str, sizeof(str), "fopen() failed on %s. %s.",
				 LOG_PATH, strerror(errno));
			log_to_stream(ERROR, str, file, line, stderr);
			return;
		}
	}

	pid_t pid = getpid();
	unsigned long time_micros = get_timestamp();
	fprintf(log_file, "%s-pid(%d)-usec(%lu)-file(%s:%d): %s\n",
		log_level_str(log_lvl), pid, time_micros, file, line,
		formated_str);
	// We do not close the log file to avoid
	// triggering a write to kernel
	// space. See above.
}

///////////////////////////////////////////////////////////////////////////////

void logger(LogLevel log_lvl, const char *formated_str, const char *file,
	    int line) {
	if (LOG_TO_FILE) log_to_file(log_lvl, formated_str, file, line);
	if (LOG_TO_STDERR)
		log_to_stream(log_lvl, formated_str, file, line, stderr);
}

///////////////////////////////////////////////////////////////////////////////
