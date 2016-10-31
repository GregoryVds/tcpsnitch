#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <sys/time.h>
#include <limits.h>
#include "config.h"
#include "lib.h"
#include "config.h"
#include "string_helpers.h"

// We do not want to open/close a new stream each time we log a single line to 
// file. Closing the stream would always trigger a write to kernel space. 
// Instead we open it once, and let the system automatically close the stream
// when the process ends. Not sure this is the best way?
FILE *log_file = NULL;

const char *string_from_debug_level(DebugLevel lvl) {
	static const char *strings[] = {"INFO", "WARN", "ERROR"};
	return strings[lvl];
}

#define ANSI_COLOR_WHITE "\x1b[37m"
#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_RESET "\x1b[0m"

void log_to_stream(DebugLevel debug_lvl, const char *formated_str,
		   const char *file, int line, FILE *stream) {
	pid_t pid = getpid();

	const char *color;
	switch (debug_lvl) {
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
	fprintf(stderr, "%s%s-%d(%s:%d): %s%s\n", color,
		string_from_debug_level(debug_lvl), pid, file, line,
		formated_str, ANSI_COLOR_RESET);
}

void log_to_file(DebugLevel debug_lvl, const char *formated_str, 
		 const char *file, int line) {

	if (log_file == NULL) {
		char *path = alloc_log_path_str();
		log_file = fopen(path, "a");
		// If cannot open log file, just log to stdout and do not log.
		if (log_file == NULL) {
			char str[1024];
			snprintf(str, sizeof(str), "fopen() failed on %s. %s.",
				 path, strerror(errno));
			log_to_stream(ERROR, str, file, line, stderr);
			free(path);
			return;
		}
		free(path);
	}

	pid_t pid = getpid();
	unsigned long time_micros = get_time_micros();
	fprintf(log_file, "%s-pid(%d)-usec(%lu)-file(%s:%d): %s\n",
		string_from_debug_level(debug_lvl), pid, time_micros,
		file, line, formated_str);
	// We do not close the log file to avoid triggering a write to kernel
	// space. See above.
}

void netspy_log(DebugLevel debug_lvl, const char *formated_str,
		const char *file, int line) {
	if (NETSPY_LOG_TO_FILE)
		log_to_file(debug_lvl, formated_str, file, line);
	if (NETSPY_LOG_TO_STDERR)
		log_to_stream(debug_lvl, formated_str, file, line, stderr);
}

bool is_socket(int fd) {
	struct stat statbuf;
	fstat(fd, &statbuf);
	return S_ISSOCK(statbuf.st_mode);
}

bool is_inet_socket(int fd) {
	if (!is_socket(fd)) return false;

	int optval;
	socklen_t optlen = sizeof(optval);
	if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &optval, &optlen) == -1) {
		DEBUG(ERROR, "getsockopt() failed. %s", strerror(errno));
		return false;
	}
	return (optval == AF_INET || optval == AF_INET6);
}

bool is_tcp_socket(int fd) {
	if (!is_inet_socket(fd)) return false;

	int optval;
	socklen_t optlen = sizeof(optval);
	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &optval, &optlen) == -1) {
		DEBUG(ERROR, "getsockopt() failed. %s", strerror(errno));
		return false;
	}
	return optval == SOCK_STREAM;
}

int append_string_to_file(const char *str, const char *path) {
	FILE *fp = fopen(path, "a");
	if (fp == NULL) {
		DEBUG(ERROR, "fopen() failed. %s", strerror(errno));
		return -1;
	}

	if (fputs(str, fp) == EOF) {
		DEBUG(ERROR, "fputs() failed.");
		fclose(fp);
		return -1;
	}

	if (fclose(fp) == EOF) {
		DEBUG(ERROR, "fclose() failed. %s", strerror(errno));
		return -1;
	}

	return 0;
}

time_t get_time_sec() {
	struct timeval tv;
	if (gettimeofday(&tv, NULL) == -1) {
		DEBUG(ERROR, "gettimeofday() failed. %s", strerror(errno));
	}
	return tv.tv_sec;
}

/* Retrieve current time in microseconds granularity */
unsigned long get_time_micros() {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	unsigned long time_micros;
	time_micros = tv.tv_sec * (unsigned long)1000000 + tv.tv_usec;
	return time_micros;
}

/* Retrieve env variable containing a LONG
 * Return long value or < 0 in case of error:
 * 	-1 if env var not set.
 * 	-2 if env var in incorrect format.
 * 	-3 if env var overflows. */
long get_long_env(const char *env_var) {
	char *var_str = getenv(env_var);
	if (var_str == NULL) return -1;  // Not set

	/* Convert from string to long */
	char *var_str_end;
	long val = strtol(var_str, &var_str_end, 10);

	if (*var_str_end != '\0') return -2;		    // Incorrect format
	if (val == LONG_MIN || val == LONG_MAX) return -3;  // Overflow
	return val;
}

