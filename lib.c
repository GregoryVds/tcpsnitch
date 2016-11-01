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
#include "logger.h"

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
		LOG(ERROR, "getsockopt() failed. %s", strerror(errno));
		return false;
	}
	return (optval == AF_INET || optval == AF_INET6);
}

bool is_tcp_socket(int fd) {
	if (!is_inet_socket(fd)) return false;

	int optval;
	socklen_t optlen = sizeof(optval);
	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &optval, &optlen) == -1) {
		LOG(ERROR, "getsockopt() failed. %s", strerror(errno));
		return false;
	}
	return optval == SOCK_STREAM;
}

int append_string_to_file(const char *str, const char *path) {
	FILE *fp = fopen(path, "a");
	if (fp == NULL) {
		LOG(ERROR, "fopen() failed. %s", strerror(errno));
		return -1;
	}

	if (fputs(str, fp) == EOF) {
		LOG(ERROR, "fputs() failed.");
		fclose(fp);
		return -2;
	}

	if (fclose(fp) == EOF) {
		LOG(ERROR, "fclose() failed. %s", strerror(errno));
		return -3;
	}

	return 0;
}

time_t get_time_sec() {
	struct timeval tv;
	fill_timeval(&tv);
	return tv.tv_sec;
}

/* Retrieve current time in microseconds granularity */
unsigned long get_time_micros() {
	struct timeval tv;
	fill_timeval(&tv);
	unsigned long time_micros;
	time_micros = tv.tv_sec * (unsigned long)1000000 + tv.tv_usec;
	return time_micros;
}

int fill_timeval(struct timeval *timeval) {
	int ret = gettimeofday(timeval, NULL);
	if (ret == -1) {
		LOG(ERROR, "gettimeofday() failed. %s.", strerror(errno));
	}
	return ret;
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

int fill_tcpinfo(int fd, struct tcp_info *info) {
	socklen_t n = sizeof(struct tcp_info);
	int ret = getsockopt(fd, SOL_TCP, TCP_INFO, (void *)&info, &n);
	if (ret == -1) {
		LOG(ERROR, "getsockopt() failed. %s", strerror(errno));
	}
	return ret;
}
