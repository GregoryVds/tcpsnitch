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

// We do not want to open/close a new stream each time we log a single line to 
// file. Not closing would leak stream pointers, and closeing would always 
// flush the buffer. Instead we open it once, and let the system automatically
// close when the process ends. Not sure this is the best way?
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
		char *path = build_log_path();
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
	// We do not close the log file to avoid triggering a flush. See above.
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

/* Extract IP address to human readable string */
#define ADDR_WIDTH 40  // Include null byte
char *build_addr_str_from_sockaddr(const struct sockaddr_storage *addr) {
	char *addr_str = (char *)calloc(sizeof(char), ADDR_WIDTH);
	const char *r;

	if (addr->ss_family == AF_INET) {
		const struct sockaddr_in *ipv4;
		ipv4 = (const struct sockaddr_in *)addr;
		r = inet_ntop(AF_INET, &(ipv4->sin_addr), addr_str, ADDR_WIDTH);
	} else if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *ipv6;
		ipv6 = (const struct sockaddr_in6 *)addr;
		r = inet_ntop(AF_INET6, &(ipv6->sin6_addr), addr_str,
			      ADDR_WIDTH);
	} else {
		DEBUG(ERROR,
		      "build_addr_str_from_sockaddr() failed due to "
		      "unsupported ss_family.");
		return NULL;
	}

	if (r == NULL) {
		DEBUG(ERROR, "inet_ntop() failed. %s", strerror(errno));
		return NULL;
	}

	return addr_str;
}

#define PORT_WIDTH 6  // Include null byte
char *build_port_str_from_sockaddr(const struct sockaddr_storage *addr) {
	char *port_str = (char *)calloc(sizeof(char), PORT_WIDTH);
	int n;

	if (addr->ss_family == AF_INET) {
		const struct sockaddr_in *ipv4;
		ipv4 = (const struct sockaddr_in *)addr;
		n = snprintf(port_str, PORT_WIDTH, "%d", ntohs(ipv4->sin_port));
	} else if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *ipv6;
		ipv6 = (const struct sockaddr_in6 *)addr;
		n = snprintf(port_str, PORT_WIDTH, "%d",
			     ntohs(ipv6->sin6_port));
	} else {
		DEBUG(ERROR,
		      "build_port_str_from_sockaddr() failed due to "
		      "unsupported ss_family.");
		return NULL;
	}

	if (n < 0) {
		DEBUG(ERROR, "snprintf() failed. %s", strerror(errno));
		return NULL;
	}
	if (n >= PORT_WIDTH) {
		DEBUG(ERROR, "snprintf() failed (truncated).");
		return NULL;
	}

	return port_str;
}

#define FULL_ADDR_WIDTH 46  // ADDR:PORT\0
char *build_full_str_from_sockaddr(const struct sockaddr *addr) {
	const struct sockaddr_storage *addr_sto;
	addr_sto = (const struct sockaddr_storage *)addr;

	char *full_str = (char *)calloc(sizeof(char), FULL_ADDR_WIDTH);
	char *addr_str = build_addr_str_from_sockaddr(addr_sto);
	char *port_str = build_port_str_from_sockaddr(addr_sto);
	strncat(full_str, addr_str, FULL_ADDR_WIDTH - 1);
	strncat(full_str, ":", (FULL_ADDR_WIDTH - 1) - strlen(full_str));
	strncat(full_str, port_str, (FULL_ADDR_WIDTH - 1) - strlen(full_str));
	free(addr_str);
	free(port_str);
	return full_str;
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

#define KERNEL_WIDTH 30
char *build_kernel() {
	FILE *fp;
	if ((fp = popen("uname -r", "r")) == NULL) {
		DEBUG(ERROR, "open() failed. %s", strerror(errno));
		return NULL;
	}

	char *kernel = (char *)calloc(sizeof(char), KERNEL_WIDTH);
	if (fgets(kernel, KERNEL_WIDTH, fp) == NULL) {
		DEBUG(ERROR,
		      "fgets() failed. Error or end of file occured "
		      "while not characters have been read");
		return NULL;
	}

	if (pclose(fp) == -1) {
		DEBUG(ERROR, "pclose() failed. %s", strerror(errno));
	}

	// Erase \n at last position.
	kernel[strlen(kernel) - 1] = '\0';
	return kernel;
}

// This function is called in DEBUG() thus it cannot itself call DEBUG() 
// otherwise it starts an infinite loop.
char *build_path(const char *file_name) {
	const char *base_path = getenv(ENV_NETSPY_PATH);
	if (base_path == NULL) base_path = NETSPY_DEFAULT_PATH; 
	int full_path_length = strlen(base_path) + strlen(file_name) + 2;
	char *full_path = (char *)malloc(sizeof(char) * full_path_length);
	// We cannot use DEBUG on snprintf error.
	snprintf(full_path, full_path_length, "%s/%s", base_path, file_name);
	return full_path;
}

char *build_json_path() { return build_path(NETSPY_JSON_FILE); }

char *build_log_path() { return build_path(NETSPY_LOG_FILE); }

char *build_pcap_path() { return build_path(NETSPY_PCAP_FILE); }

#define PATH_LENGTH 30
#define CMDLINE_LENGTH 1024
char *build_cmdline(char **app_name) {
	// Build path to /proc/pid/cmdline in path
	char path[PATH_LENGTH];
	pid_t pid = getpid();
	if (snprintf(path, PATH_LENGTH, "/proc/%d/cmdline", pid) >=
	    PATH_LENGTH) {
		DEBUG(ERROR, "snprintf() failed (truncated).");
	}

	// Read /proc/pid/cmdline in cmdline
	FILE *fp = fopen(path, "r");
	if (fp == NULL) DEBUG(ERROR, "fopen() failed. %s", strerror(errno));
	char *cmdline = (char *)malloc(sizeof(char) * CMDLINE_LENGTH);
	size_t rc = fread(cmdline, 1, CMDLINE_LENGTH, fp);
	if (rc == 0) DEBUG(ERROR, "fread() failed.");
	fclose(fp);

	// Replace null bytes between args by white spaces &
	// make char *app_name point to the app_name.
	int i;
	int app_name_length = strlen(cmdline);
	*app_name = (char *)calloc(sizeof(char), app_name_length + 1);
	for (i = 0; i < rc - 1; i++) {
		if (i < app_name_length) (*app_name)[i] = cmdline[i];
		if (cmdline[i] == '\0') cmdline[i] = ' ';
	}

	return cmdline;
}

time_t get_time_sec() {
	struct timeval tv;
	gettimeofday(&tv, NULL);
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
