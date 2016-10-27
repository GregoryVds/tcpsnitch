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

const char *string_from_debug_level(DebugLevel lvl)
{
	static const char *strings[] = { "INFO", "WARN", "ERROR" };
	return strings[lvl];
}

#define ANSI_COLOR_WHITE 	"\x1b[37m"
#define ANSI_COLOR_RED 		"\x1b[31m"
#define ANSI_COLOR_YELLOW 	"\x1b[33m"
#define ANSI_COLOR_RESET 	"\x1b[0m"

void lib_log(DebugLevel debug_lvl, const char *formated_str, const char *file,
		int line)
{
	pid_t pid = getpid();

	/* Log to stdout */
	if (NETSPY_LOG) {
		const char *color;
		switch (debug_lvl) {
			case INFO:  color = ANSI_COLOR_WHITE; 	break;
			case WARN:  color = ANSI_COLOR_YELLOW; 	break;
			case ERROR: color = ANSI_COLOR_RED; 	break;
		}

		fprintf(stderr, "%s%s-%d(%s:%d): %s%s\n",
				color,
				string_from_debug_level(debug_lvl),
				pid,
				file,
				line,
				formated_str,
				ANSI_COLOR_RESET);
	}

	/* Log to file */
	if (NETSPY_LOG_TO_FILE) {
		char *path = get_log_path();
		FILE *fp = fopen(path, "a");

		unsigned long time_micros = get_time_micros(); 

		fprintf(fp, "%s-pid(%d)-usec(%lu)-file(%s:%d): %s\n",
				string_from_debug_level(debug_lvl),
				pid,
				time_micros,
				file,
				line,
				formated_str);

		fclose(fp); // TODO: This forces a write... Slow.
		free(path);
	}

}

bool is_socket(int fd)
{
	struct stat statbuf;
	fstat(fd, &statbuf);
	return S_ISSOCK(statbuf.st_mode);
}

bool is_inet_socket(int fd)
{
	if (!is_socket(fd)) return false;

	int optval;
	socklen_t optlen = sizeof(optval);
	if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &optval, &optlen) == -1)
		die_with_system_msg("getsockopt() failed");

	return (optval == AF_INET || optval == AF_INET6);
}

bool is_tcp_socket(int fd)
{
	if (!is_inet_socket(fd)) return false;
	
	int optval;
	socklen_t optlen = sizeof(optval);
	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &optval, &optlen) == -1)
		die_with_system_msg("getsockopt() failed");

	return optval == SOCK_STREAM;
}

void die_with_system_msg(const char *msg)
{
	DEBUG(ERROR, "%s. %s.", msg, strerror(errno));
	exit(EXIT_FAILURE);
}

/* Extract IP address to human readable string */

int addr_string_from_sockaddr(const struct sockaddr_storage *addr, char *buf,
		int buf_size)
{
	const char *r;
	if (addr->ss_family==AF_INET) {
		const struct sockaddr_in *ipv4;
		ipv4 = (const struct sockaddr_in *) addr;
		r = inet_ntop(AF_INET, &(ipv4->sin_addr), buf, buf_size);
	}
	else if (addr->ss_family==AF_INET6) {
		const struct sockaddr_in6 *ipv6;
		ipv6 = (const struct sockaddr_in6 *) addr;
		r = inet_ntop(AF_INET6, &(ipv6->sin6_addr), buf, buf_size);
	}
	else {
		DEBUG(ERROR, "addr_string_from_sockaddr() failed due to "
				"unsupported ss_family.");
		return -1;
	}

	if (r == NULL) {
		DEBUG(ERROR, "inet_ntop() failed. %s", strerror(errno));
		return -2;
	}

	return 0;
}

int port_string_from_sockaddr(const struct sockaddr_storage *addr, char *buf, 
		int buf_size)
{
	int n;
	if (addr->ss_family==AF_INET) {
		const struct sockaddr_in *ipv4;
		ipv4 = (const struct sockaddr_in *) addr;
	 	n = snprintf(buf, buf_size, "%d", ntohs(ipv4->sin_port));
	}
	else if (addr->ss_family==AF_INET6) {
		const struct sockaddr_in6 *ipv6;
		ipv6 = (const struct sockaddr_in6 *) addr;
		n = snprintf(buf, buf_size, "%d", ntohs(ipv6->sin6_port));
	}
	else {
		DEBUG(ERROR, "port_string_from_sockaddr() failed due to "
				"unsupported ss_family.");
		return -1;
	}

	if (n < 0) {
		DEBUG(ERROR, "snprintf() failed. %s", strerror(errno));
		return -2;
	}

	if (n >= buf_size) DEBUG(ERROR, "snprintf() failed (truncated).") {
		return -3;
	}

	return 0;
}

int string_from_sockaddr(const struct sockaddr *addr, char *buf, int buf_size)
{
	const struct sockaddr_storage *addr_sto;
	addr_sto = (const struct sockaddr_storage *) addr;
	int n = buf_size-(PORT_WIDTH+1);
	if (addr_string_from_sockaddr(addr_sto, buf, n)	< 0) return -1;
	strncat(buf, ":", 1);
	char port[PORT_WIDTH];
	if (port_string_from_sockaddr(addr_sto, port, PORT_WIDTH) < 0) return -1;
	strncat(buf, port, PORT_WIDTH);
	return 0;
}

int append_string_to_file(const char *str, const char *path) 
{
	FILE *fp = fopen(path, "a");
	if (fp==NULL) {
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

int get_kernel_version(char *buf, int buf_size)
{
	FILE *fp;

	if ((fp = popen("uname -r", "r")) == NULL) {
		DEBUG(ERROR, "open() failed. %s", strerror(errno));
		return -1;
	}

	if (fgets(buf, buf_size, fp) == NULL) {
		DEBUG(ERROR, "fgets() failed. Error or end of file occured "
				"while not characters have been read");
		return -1;
	}

	if (pclose(fp) == -1) {
		DEBUG(ERROR, "pclose() failed. %s", strerror(errno));
		return -1;
	}

	// Erase \n at last position.
	buf[strlen(buf)-1] = '\0';
	return 0;
}

char *build_path(const char *file_name)
{
	const char *base_path = getenv(ENV_NETSPY_PATH);
	if (base_path==NULL) {
		DEBUG(ERROR, "env variable %s not set.", ENV_NETSPY_PATH);
	}

	int full_path_length = strlen(base_path)+strlen(file_name)+2;
	char *full_path = (char *) malloc(sizeof(char)*full_path_length);
	if (snprintf(full_path, full_path_length, "%s/%s", base_path, 
				file_name) >= full_path_length) {
		DEBUG(ERROR, "snprintf() failed (truncated).");
	}
	return full_path;
}

char *get_json_path()
{
	return build_path(NETSPY_JSON_FILE);
}

char *get_log_path()
{
	return build_path(NETSPY_LOG_FILE);
}

char *get_pcap_path()
{
	return build_path(NETSPY_PCAP_FILE);
}

#define PATH_LENGTH 30
#define CMDLINE_LENGTH 1024
char *get_cmdline(char **app_name)
{
	// Build path to /proc/pid/cmdline in path
	char path[PATH_LENGTH];
	pid_t pid = getpid();
	if (snprintf(path, PATH_LENGTH, "/proc/%d/cmdline", 
				pid) >= PATH_LENGTH) {
		DEBUG(ERROR, "snprintf() failed (truncated).");
	}
	
	// Read /proc/pid/cmdline in cmdline
	FILE *fp = fopen(path,"r");
	if (fp==NULL) DEBUG(ERROR, "fopen() failed. %s", strerror(errno)); 
	char *cmdline = (char *) malloc(sizeof(char)*CMDLINE_LENGTH);
	size_t rc = fread(cmdline, 1, CMDLINE_LENGTH, fp);
	if (rc==0) DEBUG(ERROR, "fread() failed.");
	fclose(fp);
	
	// Replace null bytes between args by white spaces & 
	// make char *app_name point to the app_name.
	int i;
	int app_name_length = strlen(cmdline);
	*app_name = (char *) calloc(sizeof(char), app_name_length+1);
	for (i=0; i<rc-1; i++) {
		if (i < app_name_length) (*app_name)[i] = cmdline[i];  
		if (cmdline[i]=='\0') cmdline[i]=' ';
	}

	return cmdline;
}

time_t get_time_sec()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec;
}

/* Retrieve current time in microseconds granularity */
unsigned long get_time_micros()
{
	struct timeval tv;
	gettimeofday(&tv,NULL);
	unsigned long time_micros;
	time_micros = tv.tv_sec*(unsigned long)1000000 + tv.tv_usec;
	return time_micros;
}

/* Retrieve env variable containing a LONG 
 * Return long value or < 0 in case of error:
 * 	-1 if env var not set.
 * 	-2 if env var in incorrect format.
 * 	-3 if env var overflows. */
long get_long_env(const char *env_var)
{
	char *var_str = getenv(env_var);
	if (var_str == NULL) return -1; // Not set
	
	/* Convert from string to long */
	char *var_str_end;
 	long val = strtol(var_str, &var_str_end, 10);
	
	if (*var_str_end != '\0') return -2; // Incorrect format
	if (val == LONG_MIN || val == LONG_MAX) return -3; // Overflow
	return val;
}


