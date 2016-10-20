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
#include "lib.h"

const char *string_from_debug_level(DebugLevel lvl)
{
	static const char *strings[] = { "INFO", "WARN", "ERROR" };
	return strings[lvl];
}

void log(DebugLevel debug_lvl, char *formated_str)
{
	pid_t pid = getpid();

	fprintf(stderr, "%d-%s(%s:%d): %s\n", pid, 
		 string_from_debug_level(debug_lvl), __FILE__, __LINE__,
			formated_str);
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

void addr_string_from_sockaddr(const struct sockaddr_storage *addr, char *buf, 
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
	if (r == NULL) DEBUG(ERROR, "inet_ntop() failed. %s", strerror(errno));	
}

void port_string_from_sockaddr(const struct sockaddr_storage *addr, char *buf, 
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
	if (n < 0) DEBUG(ERROR, "snprintf() failed. %s", strerror(errno));
	if (n >= buf_size) DEBUG(ERROR, "snprintf() failed (truncated).");
}

void string_from_sockaddr(const struct sockaddr *addr, char *buf, int buf_size)
{
	const struct sockaddr_storage *addr_sto;
	addr_sto = (const struct sockaddr_storage *) addr;
	addr_string_from_sockaddr(addr_sto, buf, buf_size-(PORT_WIDTH+1));
	strncat(buf, ":", 1);
	char port[PORT_WIDTH];
	port_string_from_sockaddr(addr_sto, port, PORT_WIDTH);
	strncat(buf, port, PORT_WIDTH);
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
		
	return 0;
}

