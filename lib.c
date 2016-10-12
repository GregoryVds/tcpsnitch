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

const char *string_from_debug_level(DebugLevel lvl) {
	static const char *strings[] = { "INFO", "TCP", "WARN", "ERROR" };
	return strings[lvl];
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

#define PORT_WIDTH 6

void string_from_sockaddr(const struct sockaddr *addr, char *buf, int buf_size)
{
	const struct sockaddr_storage *addr_sto;
	addr_sto = (const struct sockaddr_storage *) addr;
	char port[PORT_WIDTH];

	if (addr_sto->ss_family==AF_INET) {
		const struct sockaddr_in *ipv4;
		ipv4 = (const struct sockaddr_in *) addr;
		inet_ntop(AF_INET, &(ipv4->sin_addr), buf, buf_size);
		snprintf(port, PORT_WIDTH, ":%d", ntohs(ipv4->sin_port));
	}
	else if (addr_sto->ss_family==AF_INET6) {
		const struct sockaddr_in6 *ipv6;
		ipv6 = (const struct sockaddr_in6 *) addr;
		inet_ntop(AF_INET6, &(ipv6->sin6_addr), buf, buf_size);
		snprintf(port, PORT_WIDTH, ":%d", ntohs(ipv6->sin6_port));
	}
	strncat(buf, port, PORT_WIDTH);
}

