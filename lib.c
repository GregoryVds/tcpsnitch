#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include "lib.h"

const char *string_from_debug_level(DebugLevel lvl) {
	static const char *strings[] = { "INFO", "WARN", "ERROR" };
	return strings[lvl];
}

bool is_socket(int fd)
{
	struct stat statbuf;
	fstat(fd, &statbuf);
	return S_ISSOCK(statbuf.st_mode);
}

/* Allows to get a string from a constant.
 * Pre:
 * 	- cons: constant to be matched.
 * 	- buffer: pointer to a char array for writing the matched string.
 *	- buffer_size: size of the buffer char array.
 *	- map: array of ConsStrPair which provides the mapping.
 *	- map_size: number of elements in map.
 * Post:
 * 	- buffer: holds the string corresponding to the constant. If the
 * 	mapping was not found, then contain the constant number as a string.
 * Return:
 * 	- 1 if found a match
 * 	- 0 otherwise
 */

int string_from_cons(int cons, char *buffer, int buffer_size, 
		const IntStrPair *map, int map_size)
{
	int i;
	for (i=0; i<map_size; i++) {
		if ((map+i)->cons==cons) {
			strncpy(buffer, (map+i)->str, buffer_size);
			return 1;
		}
	}
	// No match found, just write the constant digit.
	snprintf(buffer, buffer_size, "%d", cons);
	return 0;
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

