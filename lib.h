#ifndef LIB_H
#define LIB_H

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>

/* Debugging functions */

typedef enum DebugLevel
{
	INFO,
	TCP,
	WARN,
	ERROR
} DebugLevel;

const char *string_from_debug_level(DebugLevel lvl);

#define DEBUG(debug_level, format, args...) {\
	pid_t pid = getpid();\
	char formated_string[1024];\
	snprintf(formated_string, sizeof(formated_string), format, ##args);\
	fprintf(stderr, "%d %s: %s\n", pid,\
		string_from_debug_level(debug_level), formated_string);\
}

void die_with_system_msg(const char *msg);

/* Helper functions */

bool is_socket(int fd);
bool is_inet_socket(int fd);
bool is_tcp_socket(int fd);

#define MEMBER_SIZE(type, member) sizeof(((type *)0)->member)

void string_from_sockaddr(const struct sockaddr *addr, char *buf, int buf_size);

#endif

