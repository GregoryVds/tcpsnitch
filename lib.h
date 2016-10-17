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
	WARN,
	ERROR
} DebugLevel;

const char *string_from_debug_level(DebugLevel lvl);

void log(DebugLevel debug_lvl, char *formated_str); 

#define DEBUG(debug_level, format, args...) {\
	char formated_string[1024];\
	snprintf(formated_string, sizeof(formated_string), format, ##args);\
	log(debug_level, formated_string);\
}

void die_with_system_msg(const char *msg);

/* Helper functions */

bool is_socket(int fd);
bool is_inet_socket(int fd);
bool is_tcp_socket(int fd);

#define PORT_WIDTH 6
#define MEMBER_SIZE(type, member) sizeof(((type *)0)->member)
void addr_string_from_sockaddr(const struct sockaddr_storage *addr, char *buf, 
		int buf_size);
void port_string_from_sockaddr(const struct sockaddr_storage *addr, char *buf, 
		int buf_size);

void string_from_sockaddr(const struct sockaddr *addr, char *buf, int buf_size);

int append_string_to_file(const char *str, const char *path);

#endif

