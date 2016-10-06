#ifndef LIB_H
#define LIB_H

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>

enum DebugLevel
{
	INFO,
	WARN,
	ERROR
};
typedef enum DebugLevel DebugLevel;

const char *string_from_debug_level(DebugLevel lvl);

#define DEBUG(debug_level, format, args...) {\
	pid_t pid = getpid();\
	char formated_string[1024];\
	snprintf(formated_string, sizeof(formated_string), format, ##args);\
	fprintf(stderr, "%d %s: %s\n", pid,\
		string_from_debug_level(debug_level), formated_string);\
}


bool is_socket(int fd);

#define MEMBER_SIZE(type, member) sizeof(((type *)0)->member)

typedef struct {
	int cons;
	const char str[30]; 
} IntStrPair;

int string_from_cons(int cons, char *buffer, int buffer_size, 
		const IntStrPair *map, int map_size);

#endif

