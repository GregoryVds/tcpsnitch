#include <stdio.h> // fprintf
#include <sys/types.h> // getpid
#include <unistd.h> // getpid

enum debug_level
{
	INFO,
	WARN,
	ERROR
};
typedef enum debug_level debug_level;

#define debug(debug_level, format, fs_args...) { \
	pid_t pid = getpid();\
	char formated_string[1024];\
	snprintf(formated_string, sizeof(formated_string), format, ##fs_args);\
	fprintf(stderr, "%d: %s\n", pid, formated_string);\
}

