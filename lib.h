#ifndef LIB_H
#define LIB_H

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/socket.h>

/* Debugging functions */

typedef enum DebugLevel
{
	INFO,
	WARN,
	ERROR
} DebugLevel;

const char *string_from_debug_level(DebugLevel lvl);

void netspy_log(DebugLevel debug_lvl, const char *formated_str, 
		const char *file, int line); 

#define DEBUG(debug_level, format, args...) {\
	char formated_string[1024];\
	snprintf(formated_string, sizeof(formated_string), format, ##args);\
	netspy_log(debug_level, formated_string, __FILE__, __LINE__);\
}

/* Helper functions */

bool is_socket(int fd);
bool is_inet_socket(int fd);
bool is_tcp_socket(int fd);

/* Others */
int append_string_to_file(const char *str, const char *path);
int fill_timeval(struct timeval *timeval);
time_t get_time_sec();
unsigned long get_time_micros();
long get_long_env(const char *env_var);

#endif

