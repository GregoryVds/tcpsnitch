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

void lib_log(DebugLevel debug_lvl, const char *formated_str, const char *file, int line); 

#define DEBUG(debug_level, format, args...) {\
	char formated_string[1024];\
	snprintf(formated_string, sizeof(formated_string), format, ##args);\
	lib_log(debug_level, formated_string, __FILE__, __LINE__);\
}

void die_with_system_msg(const char *msg);

/* Helper functions */

bool is_socket(int fd);
bool is_inet_socket(int fd);
bool is_tcp_socket(int fd);
#define MEMBER_SIZE(type, member) sizeof(((type *)0)->member)

/* Struct to string helpers */

#define PORT_WIDTH 6 // Include null byte
#define ADDR_WIDTH 40 // Include null byte
#define FULL_ADDR_WIDTH 46 // ADDR:PORT\0

int addr_string_from_sockaddr(const struct sockaddr_storage *addr, 
		char *buf, int buf_size);
int port_string_from_sockaddr(const struct sockaddr_storage *addr, 
		char *buf, int buf_size);
int string_from_sockaddr(const struct sockaddr *addr,
		char *buf, int buf_size);
int get_kernel_version(char *buf, int buf_size);

char *get_cmdline();

/* Other */
int append_string_to_file(const char *str, const char *path);

/* Path helpers */

char *build_path(const char *file_name);
char *get_pcap_path();
char *get_log_path();
char *get_json_path();

unsigned long get_time_micros();
long get_long_env(const char *env_var);

#endif

