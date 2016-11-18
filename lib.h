#ifndef LIB_H
#define LIB_H

#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define IF_NULL_ABORT(val, err...)  \
	if (val == NULL) {          \
		LOG(ERROR, ##err); \
		return NULL;        \
	}

bool is_socket(int fd);
bool is_inet_socket(int fd);
bool is_tcp_socket(int fd);

int append_string_to_file(const char *str, const char *path);

int fill_tcpinfo(int fd, struct tcp_info *info);
int fill_timeval(struct timeval *timeval);

time_t get_time_sec(void);
unsigned long get_time_micros(void);

long get_env_as_long(const char *env_var);
int get_int_len(int i);

bool lock(pthread_mutex_t *mutex);
bool unlock(pthread_mutex_t *mutex);
bool init_errorcheck_mutex(pthread_mutex_t *mutex);

const char *get_app_name(void);

#endif
