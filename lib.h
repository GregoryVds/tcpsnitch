#ifndef LIB_H
#define LIB_H

#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>

#define UNUSED(x) (void)(x)

bool is_fd(int fd);
bool is_socket(int fd);
bool is_inet_socket(int fd);
bool is_tcp_socket(int fd);

int append_string_to_file(const char *str, const char *path);

int fill_tcpinfo(int fd, struct tcp_info *info);
int fill_timeval(struct timeval *timeval);

time_t get_time_sec(void);
unsigned long get_time_micros(void);

long parse_long(const char *str);
long get_env_as_long(const char *env_var);
char *get_str_env(const char *env_var);
#ifdef __ANDROID__
long get_property_as_long(const char *property);
#endif
long get_long_opt_or_defaultval(const char *opt, long def_val);
int get_int_len(int i);

bool mutex_lock(pthread_mutex_t *mutex);
bool mutex_unlock(pthread_mutex_t *mutex);
bool mutex_destroy(pthread_mutex_t *mutex);
bool mutex_init(pthread_mutex_t *mutex);

void *my_malloc(size_t size);
void *my_calloc(size_t nmemb, size_t size);
int my_fputs(const char *s, FILE *stream);

char *create_numbered_dir_in_path(const char *path, int dir_number);
bool is_dir_writable(const char *path);

#endif
