#ifndef LIB_H
#define LIB_H

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

bool is_socket(int fd);
bool is_inet_socket(int fd);
bool is_tcp_socket(int fd);

int append_string_to_file(const char *str, const char *path);

int fill_tcpinfo(int fd, struct tcp_info *info);
int fill_timeval(struct timeval *timeval);

time_t get_time_sec();
unsigned long get_time_micros();

long get_env_as_long(const char *env_var);
int get_int_len(int i);
#endif
