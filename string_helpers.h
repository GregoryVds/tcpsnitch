#ifndef STRING_HELPERS_H
#define STRING_HELPERS_H

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include "tcp_spy.h"

char *alloc_host_str(const struct sockaddr_storage *addr); 
char *alloc_port_str(const struct sockaddr_storage *addr);
char *alloc_addr_str(const struct sockaddr *addr);

char *alloc_concat_path(const char *path1, const char *path2);
char *alloc_append_int_to_path(const char *path1, int i);

char *alloc_con_dirname_str(TcpConnection *con);
char *alloc_con_base_dir_path(TcpConnection *con, const char *netspy_path);

char *alloc_pcap_path_str(TcpConnection *con);
char *alloc_json_path_str(TcpConnection *con);

char *alloc_cmdline_str(char **app_name);
char *alloc_kernel_str();

char *alloc_sock_domain_str(int domain);
char *alloc_sock_type_str(int type);
char *alloc_sock_optname_str(int optname);

char *alloc_error_str(int err);

#endif

