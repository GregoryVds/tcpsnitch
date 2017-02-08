#ifndef STRING_HELPERS_H
#define STRING_HELPERS_H

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include "tcp_events.h"

char *alloc_ip_str(const struct sockaddr *addr);
char *alloc_port_str(const struct sockaddr *addr);
char *alloc_addr_str(const struct sockaddr *addr);
bool alloc_name_str(const struct sockaddr *addr, socklen_t len, char **name,
                    char **serv);

char *alloc_concat_path(const char *path1, const char *path2);
char *alloc_append_int_to_path(const char *path1, int i);

char *alloc_dirname_str(void);
char *alloc_android_opt_d(void);
char *alloc_pcap_path_str(TcpConnection *con);
char *alloc_json_path_str(TcpConnection *con);

char *alloc_cmdline_str(void);
char *alloc_app_name(void);
char *alloc_kernel_str(void);

char *alloc_sock_domain_str(int domain);
char *alloc_sock_type_str(int type);
char *alloc_sock_optname_str(int optname);

char *alloc_error_str(int err);

#endif
