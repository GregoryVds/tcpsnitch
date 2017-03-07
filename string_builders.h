#ifndef STRING_HELPERS_H
#define STRING_HELPERS_H

#include <sys/socket.h>
#include "sock_events.h"

char *alloc_ip_str(const struct sockaddr *addr);
char *alloc_port_str(const struct sockaddr *addr);
char *alloc_addr_str(const struct sockaddr *addr);
bool alloc_name_str(const struct sockaddr *addr, socklen_t len, char **name,
                    char **serv);

char *alloc_concat_path(const char *path1, const char *path2);
char *alloc_append_int_to_path(const char *path1, int i);

char *alloc_dirname_str(void);
char *alloc_android_opt_d(void);
char *alloc_pcap_path_str(SocketState *con);
char *alloc_json_path_str(SocketState *con);

char *alloc_cmdline_str(void);
char *alloc_app_name(void);
char *alloc_kernel_str(void);

char *alloc_error_str(int err);

#ifdef __ANDROID__
char *alloc_property(const char *property);
#endif

char *alloc_str_opt(const char *opt);
#endif
