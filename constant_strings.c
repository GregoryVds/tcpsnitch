#include "constant_strings.h"
#include <string.h>
#include "lib.h"
#include "logger.h"

bool alloc_string_from_cons(int cons, const IntStrPair *map, int map_size,
                            char **str_ptr) {
        static const int str_size = MEMBER_SIZE(IntStrPair, str);
        *str_ptr = (char *)my_malloc(str_size);
        if (!*str_ptr) goto error;

        // Search for const in map.
        const IntStrPair *cur;
        for (int i = 0; i < map_size; i++) {
                cur = (map + i);
                if (cur->cons == cons) {
                        strncpy(*str_ptr, cur->str, str_size);
                        return true;
                }
        }

        // No match found, just write the constant digit.
        LOG(WARN, "alloc_string_from_cons: no match found for %d.", cons);
        snprintf(*str_ptr, str_size, "%d", cons);
        return false;
error:
        LOG_FUNC_ERROR;
        return false;
}

#define MAP_GET(MAP, KEY)                                                     \
        char *str;                                                            \
        int map_size = sizeof(MAP) / sizeof(IntStrPair);                      \
        if (!alloc_string_from_cons(KEY, MAP, map_size, &str)) LOG_FUNC_WARN; \
        return str;

char *alloc_sock_domain_str(int domain) { MAP_GET(SOCKET_DOMAINS, domain); }

char *alloc_sock_type_str(int type) { MAP_GET(SOCKET_TYPES, type); }

char *alloc_sockopt_level(int level) { MAP_GET(SOCKOPT_LEVELS, level); }

char *alloc_sol_socket_sockopt(int opt) { MAP_GET(SOL_SOCKET_OPTIONS, opt); }

char *alloc_ipproto_ip_sockopt(int opt) { MAP_GET(IPPROTO_IP_OPTIONS, opt); }

char *alloc_ipproto_ipv6_sockopt(int opt) {
        MAP_GET(IPPROTO_IPV6_OPTIONS, opt);
}

char *alloc_ipproto_tcp_sockopt(int opt) { MAP_GET(IPPROTO_TCP_OPTIONS, opt); }

char *alloc_fcntl_cmd_str(int cmd) { MAP_GET(FCNTL_CMDS, cmd); }

char *alloc_ioctl_request_str(int request) { MAP_GET(IOCTL_REQUESTS, request); }
