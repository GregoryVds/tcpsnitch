#include "constants.h"
#include <stdio.h>
#include <string.h>
#include "logger.h"

bool alloc_string_from_cons(int cons, const IntStrPair *map, int map_size,
                            char **str_ptr) {
        static const int str_size = MEMBER_SIZE(IntStrPair, str);
        *str_ptr = (char *)my_malloc(str_size);

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
        LOG_FUNC_WARN;
        LOG(WARN, "No match found for %d.", cons);
        snprintf(*str_ptr, str_size, "%d", cons);
        return false;
}

#define MAP_GET(MAP, KEY)                                              \
        {                                                              \
                char *str;                                             \
                int map_size = sizeof(MAP) / sizeof(IntStrPair);       \
                if (!alloc_string_from_cons(KEY, MAP, map_size, &str)) \
                        LOG_FUNC_WARN;                                 \
                return str;                                            \
        }

char *alloc_sock_domain_str(int domain) { MAP_GET(SOCKET_DOMAINS, domain); }

char *alloc_sock_type_str(int type) { MAP_GET(SOCKET_TYPES, type); }

char *alloc_sockopt_level(int level) { MAP_GET(SOCKOPT_LEVELS, level); }

char *alloc_sockopt_name(int level, int optname) {
        switch (level) {
                case SOL_SOCKET:
                        MAP_GET(SOL_SOCKET_OPTIONS, optname);
                case SOL_TCP:
                        MAP_GET(SOL_TCP_OPTIONS, optname);
                case SOL_UDP:
                        MAP_GET(SOL_UDP_OPTIONS, optname);
                case SOL_IP:
                        MAP_GET(SOL_IP_OPTIONS, optname);
                case SOL_IPV6:
                        MAP_GET(SOL_IPV6_OPTIONS, optname);
                case SOL_PACKET:
                        MAP_GET(SOL_PACKET_OPTIONS, optname);
                case SOL_RAW:
                        MAP_GET(SOL_RAW_OPTIONS, optname);
                default:
                        LOG(WARN, "Unknown sockopt level: %d.", level);
                        LOG_FUNC_WARN;
                        MAP_GET(SOL_SOCKET_OPTIONS, optname);
        }
        // Unreachable
        return NULL;
}

char *alloc_fcntl_cmd_str(int cmd) { MAP_GET(FCNTL_CMDS, cmd); }

char *alloc_ioctl_request_str(int request) { MAP_GET(IOCTL_REQUESTS, request); }

char *alloc_errno_str(int err) { MAP_GET(ERRNOS, err); }
