#include "constant_strings.h"
#include <string.h>
#include "lib.h"
#include "logger.h"

char *alloc_string_from_cons(int cons, const IntStrPair *map, int map_size) {
        static const int str_size = MEMBER_SIZE(IntStrPair, str);
        char *str = (char *)my_malloc(str_size);
        if (!str) goto error;

        // Search for const in map.
        const IntStrPair *cur;
        for (int i = 0; i < map_size; i++) {
                cur = (map + i);
                if (cur->cons == cons) {
                        strncpy(str, cur->str, str_size);
                        return str;
                }
        }

        // No match found, just write the constant digit.
        LOG(WARN, "alloc_string_from_cons: no match found for %d.", cons);
        snprintf(str, str_size, "%d", cons);
        return str;
error:
        LOG_FUNC_FAIL;
        return NULL;
}

#define EXTRACT_FROM_MAP(MAP, KEY)                       \
        int map_size = sizeof(MAP) / sizeof(IntStrPair); \
        return alloc_string_from_cons(KEY, MAP, map_size);

char *alloc_sock_domain_str(int domain) {
        EXTRACT_FROM_MAP(SOCKET_DOMAINS, domain);
}

char *alloc_sock_type_str(int type) { EXTRACT_FROM_MAP(SOCKET_TYPES, type); }

char *alloc_sock_optname_str(int optname) {
        EXTRACT_FROM_MAP(SOCKET_OPTIONS, optname);
}

char *alloc_fcntl_cmd_str(int cmd) { EXTRACT_FROM_MAP(FCNTL_CMDS, cmd); }

char *alloc_ioctl_request_str(int request) {
        EXTRACT_FROM_MAP(IOCTL_REQUESTS, request);
}
