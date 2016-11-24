
#include "string_helpers.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "config.h"
#include "lib.h"
#include "logger.h"

///////////////////////////////////////////////////////////////////////////////

#define ADDR_WIDTH 40  // Include null byte
char *alloc_host_str(const struct sockaddr_storage *addr) {
        char *addr_str = (char *)my_calloc(sizeof(char), ADDR_WIDTH);
        if (!addr_str) goto error_out;

        // Convert host from network to printable
        const char *r;
        if (addr->ss_family == AF_INET) {
                const struct sockaddr_in *v4 = (const struct sockaddr_in *)addr;
                r = inet_ntop(AF_INET, &(v4->sin_addr), addr_str, ADDR_WIDTH);
        } else if (addr->ss_family == AF_INET6) {
                const struct sockaddr_in6 *v6 =
                    (const struct sockaddr_in6 *)addr;
                r = inet_ntop(AF_INET6, &(v6->sin6_addr), addr_str, ADDR_WIDTH);
        } else
                goto error1;

        if (!r) goto error2;
        return addr_str;
error2:
        LOG(ERROR, "inet_ntop() failed. %s.", strerror(errno));
        goto cleanup_out;
error1:
        LOG(ERROR, "Unsupported ss_family: %d.", addr->ss_family);
cleanup_out:
        free(addr_str);
error_out:
        LOG_FUNC_FAIL;
        return NULL;
}

#define PORT_WIDTH 6  // Include null byte
char *alloc_port_str(const struct sockaddr_storage *addr) {
        char *port_str = (char *)my_calloc(sizeof(char), PORT_WIDTH);
        if (!port_str) goto error_out;

        // Convert port to string
        int n;
        if (addr->ss_family == AF_INET) {
                const struct sockaddr_in *v4 = (const struct sockaddr_in *)addr;
                n = snprintf(port_str, PORT_WIDTH, "%d", ntohs(v4->sin_port));
        } else if (addr->ss_family == AF_INET6) {
                const struct sockaddr_in6 *v6 =
                    (const struct sockaddr_in6 *)addr;
                n = snprintf(port_str, PORT_WIDTH, "%d", ntohs(v6->sin6_port));
        } else
                goto error1;

        if (n < 0) goto error2;
        if (n >= PORT_WIDTH) goto error3;
        return port_str;
error3:
        LOG(ERROR, "snprintf() failed (truncated).");
        goto cleanup_out;
error2:
        LOG(ERROR, "snprintf() failed. %s.", strerror(errno));
        goto cleanup_out;
error1:
        LOG(ERROR, "Unsupported ss_family: %d.", addr->ss_family);
cleanup_out:
        free(port_str);
error_out:
        LOG_FUNC_FAIL;
        return NULL;
}

char *alloc_addr_str(const struct sockaddr *addr) {
        static int n = 46;  // ADDR:PORT\0
        const struct sockaddr_storage *addr_sto =
            (const struct sockaddr_storage *)addr;

        char *addr_str, *host_str, *port_str;
        if (!(addr_str = (char *)my_calloc(sizeof(char), n))) goto error_out;
        if (!(host_str = alloc_host_str(addr_sto))) goto error1;
        if (!(port_str = alloc_port_str(addr_sto))) goto error2;

        strncat(addr_str, host_str, n - 1);
        strncat(addr_str, ":", (n - 1) - strlen(addr_str));
        strncat(addr_str, port_str, (n - 1) - strlen(addr_str));

        free(addr_str);
        free(port_str);
        return addr_str;
error2:
        free(host_str);
error1:
        free(addr_str);
error_out:
        LOG_FUNC_FAIL;
        return NULL;
}

///////////////////////////////////////////////////////////////////////////////

char *alloc_concat_path(const char *path1, const char *path2) {
        if (!path1) goto error1;
        if (!path2) goto error2;
        int full_path_length = strlen(path1) + strlen(path2) + 2;
        char *full_path = (char *)my_malloc(sizeof(char) * full_path_length);
        if (!full_path) goto error_out;
        snprintf(full_path, full_path_length, "%s/%s", path1, path2);
        return full_path;
error1:
        LOG(ERROR, "path1 is NULL.");
        goto error_out;
error2:
        LOG(ERROR, "path2 is NULL.");
error_out:
        LOG_FUNC_FAIL;
        return NULL;
}

char *alloc_append_int_to_path(const char *path1, int i) {
        int path1_len = strlen(path1);
        int i_len = get_int_len(i);
        int full_path_length = path1_len + i_len + 2;  // Underscore + null byte
        char *full_path = (char *)my_malloc(sizeof(char) * full_path_length);
        if (!full_path) goto error;
        strncpy(full_path, path1, path1_len);
        snprintf(full_path + path1_len, i_len + 2, "_%d", i);
        return full_path;
error:
        LOG_FUNC_FAIL;
        return NULL;
}

char *alloc_pcap_path_str(TcpConnection *con) {
        return alloc_concat_path(con->directory, NETSPY_PCAP_FILE);
}

char *alloc_json_path_str(TcpConnection *con) {
        return alloc_concat_path(con->directory, NETSPY_JSON_FILE);
}

char *alloc_log_path_str(TcpConnection *con) {
        return alloc_concat_path(con->directory, NETSPY_LOG_FILE);
}

char *alloc_con_base_dir_path(TcpConnection *con, const char *netspy_path) {
        char *con_dirname, *ret;
        if (!(con_dirname = alloc_con_dirname_str(con))) goto error_out;
        if (!(ret = alloc_concat_path(netspy_path, con_dirname))) goto error1;
        free(con_dirname);
        return ret;
error1:
        free(con_dirname);
error_out:
        LOG_FUNC_FAIL;
        return NULL;
}

///////////////////////////////////////////////////////////////////////////////

char *alloc_cmdline_path(void) {
        static int path_length = 30;
        char *path = (char *)my_malloc(sizeof(char)*path_length);
        if (!path) goto error;
        if (snprintf(path, path_length, "/proc/%d/cmdline", getpid()) >=
            path_length)
                goto error;
        return path;
error:
        LOG_FUNC_FAIL;
        return NULL;
}

char *alloc_cmdline_str(void) {
        static int cmd_line_length = 1024;

        // Open cmdline file
        char *cmdline_path = alloc_cmdline_path();
        if (!cmdline_path) goto error_out;

        FILE *fp = fopen(cmdline_path, "r");
        if (!fp) goto error1;
        free(cmdline_path);

        // Read cmdline file into cmdline array
        char *cmdline = (char *)my_malloc(sizeof(char) * cmd_line_length);
        if (!cmdline) goto error2;

        int rc = fread(cmdline, 1, cmd_line_length, fp);
        if (!rc) goto error3;

        fclose(fp);
        return cmdline;
error3:
        LOG(ERROR, "fread() failed. %s.", strerror(errno));
        free(cmdline);
error2:
        fclose(fp);
        goto error_out;
error1:
        LOG(ERROR, "fopen() failed. %s.", strerror(errno));
error_out:
        LOG_FUNC_FAIL;
        return NULL;

}

///////////////////////////////////////////////////////////////////////////////

char *alloc_kernel_str(void) {
        static int kernel_width = 30;
        
        // Open fd to output of "uname -r"
        FILE *fp  = popen("uname -r", "r");
        if (!fp) goto error1;
       
        // Read output into kernel_str
        char *kernel_str = (char *)my_calloc(sizeof(char), kernel_width);
        if (!kernel_str) goto error2;
        if (!fgets(kernel_str, kernel_width, fp)) goto error3;

        pclose(fp);
        // Erase \n at last position.
        kernel_str[strlen(kernel_str) - 1] = '\0';
        return kernel_str;
error1:
        LOG(ERROR, "popen() failed. %s.", strerror(errno));
        goto error_out;
error3:
        LOG(ERROR, "fgets() failed.");
error2:
        pclose(fp);
error_out:
        LOG_FUNC_FAIL;
        return NULL;
}

///////////////////////////////////////////////////////////////////////////////

typedef struct {
        int cons;
        const char str[30];
} IntStrPair;

/* Socket domains */
static const IntStrPair SOCKET_DOMAINS[] = {
    {AF_UNIX, "AF_UNIX"}, {AF_INET, "AF_INET"},       {AF_INET6, "AF_INET6"},
    {AF_IPX, "AF_IPX"},   {AF_NETLINK, "AF_NETLINK"}, {AF_PACKET, "AF_PACKET"}};

/* Socket types */
static const IntStrPair SOCKET_TYPES[] = {{SOCK_STREAM, "SOCK_STREAM"},
                                          {SOCK_DGRAM, "SOCK_DGRAM"},
                                          {SOCK_RAW, "SOCK_RAW"},
                                          {SOCK_RDM, "SOCK_RDM"},
                                          {SOCK_SEQPACKET, "SOCK_SEQPACKET"},
                                          {SOCK_DCCP, "SOCK_DCCP"},
                                          {SOCK_PACKET, "SOCK_PACKET"}};

/* Socket options */
static const IntStrPair SOCKET_OPTIONS[] = {
    // Socket-level options (asm-generic/socket.h)
    {SO_DEBUG, "SO_DEBUG"},
    {SO_BROADCAST, "SO_BROADCAST"},
    {SO_REUSEADDR, "SO_REUSEADDR"},
    {SO_KEEPALIVE, "SO_KEEPALIVE"},
    {SO_LINGER, "SO_KEEPALIVE"},
    {SO_OOBINLINE, "SO_OOBINLINE"},
    {SO_SNDBUF, "SO_SNDBUF"},
    {SO_RCVBUF, "SO_RCVBUF"},
    {SO_DONTROUTE, "SO_DONTROUTE"},
    {SO_RCVLOWAT, "SO_RCVLOWAT"},
    {SO_RCVTIMEO, "SO_RCVTIMEO"},
    {SO_SNDLOWAT, "SO_SNDLOWAT"},
    {SO_SNDTIMEO, "SO_SNDTIMEO"},
    // IP-level options (linux/in.h) Wrong place?
    {IP_TOS, "IP_TOS"},
    {IP_TTL, "IP_TTL"},
    {IP_HDRINCL, "IP_HDRINCL"},
    {IP_OPTIONS, "IP_OPTIONS"},
    {IP_ROUTER_ALERT, "IP_ROUTER_ALERT"},
    {IP_RECVOPTS, "IP_RECVOPTS"},
    {IP_RETOPTS, "IP_RETOPTS"},
    {IP_PKTINFO, "IP_PKTINFO"},
    {IP_PKTOPTIONS, "IP_PKTOPTIONS"},
    {IP_MTU_DISCOVER, "IP_MTU_DISCOVER"},
    {IP_RECVERR, "IP_RECVERR"},
    {IP_RECVTTL, "IP_RECVTTL"},
    {IP_RECVTOS, "IP_RECVTOS"},
    {IP_MTU, "IP_MTU"},
    {IP_FREEBIND, "IP_FREEBIND"},
    {IP_IPSEC_POLICY, "IP_IPSEC_POLICY"},
    {IP_XFRM_POLICY, "IP_XFRM_POLICY"},
    {IP_PASSSEC, "IP_PASSSEC"},
    {IP_TRANSPARENT, "IP_TRANSPARENT"},
    // TCP-level options (netinet/tcp.h)
    {TCP_NODELAY, "TCP_NODELAY"},
    {TCP_MAXSEG, "TCP_MAXSEG"},
    {TCP_CORK, "TCP_CORK"},
    {TCP_KEEPIDLE, "TCP_KEEPIDLE"},
    {TCP_KEEPINTVL, "TCP_KEEPINTVL"},
    {TCP_KEEPCNT, "TCP_KEEPCNT"},
    {TCP_SYNCNT, "TCP_SYNCNT"},
    {TCP_LINGER2, "TCP_LINGER2"},
    {TCP_DEFER_ACCEPT, "TCP_DEFER_ACCEPT"},
    {TCP_WINDOW_CLAMP, "TCP_WINDOW_CLAMP"},
    {TCP_INFO, "TCP_INFO"},
    {TCP_QUICKACK, "TCP_QUICKACK"},
    {TCP_CONGESTION, "TCP_CONGESTION"},
    {TCP_MD5SIG, "TCP_MD5SIG"},
    {TCP_THIN_LINEAR_TIMEOUTS, "TCP_THIN_LINEAR_TIMEOUTS"},
    {TCP_THIN_DUPACK, "TCP_THIN_DUPACK"},
    {TCP_USER_TIMEOUT, "TCP_USER_TIMEOUT"},
    {TCP_REPAIR, "TCP_REPAIR"},
    {TCP_REPAIR_QUEUE, "TCP_REPAIR_QUEUE"},
    {TCP_QUEUE_SEQ, "TCP_QUEUE_SEQ"},
    {TCP_REPAIR_OPTIONS, "TCP_REPAIR_OPTIONS"},
    {TCP_FASTOPEN, "TCP_FASTOPEN"},
    {TCP_TIMESTAMP, "TCP_TIMESTAMP"}};

#define MEMBER_SIZE(type, member) sizeof(((type *)0)->member)

static char *alloc_string_from_cons(int cons, const IntStrPair *map,
                                    int map_size) {
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
        snprintf(str, str_size, "%d", cons);
        return str;
error:
        LOG_FUNC_FAIL;
        return NULL;
}

char *alloc_sock_domain_str(int domain) {
        int map_size = sizeof(SOCKET_DOMAINS) / sizeof(IntStrPair);
        return alloc_string_from_cons(domain, SOCKET_DOMAINS, map_size);
}

char *alloc_sock_type_str(int type) {
        int map_size = sizeof(SOCKET_TYPES) / sizeof(IntStrPair);
        return alloc_string_from_cons(type, SOCKET_TYPES, map_size);
}

char *alloc_sock_optname_str(int optname) {
        int map_size = sizeof(SOCKET_OPTIONS) / sizeof(IntStrPair);
        return alloc_string_from_cons(optname, SOCKET_OPTIONS, map_size);
}

///////////////////////////////////////////////////////////////////////////////

char *alloc_error_str(int err) {
        char *ori_str = strerror(err);
        size_t str_len = strlen(ori_str) + 1;
        char *alloc_str = (char *)my_malloc(str_len);
        if (!alloc_str) goto error;
        strncpy(alloc_str, ori_str, str_len);
        return alloc_str;
error:
        LOG_FUNC_FAIL;
        return NULL;
}

//////////////////////////////////////////////////////////////////////////////
