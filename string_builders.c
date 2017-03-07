#define _GNU_SOURCE

#include "string_builders.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef __ANDROID__
#include <sys/system_properties.h>
#endif
#include <sys/types.h>
#include "constants.h"
#include "lib.h"
#include "logger.h"

char *alloc_ip_str(const struct sockaddr *addr) {
        static const int n = INET6_ADDRSTRLEN;
        char *addr_str = (char *)my_calloc(sizeof(char) * n);
        if (!addr_str) goto error_out;

        // Convert host from network to printable
        const char *r;
        if (addr->sa_family == AF_INET) {
                const struct sockaddr_in *v4 = (const struct sockaddr_in *)addr;
                r = inet_ntop(AF_INET, &(v4->sin_addr), addr_str, n);
        } else if (addr->sa_family == AF_INET6) {
                const struct sockaddr_in6 *v6 =
                    (const struct sockaddr_in6 *)addr;
                r = inet_ntop(AF_INET6, &(v6->sin6_addr), addr_str, n);
        } else
                goto error1;

        if (!r) goto error2;
        return addr_str;
error2:
        LOG(ERROR, "inet_ntop() failed. %s.", strerror(errno));
        goto cleanup_out;
error1:
        LOG(ERROR, "Unsupported sa_family: %d.", addr->sa_family);
cleanup_out:
        free(addr_str);
error_out:
        LOG_FUNC_FAIL;
        return NULL;
}

char *alloc_port_str(const struct sockaddr *addr) {
        static const int PORT_WIDTH = 6;

        char *port_str = (char *)my_calloc(sizeof(char) * PORT_WIDTH);
        if (!port_str) goto error_out;

        // Convert port to string
        int n;
        if (addr->sa_family == AF_INET) {
                const struct sockaddr_in *v4 = (const struct sockaddr_in *)addr;
                n = snprintf(port_str, PORT_WIDTH, "%d", ntohs(v4->sin_port));
        } else if (addr->sa_family == AF_INET6) {
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
        LOG(ERROR, "Unsupported sa_family: %d.", addr->sa_family);
cleanup_out:
        free(port_str);
error_out:
        LOG_FUNC_FAIL;
        return NULL;
}

char *alloc_addr_str(const struct sockaddr *addr) {
        static const int n = 46;  // ADDR:PORT\0

        char *addr_str, *host_str, *port_str;
        if (!(addr_str = (char *)my_calloc(sizeof(char) * n))) goto error_out;
        if (!(host_str = alloc_ip_str(addr))) goto error1;
        if (!(port_str = alloc_port_str(addr))) goto error2;

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

bool alloc_name_str(const struct sockaddr *addr, socklen_t len, char **name,
                    char **serv) {
        if (!(*name = my_malloc(sizeof(char) * NI_MAXHOST))) goto error_out;
        if (!(*serv = my_malloc(sizeof(char) * NI_MAXSERV))) goto error_out;
        int rc =
            getnameinfo(addr, len, *name, NI_MAXHOST, *serv, NI_MAXSERV, 0);
        if (rc) goto error;
        return true;
error:
        LOG(ERROR, "getnameinfo() failed. %s.", gai_strerror(rc));
error_out:
        LOG_FUNC_FAIL;
        return false;
}

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

char *alloc_dirname_str(void) {
        // Base directory name is [APP_NAME]_[TIMESTAMP]_[PID]
        // Prepare components
        char *app_name = alloc_app_name();
        if (!app_name) goto error;

        int app_name_len = strlen(app_name);
        static int timestamp_len = 10;
        int pid = getpid();
        int pid_len = get_int_len(pid);
        int n = app_name_len + timestamp_len + pid_len + 3;  // 3 '_','_','\0'

        char *str = (char *)my_calloc(sizeof(char) * n);
        if (!str) goto error;

        // Build string
        strncat(str, app_name, app_name_len);
        strncat(str, "_", 1);
        snprintf(str + strlen(str), timestamp_len + 1, "%lu", get_time_sec());
        strncat(str, "_", 1);
        snprintf(str + strlen(str), pid_len + 1, "%d", pid);
        free(app_name);
        return str;
error:
        LOG_FUNC_FAIL;
        return NULL;
}

// On Android, we don't chose the logs directory. We always write under:
// /data/data/[app_name], which the internal storage of the app.
char *alloc_android_opt_d(void) {
        char *app_name = alloc_app_name();
        const char *prefix = "/data/data/";
        const char *sufix = "/tcpsnitch";
        int n = strlen(prefix) + strlen(app_name) + strlen(sufix) + 1;
        char *opt_d = (char *)my_malloc(sizeof(char) * n);
        if (!opt_d) goto error;
        sprintf(opt_d, "%s%s%s", prefix, app_name, sufix);
        free(app_name);
        return opt_d;
error:
        LOG_FUNC_FAIL;
        return NULL;
}

char *alloc_pcap_path_str(TcpConnection *con) {
        return alloc_concat_path(con->directory, PCAP_FILE);
}

char *alloc_json_path_str(TcpConnection *con) {
        return alloc_concat_path(con->directory, JSON_FILE);
}

char *alloc_cmdline_str(void) {
        static int cmd_line_length = 1024;

        FILE *fp = fopen("/proc/self/cmdline", "r");
        if (!fp) goto error1;

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

char *alloc_app_name(void) {
        char *cmdline = alloc_cmdline_str();
        if (!cmdline) goto error_out;

        char *app_name_start = strrchr(cmdline, '/');
        if (app_name_start)
                app_name_start += 1;
        else
                return cmdline;

        int n = strlen(app_name_start) + 1;
        char *app_name = (char *)my_malloc(sizeof(char) * n);
        strncpy(app_name, app_name_start, n);
        free(cmdline);
        return app_name;
error_out:
        LOG_FUNC_FAIL;
        return NULL;
}

char *alloc_kernel_str(void) {
        static int kernel_width = 30;

        // Open fd to output of "uname -r"
        FILE *fp = popen("uname -r", "r");
        if (!fp) goto error1;

        // Read output into kernel_str
        char *kernel_str = (char *)my_calloc(sizeof(char) * kernel_width);
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

#ifdef __ANDROID__
char *alloc_property(const char *property) {
        char *prop = my_malloc(sizeof(char)*(PROP_VALUE_MAX+1));
        if (!prop) goto error;
        int n = __system_property_get(property, prop);
        if (!n) goto error1;
        return prop;
error1:
        LOG(ERROR, "__system_property_get() failed.");
error:
        LOG_FUNC_FAIL;
        return NULL;
}
#endif

char *alloc_str_opt(const char *opt) {
#ifdef __ANDROID__
        return alloc_property(opt);
#else
        char *env_val = get_str_env(opt);
        if (!env_val) goto error;
        int n = strlen(env_val) + 1;
        char *opt_str = (char *)my_malloc(n * sizeof(char));
        if (!opt_str) goto error1;
        strncpy(opt_str, env_val, n);
        return opt_str;
error:
        LOG(ERROR, "Env %s was not set", opt);
error1:
        LOG_FUNC_FAIL;
        return NULL;
#endif
}
