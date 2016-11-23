#define _GNU_SOURCE  // For program_invocation_name

#include "lib.h"
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include "logger.h"

///////////////////////////////////////////////////////////////////////////////

bool is_fd(int fd) {
        return fcntl(fd, F_GETFD) != -1 || errno != EBADF;
}

bool is_socket(int fd) {
        if (!is_fd(fd)) return false;
        struct stat statbuf;
        if (fstat(fd, &statbuf)) goto error;
        return S_ISSOCK(statbuf.st_mode);
error:
        LOG(ERROR, "fstat() failed. %s.", strerror(errno));
        LOG_FUNC_FAIL;
        LOG(ERROR, "Assume fd is not a socket.");
        return false;
}

bool is_inet_socket(int fd) {
        if (!is_socket(fd)) return false;
        int optval;
        socklen_t optlen = sizeof(optval);
        if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &optval, &optlen)) goto error;
        return (optval == AF_INET || optval == AF_INET6);
error:
        LOG(ERROR, "getsockopt() failed. %s.", strerror(errno));
        LOG_FUNC_FAIL; 
        LOG(ERROR, "Assume socket is not a INET socket.");
        return false;
}

bool is_tcp_socket(int fd) {
        if (!is_inet_socket(fd)) return false;
        int optval;
        socklen_t optlen = sizeof(optval);
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &optval, &optlen)) goto error;
        return optval == SOCK_STREAM;
error:
        LOG(ERROR, "getsockopt() failed. %s.", strerror(errno));
        LOG_FUNC_FAIL; 
        LOG(ERROR, "Assume INRY socket is not a TCP socket.");
        return false;
}

///////////////////////////////////////////////////////////////////////////////

int append_string_to_file(const char *str, const char *path) {
        FILE *fp = fopen(path, "a");
        if (!fp) goto error1; 
        if (fputs(str, fp) == EOF) goto error2;
        if (fclose(fp) == EOF) goto error3;
        return 0;
error3:
        LOG(ERROR, "fclose() failed. %s.", strerror(errno));
        goto error_out;
error2:
        fclose(fp);
        LOG(ERROR, "fputs() failed.");
        goto error_out;
error1:
        LOG(ERROR, "fopen() failed. %s.", strerror(errno));
        goto error_out;
error_out:
        LOG_FUNC_FAIL;
        return -1;
}

///////////////////////////////////////////////////////////////////////////////

int fill_timeval(struct timeval *timeval) {
        if (gettimeofday(timeval, NULL)) goto error;
        return 0;
error:
        LOG(ERROR, "gettimeofday() failed. %s.", strerror(errno));
        LOG_FUNC_FAIL;
        return -1;
}

int fill_tcpinfo(int fd, struct tcp_info *info) {
        socklen_t n = sizeof(struct tcp_info);
        if (getsockopt(fd, SOL_TCP, TCP_INFO, (void *)&info, &n)) goto error;
        return 0;
error:
        LOG(ERROR, "getsockopt() failed. %s.", strerror(errno));
        LOG_FUNC_FAIL;
        return -1;
}

///////////////////////////////////////////////////////////////////////////////

time_t get_time_sec() {
        struct timeval tv;
        if (fill_timeval(&tv)) goto error;
        return tv.tv_sec;
error:
        LOG_FUNC_FAIL;
        return 0;
}

unsigned long get_time_micros() {
        struct timeval tv;
        if (fill_timeval(&tv)) goto error;
        unsigned long time_micros;
        time_micros = tv.tv_sec * (unsigned long)1000000 + tv.tv_usec;
        return time_micros;
error:
        LOG_FUNC_FAIL;
        return 0;
}

///////////////////////////////////////////////////////////////////////////////

/* Retrieve env variable containing a LONG
 * Return long value or < 0 in case of error:
 * 	-1 if env var not set.
 * 	-2 if env var in incorrect format.
 * 	-3 if env var overflows. */

long get_env_as_long(const char *env_var) {
        char *var_str = getenv(env_var);
        if (var_str == NULL) return -1;  // Not set

        /* Convert from string to long */
        char *var_str_end;
        long val = strtol(var_str, &var_str_end, 10);

        if (*var_str_end != '\0') return -2;                // Incorrect format
        if (val == LONG_MIN || val == LONG_MAX) return -3;  // Overflow
        return val;
}

////////////////////////////////////////////////////////////////////////////////

int get_int_len(int i) {
        int l = 1;
        while (i > 9) {
                l++;
                i = i / 10;
        }
        return l;
}

////////////////////////////////////////////////////////////////////////////////

bool lock(pthread_mutex_t *mutex) {
        int rc = pthread_mutex_lock(mutex);
        if (rc != 0) {
                LOG(ERROR, "pthread_mutex_lock() failed. %s.", strerror(rc));
                return false;
        }
        return true;
}

bool unlock(pthread_mutex_t *mutex) {
        int rc = pthread_mutex_unlock(mutex);
        if (rc != 0) {
                LOG(ERROR, "pthread_mutex_unlock() failed. %s.", strerror(rc));
                return false;
        }
        return true;
}

bool mutex_destroy(pthread_mutex_t *mutex) {
        int rc = pthread_mutex_destroy(mutex);
        if (rc != 0)
                LOG(ERROR, "pthread_mutex_destroy() failed. %s.", strerror(rc));
        return rc == 0;
}

bool mutex_init(pthread_mutex_t *mutex) {
        pthread_mutexattr_t attr;
        int rc;
        if ((rc = pthread_mutexattr_init(&attr)) ||
            (rc = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK)) ||
            (rc = pthread_mutex_init(mutex, &attr)) ||
            (rc = pthread_mutexattr_destroy(&attr))) {
                LOG(ERROR, "mutex_init() failed. %s.", strerror(rc));
                return false;
        }

        return true;
}

const char *get_app_name(void) {
        char *app_name, *last = strrchr(program_invocation_name, '/');
        if (last == NULL)
                app_name = program_invocation_name;
        else
                app_name = last + 1;

        return app_name;
}

void *my_malloc(size_t size) {
        void *ret = malloc(size);
        if (!ret) LOG(ERROR, "malloc() failed.");
        return ret;
}

void *my_calloc(size_t nmemb, size_t size) {
        void *ret = calloc(nmemb, size);
        if (!ret) LOG(ERROR, "malloc() failed.");
        return ret;
}
