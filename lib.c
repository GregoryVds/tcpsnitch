#define _GNU_SOURCE  // For program_invocation_name

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef __ANDROID__
#include <sys/system_properties.h>
#endif
#include "lib.h"
#include "logger.h"
#include "string_builders.h"

// We don't want to call the getsockopt we defined as it would be intercepted.
typedef int (*orig_getsockopt_type)(int sockfd, int level, int optname,
				    void *optval, socklen_t *optlen);

orig_getsockopt_type orig_getsockopt;

int my_getsockopt(int sockfd, int level, int optname, void *optval,
		  socklen_t *optlen) {
	if (!orig_getsockopt)
		orig_getsockopt =
		    (orig_getsockopt_type)dlsym(RTLD_NEXT, "getsockopt");
	return orig_getsockopt(sockfd, level, optname, optval, optlen);
}

bool is_fd(int fd) { return fcntl(fd, F_GETFD) != -1 || errno != EBADF; }

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
	if (my_getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &optval, &optlen))
		goto error;
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
	if (my_getsockopt(fd, SOL_SOCKET, SO_TYPE, &optval, &optlen))
		goto error;
	return optval == SOCK_STREAM;
error:
	LOG(ERROR, "getsockopt() failed. %s.", strerror(errno));
	LOG_FUNC_FAIL;
	LOG(ERROR, "Assume socket is not a TCP socket.");
	return false;
}

int append_string_to_file(const char *str, const char *path) {
	FILE *fp = fopen(path, "a");
	if (!fp) goto error1;
	if (fputs(str, fp) == EOF) goto error2;
	if (fclose(fp) == EOF) goto error3;
	return 0;
error1:
	LOG(ERROR, "fopen() failed. %s.", strerror(errno));
	goto error_out;
error2:
	fclose(fp);
	LOG(ERROR, "fputs() failed.");
	goto error_out;
error3:
	LOG(ERROR, "fclose() failed. %s.", strerror(errno));
error_out:
	LOG_FUNC_FAIL;
	return -1;
}

int fill_timeval(struct timeval *timeval) {
	if (gettimeofday(timeval, NULL)) goto error;
	return 0;
error:
	LOG(ERROR, "gettimeofday() failed. %s.", strerror(errno));
	LOG_FUNC_FAIL;
	return -1;
}

int fill_tcp_info(int fd, struct tcp_info *info) {
	socklen_t n = sizeof(struct tcp_info);
	if (my_getsockopt(fd, SOL_TCP, TCP_INFO, (void *)info, &n)) goto error;
	return 0;
error:
	LOG(ERROR, "getsockopt() failed. %s.", strerror(errno));
	LOG_FUNC_FAIL;
	return -1;
}

time_t get_time_sec(void) {
	struct timeval tv;
	if (fill_timeval(&tv)) goto error;
	return tv.tv_sec;
error:
	LOG_FUNC_FAIL;
	return 0;
}

unsigned long get_time_micros(void) {
	struct timeval tv;
	if (fill_timeval(&tv)) goto error;
	unsigned long time_micros;
	time_micros = tv.tv_sec * (unsigned long)1000000 + tv.tv_usec;
	return time_micros;
error:
	LOG_FUNC_FAIL;
	return 0;
}

long parse_long(const char *str) {
	char *str_end;
	long val = strtol(str, &str_end, 10);
	if (*str_end != '\0') goto error1;
	if (val == LONG_MIN || val == LONG_MAX) goto error2;
	return val;
error1:
	LOG(ERROR, "strtol() failed. Incorrect format.");
	goto error_out;
error2:
	LOG(ERROR, "strtol() failed. Overflow.");
error_out:
	LOG_FUNC_FAIL;
	return -1;
}

long get_env_as_long(const char *env_var) {
	char *var_str = getenv(env_var);
	if (var_str == NULL) goto error;
	return parse_long(var_str);
error:
	LOG(ERROR, "getenv() failed. Variable %s is not set.", env_var);
	LOG_FUNC_FAIL;
	return -1;
}

char *get_str_env(const char *env_var) {
	char *val = getenv(env_var);
	if (!val) return NULL;
	return strlen(val) ? val : NULL;
}

#ifdef __ANDROID__
long get_property_as_long(const char *property) {
	char val[PROP_VALUE_MAX + 1];
	int n = __system_property_get(property, val);
	if (!n) goto error;
	return parse_long(val);
error:
	LOG(ERROR, "property not defined or empty.");
	LOG_FUNC_FAIL;
	return -1;
}
#endif

long get_long_opt_or_defaultval(const char *opt, long def_val) {
#ifdef __ANDROID__
	long val = get_property_as_long(opt);
#else
	long val = get_env_as_long(opt);
#endif
	if (val < 0) LOG(WARN, "%s incorrect. Defaults to %lu.", opt, def_val);
	return val;
}

int get_int_len(int i) {
	if (i < 0) goto error;
	int l = 1;
	while (i > 9) {
		l++;
		i = i / 10;
	}
	return l;
error:
	LOG_FUNC_FAIL;
	LOG(ERROR, "Negative numbers not supported.");
	return 0;
}

bool mutex_lock(pthread_mutex_t *mutex) {
	int rc = pthread_mutex_lock(mutex);
	if (rc) goto error;
	return true;
error:
	LOG(ERROR, "pthread_mutex_lock() failed. %s.", strerror(rc));
	LOG_FUNC_FAIL;
	return false;
}

bool mutex_unlock(pthread_mutex_t *mutex) {
	int rc = pthread_mutex_unlock(mutex);
	if (rc) goto error;
	return true;
error:
	LOG(ERROR, "pthread_mutex_unlock() failed. %s.", strerror(rc));
	LOG_FUNC_FAIL;
	return false;
}

bool mutex_destroy(pthread_mutex_t *mutex) {
	int rc = pthread_mutex_destroy(mutex);
	if (rc) goto error;
	return true;
error:
	LOG(ERROR, "pthread_mutex_destroy() failed. %s.", strerror(rc));
	LOG_FUNC_FAIL;
	return false;
}

bool mutex_init(pthread_mutex_t *mutex) {
	pthread_mutexattr_t attr;
	int rc;
	if ((rc = pthread_mutexattr_init(&attr)) ||
	    (rc = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK)) ||
	    (rc = pthread_mutex_init(mutex, &attr)) ||
	    (rc = pthread_mutexattr_destroy(&attr)))
		goto error;
	return true;
error:
	LOG(ERROR, "mutex_init() failed. %s.", strerror(rc));
	LOG_FUNC_FAIL;
	return false;
}

void *my_malloc(size_t size) {
	void *ret = malloc(size);
	if (!ret) goto error;
	return ret;
error:
	LOG(ERROR, "malloc() failed.");
	LOG_FUNC_FAIL;
	return NULL;
}

void *my_calloc(size_t nmemb, size_t size) {
	void *ret = calloc(nmemb, size);
	if (!ret) goto error;
	return ret;
error:
	LOG(ERROR, "calloc() failed.");
	LOG_FUNC_FAIL;
	return NULL;
}

int my_fputs(const char *s, FILE *stream) {
	int ret = fputs(s, stream);
	if (ret == EOF) goto error;
	return ret;
error:
	LOG(ERROR, "fputs() failed. %s.", strerror(errno));
	LOG_FUNC_FAIL;
	return ret;
}

char *create_numbered_dir_in_path(const char *path, int dir_number) {
	char *dirname, *dir_path;
	int n;
	if (!path) goto error1;

	// Build string "[path]/[dir_number] in dir_path"
	if (!(n = get_int_len(dir_number) + 2)) goto error_out;  // +"/" & "\0"
	if (!(dirname = (char *)my_malloc(sizeof(char) * n))) goto error_out;
	snprintf(dirname, n, "%d", dir_number);
	if (!(dir_path = alloc_concat_path(path, dirname))) goto error3;

	if (mkdir(dir_path, 0777)) goto error2;
	return dir_path;
error1:
	LOG(ERROR, "path is NULL.");
	goto error_out;
error2:
	LOG(ERROR, "mkdir() failed. %s.", strerror(errno));
error3:
	free(dirname);
error_out:
	LOG_FUNC_FAIL;
	return NULL;
}

bool is_dir_writable(const char *path) {
	if (!path) return false;
	DIR *dir;
	if ((dir = opendir(path)))
		closedir(dir);
	else
		return false;
	return true;
}
