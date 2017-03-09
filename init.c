#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef __ANDROID__
#include <sys/system_properties.h>
#include <android/log.h>
#endif
#include "constants.h"
#include "lib.h"
#include "logger.h"
#include "string_builders.h"
#include "sock_events.h"

long conf_opt_b;
long conf_opt_c;
char *conf_opt_d;
long conf_opt_f;
char *conf_opt_i;
long conf_opt_l;
long conf_opt_p;
long conf_opt_u;
long conf_opt_t;
long conf_opt_v;

char *logs_dir_path;

#ifndef __ANDROID__
FILE *_stdout;
FILE *_stderr;
#endif

static bool initialized = false;

#ifdef __ANDROID__
static pthread_mutex_t init_mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER;
#else
static pthread_mutex_t init_mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;
#endif

/* Private functions */

// Find first directory available starting from [base_path] by concatenating
// increasing integers.
static char *create_logs_dir_at_path(const char *path) {
        char *dirname, *base_path, *full_path;
        int i = 0;
        DIR *dir;
        if (!(dirname = alloc_dirname_str())) goto error_out;
        if (!(base_path = alloc_concat_path(path, dirname))) goto error1;
        if (!(full_path = alloc_append_int_to_path(base_path, i))) goto error2;

        while (true) {
                if ((dir = opendir(full_path))) {  // Already exists.
                        free(full_path);
                        i++;
                        full_path = alloc_append_int_to_path(base_path, i);
               } else if (!dir && errno == ENOENT)
                        break;  // Free.
                else if (!dir)
                        goto error3;  // Failure for some other reason.
        }

        // Finally, create dir at full_path.
        if (mkdir(full_path, 0777)) goto error4;

        free(dirname);
        free(base_path);
        return full_path;
error4:
        LOG(ERROR, "mkdir() failed for %s. %s.", path, strerror(errno));
        free(full_path);
        goto error_out;
error3:
        LOG(ERROR, "opendir() failed. %s.", strerror(errno));
        free(full_path);
error2:
        free(base_path);
error1:
        free(dirname);
error_out:
        LOG_FUNC_ERROR;
        return NULL;
}

static void tcpsnitch_free(void) {
        free(conf_opt_d);
        free(logs_dir_path);
        // We don't check for errors on this one. This is called
        // after fork() and will logically failed if the mutex
        // was lock at the time of forking. This is normal.
        pthread_mutex_destroy(&init_mutex);
}

#ifndef __ANDROID__
static void open_std_streams(void) {
        /* We need a way to unweave the main process and tcpsnitch standard
         * streams. To this purpose, we create 2 additionnal fd (3 & 4) with
         * some bash redirections (3>&1 4>&2 1>/dev/null 2>&). As a consequence,
         * tcpsnitch stderr/stdout do not have the regular 1 & 2 fd, but are
         * 3 and 4 instead. */
        if (!(_stdout = fdopen(STDOUT_FD, "w"))) goto error1;
        if (!(_stderr = fdopen(STDERR_FD, "w"))) goto error2;
        return;
error2:
        LOG(ERROR, "fdopen() failed. No buffered I/O for stdout.");
        goto error_out;
error1:
        LOG(ERROR, "fdopen() failed. No buffered I/O for stdout.");
error_out:
        LOG_FUNC_ERROR;
}
#endif

static void get_options(void) {
        conf_opt_b = get_long_opt_or_defaultval(OPT_B, 4096);
        conf_opt_c = get_long_opt_or_defaultval(OPT_C, 0);
#ifdef __ANDROID__
        conf_opt_d = alloc_android_opt_d();
#else
        conf_opt_d = alloc_str_opt(OPT_D);
#endif
        conf_opt_f = get_long_opt_or_defaultval(OPT_F, WARN);
#ifdef __ANDROID__
        conf_opt_i = NULL;
#else
        conf_opt_i = get_str_env(OPT_I);
#endif
        conf_opt_l = get_long_opt_or_defaultval(OPT_L, WARN);
        conf_opt_p = get_long_opt_or_defaultval(OPT_P, 0);
        conf_opt_u = get_long_opt_or_defaultval(OPT_U, 0);
        conf_opt_t = get_long_opt_or_defaultval(OPT_T, 1000);
        conf_opt_v = get_long_opt_or_defaultval(OPT_V, 0);
}

static void log_options(void) {
        LOG(INFO, "Option b: %lu.", conf_opt_b);
        LOG(INFO, "Option c: %lu.", conf_opt_c);
        LOG(INFO, "Option d: %s", conf_opt_d);
        LOG(INFO, "Option f: %lu.", conf_opt_f);
        LOG(INFO, "Option i: %s.", conf_opt_i);
        LOG(INFO, "Option l: %lu.", conf_opt_l);
        LOG(INFO, "Option p: %lu.", conf_opt_p);
        LOG(INFO, "Option u: %lu.", conf_opt_u);
        LOG(INFO, "Option t: %lu.", conf_opt_t);
        LOG(INFO, "Option v: %lu.", conf_opt_v);
}

static void init_logs(void) {
        char *log_file_path;
        if (!(log_file_path = alloc_concat_path(logs_dir_path, MAIN_LOG_FILE)))
                goto error;
        logger_init(log_file_path, conf_opt_l, conf_opt_f);
        free(log_file_path);
        return;
error:
        LOG_FUNC_ERROR;
        LOG(ERROR, "No logs to file.");
}

static void *json_dumper_thread(void *arg) {
        UNUSED(arg);
        LOG_FUNC_INFO;

        struct timespec time;
        time.tv_sec = conf_opt_t / 1000;
        time.tv_nsec = (conf_opt_t % 1000) * 1000 * 1000;  // opt_t is in ms

        while (true) {
                dump_all_sock_events();
                nanosleep(&time, NULL);
        }
        // Unreachable
        return NULL;
}

void start_json_dumper_thread(void) {
        pthread_t thread;
        int rc = pthread_create(&thread, NULL, json_dumper_thread, NULL);
        if (rc) goto error;
        return;
error:
        LOG(ERROR, "pthread_create_failed(). %s.", strerror(rc));
        LOG_FUNC_ERROR;
}

/* Public functions */

/*  This function is used to reset the library after a fork() call. If a fork()
 *  is not followed by exec(), the global variables are not reinitialized.
 *  This means that 2 processes with differents PID would use the same
 * conf_opt_d,
 *  but more importantly, the child would inherit all the states from the
 *  fd_con_map of its parents. This leads to many issues:
 *     - The 2 processes will mix their logs in the same file.
 *     - If both the parent/child open a connection on the same FD, the last
 *     one the close it will overwrite the logs of the first to close.
 *     - ...
 *
 *  Our solution is to always reset the state of the library on fork(). One
 *  known issue of this solution is when both the child and the parent
 *  write/read on the SAME TCP connection opened by the parent. In that case,
 *  we will not have a complete view of the connection. Each process will have
 *  its own partial view. This is a known limitation.
 *
 *  Normally this function is called directly after fork() in the child process
 *  before it returns. There are normally no reasons to lock the mutex since at
 *  that moment, there should be a single thread of execution in the new child
 *  process. It thus better to still reset the library if we fail to acquire the
 *  mutex. Not resetting could have much more drastic consequences such as those
 *  explained above. */

void reset_tcpsnitch(void) {
        if (!initialized) return;  // Nothing to do.
        tcpsnitch_free();
        logger_init(NULL, WARN, WARN);
        initialized = false;
        mutex_init(&init_mutex);
        tcp_free();
        tcp_reset();
}

void init_tcpsnitch(void) {
        mutex_lock(&init_mutex);
        if (initialized) goto exit;

#ifndef __ANDROID__
        open_std_streams();
#endif
        get_options();
        if (!conf_opt_d) goto exit1;
        if (!(logs_dir_path = create_logs_dir_at_path(conf_opt_d))) goto exit1;
        init_logs();
        log_options();
        if (conf_opt_t) start_json_dumper_thread();
        goto exit;
exit1:
        LOG(ERROR, "Nothing will be written to file (log, pcap, json).");
exit:
        initialized = true;
        mutex_unlock(&init_mutex);
        return;
}

__attribute__((destructor)) static void cleanup(void) {
        LOG(INFO, "Performing library cleanup before end of process.");
        dump_all_sock_events();
        // tcp_free();
        // tcpsnitch_free();
}

