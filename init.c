#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef __ANDROID__
#include <android/log.h>
#include <sys/system_properties.h>
#endif
#include "constants.h"
#include "lib.h"
#include "logger.h"
#include "sock_events.h"
#include "string_builders.h"

long conf_opt_b;
long conf_opt_c;
char *conf_opt_d;
long conf_opt_f;
long conf_opt_l;
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

/* This function creates the directory where the traces of the current process
 * will be placed. We start from [base_path], which is the number of the process
 * and try to find the first directory available by concatenating increasing
 * integers. */
static char *create_logs_dir_at_path(const char *path) {
        char *app_name, *base_path, *full_path;
        int i = 0;
        DIR *dir;
        if (!(app_name = alloc_app_name())) goto error_out;
        if (!(base_path = alloc_concat_path(path, app_name))) goto error1;
        free(app_name);
        full_path = alloc_append_int_to_path(base_path, i);

        while (true) {
                if ((dir = opendir(full_path))) {  // Already exists.
                        free(full_path);
                        i++;
                        full_path = alloc_append_int_to_path(base_path, i);
                } else if (!dir && errno == ENOENT)
                        break;  // Free.
                else if (!dir)
                        goto error2;  // Failure for some other reason.
        }

        free(base_path);
        // Finally, create dir at full_path.
        if (mkdir(full_path, 0777)) goto error3;
        return full_path;
error3:
        LOG(ERROR, "mkdir() failed for %s. %s.", path, strerror(errno));
        free(full_path);
        goto error_out;
error2:
        LOG(ERROR, "opendir() failed. %s.", strerror(errno));
        free(full_path);
        free(base_path);
        goto error_out;
error1:
        free(app_name);
error_out:
        LOG_FUNC_ERROR;
        return NULL;
}

static void tcpsnitch_free(void) {
        free(conf_opt_d);
        free(logs_dir_path);
#ifndef __ANDROID__
        if (_stdout) fclose(_stdout);
        if (_stderr) fclose(_stderr);
#endif
        // We don't check for errors on this one. This is called after fork()
        // will logically fail if the mutex was locked at the time of forking.
        pthread_mutex_destroy(&init_mutex);
}

#ifndef __ANDROID__
static void open_std_streams(void) {
        /* We need a way to unweave the main process and tcpsnitch standard
         * streams. To this purpose, we create 2 additionnal fds (3 & 4) with
         * bash redirections that this lib use as standard streams. */
        _stdout = my_fdopen(STDOUT_FD, "w");
        _stderr = my_fdopen(STDERR_FD, "w");
}
#endif

static void get_options(void) {
        conf_opt_b = get_long_opt_or_defaultval(OPT_B, 4096);
#ifdef __ANDROID__
        conf_opt_d = alloc_android_opt_d();
#else
        conf_opt_c = get_long_opt_or_defaultval(OPT_C, 0);
        conf_opt_d = alloc_str_opt(OPT_D);
#endif
        conf_opt_f = get_long_opt_or_defaultval(OPT_F, WARN);
        conf_opt_l = get_long_opt_or_defaultval(OPT_L, WARN);
        conf_opt_t = get_long_opt_or_defaultval(OPT_T, 1000);
        conf_opt_u = get_long_opt_or_defaultval(OPT_U, 0);
        conf_opt_v = get_long_opt_or_defaultval(OPT_V, 0);
}

static void log_options(void) {
        LOG(INFO, "Option b: %lu.", conf_opt_b);
#ifndef __ANDROID__
        LOG(INFO, "Option c: %lu.", conf_opt_c);
#endif
        LOG(INFO, "Option d: %s", conf_opt_d);
        LOG(INFO, "Option f: %lu.", conf_opt_f);
        LOG(INFO, "Option l: %lu.", conf_opt_l);
        LOG(INFO, "Option t: %lu.", conf_opt_t);
        LOG(INFO, "Option u: %lu.", conf_opt_u);
        LOG(INFO, "Option v: %lu.", conf_opt_v);
}

static void init_logs(void) {
        char *log_file_path;
        if (!(log_file_path = alloc_concat_path(logs_dir_path, "logs.txt")))
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
        my_pthread_create(&thread, NULL, json_dumper_thread, NULL);
}

/* Public functions */

/*  This function is used to reset the library after a fork() call. If a fork()
 *  is not followed by exec(), the global variables are not reinitialized.
 *  However, we would like to distinguish the traces by process. */

void reset_tcpsnitch(void) {
        if (!initialized) return;  // Nothing to do.
        tcpsnitch_free();
        logger_init(NULL, WARN, WARN);
        initialized = false;
        mutex_init(&init_mutex);
        sock_ev_reset();
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
