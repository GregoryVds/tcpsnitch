#define _GNU_SOURCE  // For program_invocation_name

#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <slog.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "config.h"
#include "lib.h"
#include "logger.h"
#include "string_helpers.h"
#include "tcp_spy.h"

char *log_path = NULL;
long tcp_info_bytes_ival = 0;
long tcp_info_time_ival = 0;

///////////////////////////////////////////////////////////////////////////////
/*
  ___ _   _ _____ _____ ____  _   _    _    _          _    ____ ___
 |_ _| \ | |_   _| ____|  _ \| \ | |  / \  | |        / \  |  _ \_ _|
  | ||  \| | | | |  _| | |_) |  \| | / _ \ | |       / _ \ | |_) | |
  | || |\  | | | | |___|  _ <| |\  |/ ___ \| |___   / ___ \|  __/| |
 |___|_| \_| |_| |_____|_| \_\_| \_/_/   \_\_____| /_/   \_\_|  |___|

*/
///////////////////////////////////////////////////////////////////////////////

static bool initialized = false;
static pthread_mutex_t init_mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;

///////////////////////////////////////////////////////////////////////////////

static long get_tcpinfo_ival(const char *env_var) {
        long val = get_env_as_long(env_var);
        if (val < 0) {
                LOG(ALWAYS, "Interval %s assumed to be 0.", env_var);
        } else
                LOG(ALWAYS, "Interval %s set to %lu.", env_var, val);
        return (val < 0) ? 0 : val;
}

static void get_tcpinfo_ivals(void) {
        tcp_info_bytes_ival = get_tcpinfo_ival(ENV_BYTES_IVAL);
        tcp_info_time_ival = get_tcpinfo_ival(ENV_MICROS_IVAL);
}

///////////////////////////////////////////////////////////////////////////////

static const char *get_netspy_path(void) {
        // Try to get ENV_PATH.
        DIR *dir;
        const char *path = getenv(ENV_PATH);
        if (path) {
                // If ENV_PATH is set, we verify than we can open it.
                // Otherwise we report an error.
                LOG(INFO, "Netspy path set with %s=%s.", ENV_PATH, path);
                if ((dir = opendir(path)))
                        closedir(dir);
                else
                        goto error2;
        } else {
                // If ENV_PATH is not set, we default to DEFAULT_PATH.
                // If we cannot open it, we try to create it.
                path = NETSPY_DEFAULT_PATH;
                LOG(WARN, "%s not set. Defaults to %s.", ENV_PATH, path);
                if ((dir = opendir(path)))
                        closedir(dir);       // Ok.
                else if (errno == ENOENT) {  // Does not exists.
                        LOG(INFO, "%s does not exists. Creating it.", path);
                        if (mkdir(path, 0777)) goto error1;
                } else
                        goto error2;
        }
        return path;
error2:
        LOG(ERROR, "opendir() failed on %s. %s.", path, strerror(errno));
        goto error_out;
error1:
        LOG(ERROR, "mkdir failed. %s.", strerror(errno));
error_out:
        LOG_FUNC_FAIL;
        return NULL;
}

///////////////////////////////////////////////////////////////////////////////

static void log_metadata(const char *netspy_path) {
        // TODO
        if (netspy_path == NULL) return;
}

///////////////////////////////////////////////////////////////////////////////

static char *create_logs_dir(const char *netspy_path) {
        char *base_path, *path;
        DIR *dir;
        if (!(base_path = alloc_base_dir_path(netspy_path))) goto error_out;

        // Find first directory available starting from base_path and by
        // concatenating increasing integers.
        int i = 0;
        if (!(path = alloc_append_int_to_path(base_path, i))) goto error1;
        while (true) {
                if ((dir = opendir(path))) {  // Already exists.
                        i++;
                        LOG(ALWAYS, "Cannot create %s (already exists).", path);
                        LOG(ALWAYS, "Appending next integer (%d).", i);
                        path = alloc_append_int_to_path(base_path, i);
                } else if (!dir && errno == ENOENT)
                        break;  // Free.
                else if (!dir)
                        goto error2;  // Failure for some other reason.
        }
        free(base_path);

        // Finally, create dir at path.
        if (mkdir(path, 0777)) goto error3;
        LOG(ALWAYS, "Logs directory created at %s.", path);
        return path;
error3:
        LOG(ALWAYS, "mkdir() failed for %s. %s.", path, strerror(errno));
        free(path);
        goto error_out;
error2:
        LOG(ALWAYS, "opendir() failed. %s.", strerror(errno));
        free(path);
error1:
        free(base_path);
error_out:
        LOG_FUNC_FAIL;
        return NULL;
}

///////////////////////////////////////////////////////////////////////////////

void netspy_free(void) {
        free(log_path);
        mutex_destroy(&init_mutex);
}

void netspy_reset(void) {
        log_path = NULL;
        tcp_info_time_ival = 0;
        tcp_info_time_ival = 0;
        initialized = false;
        mutex_init(&init_mutex);
}

static void cleanup(void) {
        LOG(INFO, "Performing library cleanup before end of process.");
        tcp_close_unclosed_connections();
        tcp_free();
        netspy_free();
}

///////////////////////////////////////////////////////////////////////////////
/*
  ____  _   _ ____  _     ___ ____      _    ____ ___
 |  _ \| | | | __ )| |   |_ _/ ___|    / \  |  _ \_ _|
 | |_) | | | |  _ \| |    | | |       / _ \ | |_) | |
 |  __/| |_| | |_) | |___ | | |___   / ___ \|  __/| |
 |_|    \___/|____/|_____|___\____| /_/   \_\_|  |___|

*/
///////////////////////////////////////////////////////////////////////////////

/*  This function is used to reset the library after a fork() call. If a fork()
 *  is not followed by exec(), the global variables are not reinitialized.
 *  This means that 2 processes with differents PID would use the same log_path,
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

void reset_netspy(void) {
        if (!initialized) return;  // Nothing to do.
        LOG(ALWAYS, "Netspy reset.");
        slog_init(NULL, NULL, 0, 0, 0);
        netspy_free();
        netspy_reset();
        tcp_free();
        tcp_reset();
}

void init_netspy(void) {
        mutex_lock(&init_mutex);
        if (initialized) goto exit;
        LOG(ALWAYS, "Initialization of Netspy library...");
        const char *netspy_path;
        char *log_file_path;

        atexit(cleanup);      // Register cleanup handler
        get_tcpinfo_ivals();  // Extract tcp_info intervals from ENV.

        if (!(netspy_path = get_netspy_path())) goto exit1; // Get netspy_path.
        log_metadata(netspy_path); // Log metadata about machine.

        // Configure logs
        if (!(log_path = create_logs_dir(netspy_path))) goto exit1;
        if (!(log_file_path = alloc_concat_path(log_path, get_app_name()))) {
                goto exit1;        
        } else {
                slog_init(log_file_path, "/etc/netspy_log.cfg", 1, 1, 1);
                free(log_file_path);
        }
        goto exit;
exit1:
        LOG(ERROR, "No logs to file.");
exit:
        initialized = true;
        mutex_unlock(&init_mutex);
        return;
}

