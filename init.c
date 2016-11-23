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

// Public data
char *log_path = NULL;  // Directory in Netspy path for this run of Netspy.
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

static char *log_file_path;
static bool initialized = false;
static pthread_mutex_t init_mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;

static const char *get_netspy_path(void) {
        // Check NETSPY path in ENV
        const char *path = getenv(ENV_PATH);
        if (path == NULL) {
                path = NETSPY_DEFAULT_PATH;
                LOG(INFO, "Netspy path not specified in %s. Defaults to %s.",
                    ENV_PATH, path);
                DIR *dir = opendir(path);
                if (dir) {
                        closedir(dir);
                } else if (errno == ENOENT) {  // Does not exists.
                        LOG(INFO, "%s does not exists. Creating it.", path);
                        if (mkdir(path, 0777) == -1) {
                                LOG(ERROR, "mkdir() failed. %s.",
                                    strerror(errno));
                                return NULL;
                        }
                } else {
                        LOG(ERROR, "opendir() failed on %s. %s", path,
                            strerror(errno));
                        return NULL;
                }

        } else {
                LOG(INFO, "Netspy path set with %s=%s.", ENV_PATH, path);
                // Make sure we can access it.
                DIR *dir = opendir(path);
                if (dir)  // Ok, we can access.
                        closedir(dir);
                else {
                        LOG(ERROR, "opendir() failed on %s. %s.", path,
                            strerror(errno));
                        return NULL;
                }
        }

        return path;
}

///////////////////////////////////////////////////////////////////////////////

static void log_metadata(const char *netspy_path) {
        // TODO
        if (netspy_path == NULL) return;
}

///////////////////////////////////////////////////////////////////////////////
/* For each Netspy run, we create a new log directory in the Netspy path. This
 * directory is named as follows: [APPLICATION]_[TIMESTAMP]_[X] where X is an
 * integer serving to differentiate names if the same application runs
 * multiple times in the same second. For instance: "curl_147819596_0".
 *
 * This function returns the base name, without the _[X] part.
 */

#define TIMESTAMP_WIDTH 10
static char *alloc_base_log_dir_name(void) {
        const char *app_name = get_app_name();
        int pid = getpid();
        int pid_len = get_int_len(pid);

        int app_name_length = strlen(app_name);
        int n =
            app_name_length + TIMESTAMP_WIDTH + pid_len + 3;  // APP_TIMESTAMP\0

        char *base_name = (char *)calloc(sizeof(char), n);
        if (base_name == NULL) {
                LOG(ERROR, "calloc() failed.");
                return NULL;
        }

        strncat(base_name, app_name, app_name_length);
        strncat(base_name, "_", 1);
        snprintf(base_name + strlen(base_name), TIMESTAMP_WIDTH + 1, "%lu",
                 get_time_sec());
        strncat(base_name, "_", 1);
        snprintf(base_name + strlen(base_name), pid_len + 1, "%d", pid);
        return base_name;
}

static char *alloc_base_log_dir_path(const char *netspy_path) {
        // Get base log dir name
        char *base_name = alloc_base_log_dir_name();
        if (base_name == NULL) {
                LOG(ERROR, "alloc_base_log_dir_name_str() failed.");
                return NULL;
        }

        // Get base log dir path
        char *base_path = alloc_concat_path(netspy_path, base_name);
        if (base_path == NULL) {
                LOG(ERROR, "alloc_concat_path() failed.");
                free(base_name);
                return NULL;
        }
        free(base_name);

        return base_path;
}

#define TIMESTAMP_WIDTH 10
static char *create_logs_dir(const char *netspy_path) {
        // Get base path
        char *base_path = alloc_base_log_dir_path(netspy_path);
        if (base_path == NULL) {
                LOG(ERROR, "alloc_base_log_dir_path() failed.");
                return NULL;
        }

        // Find first directory available starting from base_path and
        // concatenating increasing integers.
        int i = 0;
        char *actual_path = alloc_append_int_to_path(base_path, i);
        while (true) {
                DIR *dir = opendir(actual_path);
                if (dir == NULL && errno == ENOENT)
                        break;           // Free.
                else if (dir == NULL) {  // Failure for some other reason.
                        LOG(ERROR, "opendir() failed. %s.", strerror(errno));
                        return NULL;  // We abort.
                }

                // Dir exists, append next integer to path.
                i++;
                LOG(INFO,
                    "Cannot use directory %s since it already exists. Trying "
                    "by appending next integer (%d).",
                    actual_path, i);
                actual_path = alloc_append_int_to_path(base_path, i);
        }
        free(base_path);

        // Finally, create dir at actual_path.
        int ret = mkdir(actual_path, 0777);
        if (ret == -1) {
                LOG(ERROR, "mkdir() failed for %s. %s.", actual_path,
                    strerror(errno));
                return NULL;
        }

        return actual_path;
}

///////////////////////////////////////////////////////////////////////////////

/* Retrieve interval for tcpinfo (could be byte ou time interval).
 * If not set or in incorrect format, we assume 0 and thus no lower bound. */
static long get_tcpinfo_ival(const char *env_var) {
        long t = get_env_as_long(env_var);
        if (t == -1) LOG(WARN, "No interval set with %s.", env_var);
        if (t == -2) LOG(ERROR, "Invalid interval set with %s.", env_var);
        if (t == -3) LOG(ERROR, "Interval set with %s overflows.", env_var);
        // On error, we use a default value of 0.
        if (t < 0) {
                LOG(WARN,
                    "Interval %s assumed to be 0. No lower bound "
                    "set on tcp_info capture frequency.",
                    env_var);
        }
        return (t < 0) ? 0 : t;
}

static void get_tcpinfo_ivals(void) {
        tcp_info_bytes_ival = get_tcpinfo_ival(ENV_BYTES_IVAL);
        LOG(INFO, "tcp_info min bytes interval set to %lu.",
            tcp_info_bytes_ival);
        tcp_info_time_ival = get_tcpinfo_ival(ENV_MICROS_IVAL);
        LOG(INFO, "tcp_info min microseconds interval set to %lu.",
            tcp_info_time_ival);
}

///////////////////////////////////////////////////////////////////////////////

static void cleanup(void) {
        LOG(INFO, "Performing cleanup.");
        // TODO: mutex_destroy(&init_mutex);
        // TODO: THIS CRASHES =-> free(log_file_path);
        tcp_cleanup();
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
        slog_init(NULL, NULL, 0, 0, 0);
        LOG(INFO, "Netspy reset...");
        log_path = NULL;
        tcp_info_time_ival = 0;
        tcp_info_time_ival = 0;
        log_file_path = NULL;
        mutex_init(&init_mutex);
        initialized = false;
        tcp_reset();
}

void init_netspy(void) {
        // Acquire mutex
        if (!(lock(&init_mutex))) return;
        if (initialized) goto exit;

        // Start initialization
        LOG(INFO, "Initialization of Netspy library...");

        atexit(cleanup);      // Register cleanup handler
        get_tcpinfo_ivals();  // Extract tcp_info intervals from ENV.

        // Get directory where netpsy activity is logged.
        const char *netspy_path = get_netspy_path();
        if (netspy_path == NULL) {
                LOG(ERROR, "get_nestpy_path() failed. No logs to file.");
                initialized = true;
                goto exit;
        }

        // Log machine metadatas. This should only be done ONCE for a given
        // machine across multiple netspy runs.
        log_metadata(netspy_path);

        // Create log directory for this run.
        log_path = create_logs_dir(netspy_path);
        if (log_path == NULL) {
                LOG(INFO, "create_logs_dir() failed. Won't log to file.");
                initialized = true;
                goto exit;
        } else {
                LOG(INFO, "Logs directory created at %s.", log_path);
        }

        // Configure log library.
        log_file_path = alloc_concat_path(log_path, get_app_name());
        if (log_file_path == NULL) {
                LOG(ERROR,
                    "alloc_concat_path() failed. Logging library cannot log"
                    " to file.");
        } else {
                slog_init(log_file_path, "/etc/netspy_log.cfg", 1, 1, 1);
        }

        initialized = true;
        goto exit;
exit:
        // Release mutex
        unlock(&init_mutex);
        return;
}

///////////////////////////////////////////////////////////////////////////////
