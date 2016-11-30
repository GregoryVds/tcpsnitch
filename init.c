#define _GNU_SOURCE  // For program_invocation_name

#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "config.h"
#include "lib.h"
#include "logger.h"
#include "string_helpers.h"
#include "tcp_spy.h"

char *tcpspy_dir = NULL;
long tcp_info_bytes_ival = 0;
long tcp_info_micros_ival = 0;

static bool initialized = false;
static pthread_mutex_t init_mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;

static const char *get_tcpspy_dir(void);
static char *create_logs_dir(const char *netspy_path);
static void netspy_free(void);
static void cleanup(void);
 
/* Private functions */

static const char *get_tcpspy_dir(void) {
        DIR *dir;
        const char *path = getenv(ENV_DIR);
        if (path) {
                if ((dir = opendir(path)))
                        closedir(dir);
                else
                        goto error1;
        } else
                goto error2;
        return path;
error1:
        LOG(ERROR, "opendir() failed on %s. %s.", path, strerror(errno));
        goto error_out;
error2:
        LOG(ERROR, "%s not set.", ENV_DIR);
error_out:
        LOG_FUNC_FAIL;
        return NULL;
}

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
                        path = alloc_append_int_to_path(base_path, i);
                } else if (!dir && errno == ENOENT)
                        break;  // Free.
                else if (!dir)
                        goto error2;  // Failure for some other reason.
        }
        free(base_path);

        // Finally, create dir at path.
        if (mkdir(path, 0777)) goto error3;
        return path;
error3:
        LOG(ERROR, "mkdir() failed for %s. %s.", path, strerror(errno));
        free(path);
        goto error_out;
error2:
        LOG(ERROR, "opendir() failed. %s.", strerror(errno));
        free(path);
error1:
        free(base_path);
error_out:
        LOG_FUNC_FAIL;
        return NULL;
}

static void netspy_free(void) {
        free(tcpspy_dir);
        mutex_destroy(&init_mutex);
}

static void cleanup(void) {
        LOG(INFO, "Performing library cleanup before end of process.");
        tcp_close_unclosed_connections();
        // tcp_free();
        // netspy_free();
}

/* Public functions */

/*  This function is used to reset the library after a fork() call. If a fork()
 *  is not followed by exec(), the global variables are not reinitialized.
 *  This means that 2 processes with differents PID would use the same tcpspy_dir,
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

        netspy_free();
        logger_init(NULL, 0, 0);
        tcpspy_dir = NULL;
        tcp_info_bytes_ival = 0;
        tcp_info_micros_ival = 0;
        initialized = false;
        mutex_init(&init_mutex);

        tcp_free();
        tcp_reset();
}

static bool config_init_logger(const char *netspy_path) {
        const char *init_logs_path =
            alloc_concat_path(netspy_path, TCPSPY_INIT_LOGS_FILE);
        if (init_logs_path)
                logger_init(init_logs_path, DEBUG, DEBUG);
        else
                goto error;
        return true;
error:
        LOG_FUNC_FAIL;
        return false;
}

void init_netspy(void) {
        mutex_lock(&init_mutex);
        if (initialized) goto exit;

        const char *netspy_path = get_tcpspy_dir();
        if (!netspy_path) goto exit1;
        
        config_init_logger(netspy_path);
        /* At this point we have initialization logs to file */

        atexit(cleanup);

        /* Fetch other ENV variables */
        static long file_log_lvl, stderr_log_lvl;
        tcp_info_bytes_ival = get_long_env_or_defaultval(ENV_BYTES_IVAL, 4096);
        tcp_info_micros_ival = get_long_env_or_defaultval(ENV_MICROS_IVAL, 0);
        file_log_lvl = get_long_env_or_defaultval(ENV_FILE_LOG_LVL, WARN);
        stderr_log_lvl = get_long_env_or_defaultval(ENV_STDERR_LOG_LVL, WARN);

        /* Create dir containing log, pcap and json files for this process */
        if (!(tcpspy_dir = create_logs_dir(netspy_path))) goto exit1;

        const char *log_file_path;
        if (!(log_file_path = alloc_concat_path(tcpspy_dir, "tcpsnitch.log")))
                goto exit2;
        else
                logger_init(log_file_path, stderr_log_lvl, file_log_lvl);

        goto exit;
exit1:
        LOG(ERROR, "Nothing will be written to file (log, pcap, json).");
        goto exit;
exit2:
        LOG(ERROR, "No logs to file.");
exit:
        initialized = true;
        mutex_unlock(&init_mutex);
        return;
}
