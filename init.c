#define _GNU_SOURCE  // For program_invocation_name

#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "config.h"
#include "lib.h"
#include "logger.h"
#include "string_helpers.h"
#include "tcp_spy.h"

const char *netspy_path = NULL;  // Directory where Netspy runs are recorded.
char *log_path = NULL;     // Directory in Netspy path for this run of Netspy.

long tcp_info_bytes_ival = 0;
long tcp_info_time_ival = 0;

static bool initialized = false;

///////////////////////////////////////////////////////////////////////////////

const char *get_netspy_path(void) {
	// Check NETSPY path in ENV
	const char *path = getenv(ENV_NETSPY_PATH);
	if (path == NULL) {
		path = NETSPY_DEFAULT_PATH;
		LOG(INFO, "Netspy path not specified in %s. Defaults to %s.",
		    ENV_NETSPY_PATH, path);
	} else {
		LOG(INFO, "Netspy path set with %s=%s.", ENV_NETSPY_PATH, path);
	}

	// Make sure we can access it.
	DIR *dir = opendir(path);
	if (dir)  // Ok, we can access.
		closedir(dir);
	else {
		LOG(ERROR, "Cannot access Netspy path. %s.", strerror(errno));
		LOG(ERROR, "Netspy is unable to log data.");
		return NULL;
	}

	return path;
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
char *alloc_base_log_dir_name(void) {
	char *app_name = program_invocation_name;  // Not portable?
	int app_name_length = strlen(app_name);
	int n = app_name_length + TIMESTAMP_WIDTH + 2;  // APP_TIMESTAMP\0

	char *base_name = (char *)calloc(sizeof(char), n);
	if (base_name == NULL) {
		LOG(ERROR, "calloc() failed.");
		return NULL;
	}

	strncat(base_name, app_name, app_name_length);
	strncat(base_name, "_", 1);
	snprintf(base_name + strlen(base_name), TIMESTAMP_WIDTH, "%lu",
		 get_time_sec());

	return base_name;
}

char *alloc_base_log_dir_path(void) {
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
static char *create_logs_dir(void) {
	// Get base path
	char *base_path = alloc_base_log_dir_path();
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
			break;		 // Free.
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
	int ret = mkdir(actual_path, 0700);
	if (ret == -1) {
		LOG(ERROR, "mkdir() failed. %s.", strerror(errno));
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
	tcp_info_bytes_ival = get_tcpinfo_ival(ENV_NETSPY_TCPINFO_BYTES_IVAL);
	LOG(WARN, "tcp_info min bytes interval set to %lu.",
	    tcp_info_bytes_ival);
	tcp_info_time_ival = get_tcpinfo_ival(ENV_NETSPY_TCPINFO_MICROS_IVAL);
	LOG(WARN, "tcp_info min microseconds interval set to %lu.",
	    tcp_info_time_ival);
}

///////////////////////////////////////////////////////////////////////////////

void init_netspy(void) {
	if (initialized) return;

	LOG(INFO, "Initialization of Netspy library...");
	initialized = true;
	get_tcpinfo_ivals();

	netspy_path = get_netspy_path();
	if (netspy_path == NULL) {
		LOG(ERROR, "get_nestpy_path() failed. Won't log to file.");
		return;
	}

	log_path = create_logs_dir();
	if (log_path == NULL) {
		LOG(INFO, "create_logs_dir() failed. Won't log to file.");
	} else {
		LOG(INFO, "Logs directory created at %s.", log_path);
	}

	// Configure log library.
	char *log_file_path = alloc_concat_path(log_path, NETSPY_LOG_FILE); 
	set_log_path(log_file_path);
	free(log_file_path);
}

///////////////////////////////////////////////////////////////////////////////
