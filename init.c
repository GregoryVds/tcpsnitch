#define _GNU_SOURCE  // For program_invocation_name

#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "config.h"
#include "logger.h"
#include "tcp_spy.h"
#include "lib.h"
#include "string_helpers.h"

char *netspy_path = NULL;
char *log_path = NULL;
long tcp_info_bytes_ival = 0;
long tcp_info_time_ival = 0;

static bool initialized = false;

///////////////////////////////////////////////////////////////////////////////

char *get_netspy_path() {
	LOG(INFO, "Getting Netspy path...");

	// Check NETSPY path in ENV
	char *path = getenv(ENV_NETSPY_PATH);
	if (path == NULL) {
		path = NETSPY_DEFAULT_PATH;
		LOG(INFO, "Netspy path not specified in %s. Defaults to %s.",
		    ENV_NETSPY_PATH, path);
	} else {
		LOG(INFO, "Netspy path set with %s=%s.", ENV_NETSPY_PATH, path);
	}

	// Make sure we can access it.
	DIR *dir = opendir(path);
	if (dir) {
		closedir(dir);  // Dir exists. OK.
		LOG(INFO, "Can open Netspy path.");
	} else {
		LOG(ERROR, "Cannot access Netspy path. %s.", strerror(errno));
		LOG(ERROR, "Unable to log data.");
		return NULL;
	}

	return path;
}

///////////////////////////////////////////////////////////////////////////////

#define TIMESTAMP_WIDTH 10
char *alloc_base_log_dir_name_str() {
	char *app_name = program_invocation_name;
	int app_name_length = strlen(app_name);
	int n = app_name_length + TIMESTAMP_WIDTH + 2;  // APP_TIMESTAMP\0
	char *dirname = (char *)calloc(sizeof(char), n);
	if (dirname == NULL) {
		LOG(ERROR, "calloc() failed.");
		return NULL;
	}

	strncat(dirname, app_name, app_name_length);
	strncat(dirname, "_", 1);
	snprintf(dirname + strlen(dirname), TIMESTAMP_WIDTH, "%lu",
		 get_time_sec());

	return dirname;
}

#define TIMESTAMP_WIDTH 10
static char *create_logs_dir() {
	LOG(INFO, "Computing log path...");
	
	// Get base log dir name
	char *base_name = alloc_base_log_dir_name_str();
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

	// Find find first directory available starting from base_path and 
	// concatening increasing integers.
	int i = 0;
	char *actual_path = alloc_append_int_to_path(base_path, i);

	bool is_free = false;
	char *tmp;
	while (is_free == false) {
		DIR *dir = opendir(actual_path);
		if (dir == NULL) {
			if (errno == ENOENT)  // Does not exists.
				is_free = true;
			else {  // Failure for some other reason.
				LOG(ERROR, "opendir() failed. %s.",
				    strerror(errno));
				return NULL;
			}
		} else {  // Dir exists, append next integer to path.
			i++;
			LOG(INFO,
			    "Cannot use directory %s since it already "
			    "exists. Trying by appending next integer (%d).",
			    actual_path, i);
			tmp = actual_path;
			actual_path = alloc_append_int_to_path(base_path, i);
			free(tmp);
		}
	}

	// At this point, actual_path is a directory that does not exists so
	// we can create it.
	int ret = mkdir(actual_path, 0700);
	if (ret == -1) {
		LOG(ERROR, "mkdir() failed. %s.", strerror(errno));
		return NULL;
	}

	free(base_path);
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

static void get_tcpinfo_ivals() {
	tcp_info_bytes_ival = get_tcpinfo_ival(ENV_NETSPY_TCPINFO_BYTES_IVAL);
	LOG(WARN, "tcp_info min bytes interval set to %lu.",
	    tcp_info_bytes_ival);
	tcp_info_time_ival = get_tcpinfo_ival(ENV_NETSPY_TCPINFO_MICROS_IVAL);
	LOG(WARN, "tcp_info min microseconds interval set to %lu.",
	    tcp_info_time_ival);
}

///////////////////////////////////////////////////////////////////////////////

void init_netspy() {
	if (initialized) return;

	LOG(INFO, "Initialization of Netspy library...");
 	netspy_path = get_netspy_path();
	if (netspy_path == NULL) {
		LOG(ERROR, "No valid Netspy path. Won't log.");
	} else {
		log_path = create_logs_dir();
		if (log_path == NULL) {
			LOG(INFO, "Could not create logs directory. Won't log.");
		} else {
			LOG(INFO, "Logs directory created at %s.", log_path);
		}
		set_log_path(log_path);
	}

	get_tcpinfo_ivals();
	initialized = true;
}

///////////////////////////////////////////////////////////////////////////////
