#include "packet_sniffer.h"
#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "config.h"
#include "lib.h"
#include "logger.h"
#include "string_helpers.h"

///////////////////////////////////////////////////////////////////////////////
/*
  ___ _   _ _____ _____ ____  _   _    _    _          _    ____ ___
 |_ _| \ | |_   _| ____|  _ \| \ | |  / \  | |        / \  |  _ \_ _|
  | ||  \| | | | |  _| | |_) |  \| | / _ \ | |       / _ \ | |_) | |
  | || |\  | | | | |___|  _ <| |\  |/ ___ \| |___   / ___ \|  __/| |
 |___|_| \_| |_| |_____|_| \_\_| \_/_/   \_\_____| /_/   \_\_|  |___|

*/
///////////////////////////////////////////////////////////////////////////////

static pcap_t *get_capture_handle(void);
static void *capture_thread(void *params);
static void *delayed_stop_thread(void *params);

/* Return handle to capture handle. If env var NETSPY_DEV is not specified,
 * then return the default device obtained with pcap_lookupdev().
 *
 * Returns a pcap_t * on success, or NULL in case of error. */

static pcap_t *get_capture_handle(void) {
	char *dev = getenv(ENV_DEV);
	char err_buf[PCAP_ERRBUF_SIZE];

	if (dev == NULL) {
		LOG(WARN,
		    "Env variable %s was not set. Capture on all interfaces.",
		    ENV_DEV);
	}
        
	// Set err_buf to empty string to get warnings.
	err_buf[0] = 0;
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 0, 0, err_buf);

	if (err_buf[0] != 0)
		LOG(WARN, "pcap_open_live() warning. %s.", err_buf);
	if (handle == NULL) LOG(ERROR, "pcap_open_live() failed. %s.", err_buf);

	return handle;
}

///////////////////////////////////////////////////////////////////////////////

typedef struct {
	pcap_t *handle;
	pcap_dumper_t *dump;
	bool *switch_flag;
} CaptureThreadArgs;

static void *capture_thread(void *params) {
	LOG(INFO, "Capture thread started.");
	CaptureThreadArgs *args = (CaptureThreadArgs *)params;

	bool *should_capture = args->switch_flag;
	while (*should_capture) {
		if (pcap_dispatch(args->handle, -1, &pcap_dump,
				  (u_char *)args->dump) == -1) {
			LOG(ERROR, "pcap_dispatch() failed. %s.",
			    pcap_geterr(args->handle));
		}
	}

	LOG(INFO, "Capture ended.");
	pcap_close(args->handle);
	pcap_dump_close(args->dump);
	free(should_capture);
	free(args);
	return NULL;
}

///////////////////////////////////////////////////////////////////////////////

typedef struct {
	bool *switch_flag;
	int delay_ms;
} DelayStopThreadArgs;

static void *delayed_stop_thread(void *params) {
	LOG(INFO, "Delayed stop thread started.");
	DelayStopThreadArgs *args = (DelayStopThreadArgs *)params;
	struct timespec ns = {0, args->delay_ms*1000000};
	nanosleep(&ns, NULL);
	*(args->switch_flag) = false;
	LOG(INFO, "Turned off capture switch.");
	return NULL;
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


char *build_capture_filter(const struct sockaddr_storage *bound_addr,
			   const struct sockaddr_storage *connect_addr) {
	char *bound_port = NULL, *connect_port = NULL, *connect_host = NULL,
	     *filter = NULL;

	if (bound_addr)
		if (!(bound_port = alloc_port_str(bound_addr))) return NULL;

	if (!(connect_host = alloc_host_str(connect_addr))) goto error1;
	if (!(connect_port = alloc_port_str(connect_addr))) goto error2;

	if (!(filter = (char *)malloc(sizeof(char) * FILTER_SIZE)))
		goto error3;

	snprintf(filter, FILTER_SIZE, "host %s and port %s", connect_host,
		 connect_port);

	// If bound_addr, then we apport additionnal filter on source port.
	if (bound_addr) {
		int n = strlen(filter);
		snprintf(filter + n, FILTER_SIZE - n, " and port %s",
			 bound_port);
	}

	LOG(INFO, "Starting capture with filter: '%s'", filter);
	free(bound_port);
	free(connect_host);
	free(connect_port);

	return filter;
error3:
	free(connect_port);
	goto error2;
error2:
	free(connect_host);
	goto error1;
error1:
	free(bound_port);
	return NULL;
}

/* Start a capture with the given filters & save raw data to file at path.
 *
 * Return a pcap_t * on success, on NULL on error. */

bool *start_capture(char *filter_str, char *path) {
	// Get handle
	pcap_t *handle = get_capture_handle();
	if (handle == NULL) {
		LOG(ERROR, "No capture. Could not get capture handle.");
		return NULL;
	}

	// Compile filter
	struct bpf_program comp_filter;
	if (pcap_compile(handle, &comp_filter, filter_str, 1,
			 PCAP_NETMASK_UNKNOWN) < 0) {
		LOG(ERROR, "pcap_compile() failed. %s.", pcap_geterr(handle));
		goto error1;
	}

	// Apply filter
	if (pcap_setfilter(handle, &comp_filter) < 0) {
		LOG(ERROR, "pcap_setfilter() failed. %s.", pcap_geterr(handle));
		goto error1;
	}

	// Set capture handle into 'non-blocking' mode
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_setnonblock(handle, 1, errbuf) == -1) {
		LOG(ERROR, "pcap_setnonblock() failed. %s.", errbuf);
		goto error1;
	}

	// Open a file to which to write packets.
	// The pcap_dumper_t * can be passed to pcap_dump.
	pcap_dumper_t *dump = pcap_dump_open(handle, path);
	if (dump == NULL) {
		LOG(ERROR, "pcap_dump_open() failed. %s.", pcap_geterr(handle));
		goto error1;
	}

	// Alloc flag for controlling capture end. This flag can be turned off
	// at any time by called thread to end the capture.
	bool *switch_flag = malloc(sizeof(bool));
	if (switch_flag == NULL) {
		LOG(ERROR, "malloc() failed");
		goto error2;
	}
	(*switch_flag) = true;

	// Start capture in another thread.
	CaptureThreadArgs *args =
	    (CaptureThreadArgs *)malloc(sizeof(CaptureThreadArgs));
	if (args == NULL) {
		LOG(ERROR, "malloc() failed.");
		goto error3;
	}

	args->handle = handle;
	args->dump = dump;
	args->switch_flag = switch_flag;

	pthread_t thread;
	int rc = pthread_create(&thread, NULL, capture_thread, args);
	if (rc) {
		LOG(ERROR, "pthread_create_failed(). %s.", strerror(rc));
		goto error2;
	}

	return switch_flag;
error3:
	free(switch_flag);
	goto error2;
error2:
	pcap_dump_close(dump);
	goto error1;
error1:
	pcap_close(handle);
	LOG(ERROR, "No capture.");
	return NULL;
}

int stop_capture(bool *switch_flag, int delay_ms) {
	DelayStopThreadArgs *args =
	    (DelayStopThreadArgs *)malloc(sizeof(DelayStopThreadArgs));
	if (args == NULL) {
		LOG(ERROR, "malloc failed.");
		goto error;
	}

	args->switch_flag = switch_flag;
	args->delay_ms = delay_ms;

	pthread_t delay_thread;
	int rc = pthread_create(&delay_thread, NULL, delayed_stop_thread, args);
	if (rc != 0) {
		LOG(ERROR, "pthread_create_failed(). %s.", strerror(rc));
		goto error;
	}

	return 0;
error:
	LOG(ERROR,
	    "Failed to create thread to delay packet capture end. "
	    "Ending packet capture immediately.");
	*(switch_flag) = false;
	return -1;
}


