#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <pcap.h>
#include "packet_sniffer.h"
#include "lib.h"
#include "config.h"

void *capture_thread(void *params);

/* Return handle to capture handle. If env var NETSPY_DEV is not specified, 
 * then return the default device obtained with pcap_lookupdev().
 *
 * Returns a pcap_t * on success, or NULL in case of error. */

pcap_t *get_capture_handle()
{
	char *dev = getenv(ENV_NETSPY_DEV);
	char err_buf[PCAP_ERRBUF_SIZE];

	if (dev==NULL) {
		// NETSPAY_DEV was not set, get default device.
		DEBUG(WARN, "Env variable %s was not set for capture. Use "
				"default device instead.", ENV_NETSPY_DEV);
		dev = pcap_lookupdev(err_buf);
		if (dev==NULL) {
			DEBUG(ERROR, "pcap_lookupdev() failed. %s", err_buf);
			DEBUG(WARN, "Capture on all interfaces.");
		}
	}

	// Set err_buf to empty string to get warnings.
	err_buf[0] = 0;
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 0, 0, err_buf);
	if (err_buf[0] != 0) {
		DEBUG(WARN, "pcap_open_live() warning. %s", err_buf);
	}
	
	if (handle==NULL) {
		DEBUG(ERROR, "pcap_open_live() failed. %s", err_buf);
	}

	return handle;
}

/* Start a capture with the given filters & save raw data to file at path. 
 *
 * Return a pcap_t * on success, on NULL on error. */

typedef struct {
	pcap_t *handle;
	pcap_dumper_t *dump;
} CaptureThreadArgs;

pcap_t *start_capture(char *filter_str, char *path, pthread_t *thread) 
{
	// Get handle
	pcap_t *handle = get_capture_handle();
	if (handle==NULL) {
		DEBUG(ERROR, "No capture. Could not get capture handle.");
		return NULL;
	}

	// Compile filter
	struct bpf_program comp_filter;
	if (pcap_compile(handle, &comp_filter, filter_str, 1, 
				PCAP_NETMASK_UNKNOWN) < 0) {
		DEBUG(ERROR, "No capture. pcap_compile() failed. %s", 
				pcap_geterr(handle));
		pcap_close(handle);
		return NULL;
	}

	// Apply filter
	if (pcap_setfilter(handle, &comp_filter) < 0) {
		DEBUG(ERROR, "No capture. pcap_setfilter() failed. %s", 
				pcap_geterr(handle));
		pcap_close(handle);
		return NULL;
	}

	// Open a file to which to write packets. The pcap_dumper_t * can be
	// passed to pcap_dump.
	pcap_dumper_t *dump = pcap_dump_open(handle, path);
	if (dump==NULL) {
		DEBUG(ERROR, "No capture. pcap_dump_open() failed. %s",
				pcap_geterr(handle)); 
		pcap_close(handle);
		return NULL;
	}

	// Start capture in another thread.
	CaptureThreadArgs *args = (CaptureThreadArgs *)
					malloc(sizeof(CaptureThreadArgs));
	args->handle = handle;
	args->dump = dump;

	int rc = pthread_create(thread, NULL, capture_thread, args);
	if (rc) {
		DEBUG(WARN, "No capture. pthread_create_failed(). %s", 
				strerror(rc));
		pcap_close(handle);
		return NULL;
	}

	return handle;
}

/* params should be CaptureThreadArgs *. 
 * Return a int * with the number of packets captured in case of success, of a 
 * negative value in case of error. */

void *capture_thread(void *params) 
{
	DEBUG(INFO, "Capture thread started.");
	CaptureThreadArgs *args = (CaptureThreadArgs *) params;
	
	// Start capture. -1 means infinity, packets are processed until 
	// pcap_breakloop() is called when we are done capturing.
	int *pcount = (int *) malloc(sizeof(int)); 
	*pcount = pcap_loop(args->handle, -1, &pcap_dump, (u_char *)args->dump);
	
	DEBUG(INFO, "Capture ended.");

	if (*pcount == -1) {
		DEBUG(ERROR, "pcap_loop() failed. %s", 
				pcap_geterr(args->handle));
	}
	
	/* The documentation states that pcap_loop() returns -2 if the loop 
	 * terminated due to a call to pcap_breakloop() BEFORE ANY PACKET WERE
	 * PROCESSED. The uppercase part is NOT true. It always returns -2 when
	 * pcap_breakloop() is called, even if some packets were captured. */
	if (*pcount != -2) {
		DEBUG(WARN, "pcap_loop() terminated before pcap_breakloop().");
	}
	
	pcap_close(args->handle);
	pcap_dump_close(args->dump);
	free(args);

	return pcount;
}

/* Stop the ongoing capture on *pcap. 
 * Retrieve return value from pcap_loop() or -3 on pthread_join() error. */

int stop_capture(pcap_t *pcap, pthread_t *thread)
{
	pcap_breakloop(pcap);
	
	// Retrieve thread.
	int *pcount_ptr;
	int pcount, rc;

	rc = pthread_join(*thread, (void **) &(pcount_ptr));
	if (rc != 0) {
		DEBUG(ERROR, "pthread_join() failed. %s", strerror(rc));
		return -3;
	}

	pcount = *pcount_ptr;
	free(pcount_ptr);
	return pcount;
}

char *build_capture_filter(const struct sockaddr *addr) 
{
	struct sockaddr_storage *addr_sto = (struct sockaddr_storage *) addr;
	char *addr_str = build_addr_str_from_sockaddr(addr_sto);
	char *port_str = build_port_str_from_sockaddr(addr_sto);
	char *filter = (char *) malloc(sizeof(char)*FILTER_SIZE);
	snprintf(filter, FILTER_SIZE, "host %s and port %s", addr_str, port_str);
	free(addr_str);
	free(port_str);
	DEBUG(INFO, "Starting capture with filter: '%s'", filter);
	return filter;
}

