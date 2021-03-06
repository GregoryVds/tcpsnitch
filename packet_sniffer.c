#define _GNU_SOURCE

#include "packet_sniffer.h"
#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "constants.h"
#include "init.h"
#include "lib.h"
#include "logger.h"
#include "logger.h"
#include "string_builders.h"

#define BUFFER_SIZE 8 * 100000  // In MB = 8MB

typedef struct {
        pcap_t *handle;
        pcap_dumper_t *dump;
        bool *switch_flag;
} CaptureThreadArgs;

typedef struct {
        bool *switch_flag;
        int delay_ms;
} DelayStopThreadArgs;

/* Internal functions */

static pcap_t *get_capture_handle(void) {
        char err_buf[PCAP_ERRBUF_SIZE];
        err_buf[0] = 0;
        pcap_t *handle = pcap_open_live("any", BUFSIZ, 0, 0, err_buf);
        if (err_buf[0] != 0) LOG(WARN, "pcap_open_live() warn. %s.", err_buf);
        if (!handle) goto error;

        if (!pcap_set_buffer_size(handle, BUFFER_SIZE))
                LOG(WARN, "pcap_set_buffer_size() failed.");

        return handle;
error:
        LOG_FUNC_ERROR;
        LOG(ERROR, "pcap_open_live() failed. %s.", err_buf);
        return NULL;
}

/* This thread captures packets indefinitely until the boolean pointed by
   switch_flag is turned to false. */
static void *capture_thread(void *params) {
        LOG_FUNC_INFO;
        CaptureThreadArgs *args = (CaptureThreadArgs *)params;

        bool *switch_flag = args->switch_flag;
        while (*switch_flag) {
                if (pcap_dispatch(args->handle, -1, &pcap_dump,
                                  (u_char *)args->dump) == -1) {
                        LOG(ERROR, "pcap_dispatch() failed. %s.",
                            pcap_geterr(args->handle));
                }
        }

        pcap_close(args->handle);
        pcap_dump_close(args->dump);
        free(switch_flag);
        free(args);
        LOG(INFO, "Capture thread ended.");
        return NULL;
}

/* The sole purpose of this thread if to wait delay_ms before setting the
 * switch flag to false. We don't want to hang the main thread, we thus do this
 * in another thread to delay the end of the packet capture. */
static void *delayed_stop_thread(void *params) {
        LOG_FUNC_INFO;
        DelayStopThreadArgs *args = (DelayStopThreadArgs *)params;
        struct timespec ns = {0, args->delay_ms * 1000000};
        nanosleep(&ns, NULL);
        *(args->switch_flag) = false;
        LOG(INFO, "Turned off capture switch.");
        return NULL;
}

/* Public functions */

// TODO: Bind to specific IP on host to filter on addr1 host too.
char *alloc_capture_filter(const struct sockaddr *addr1,
                           const struct sockaddr *addr2) {
        LOG_FUNC_INFO;
        static const char *PORT_FILTER = "port %s";
        static const char *SINGLE_FILTER = "host %s and port %s";
        static const char *DOUBLE_FILTER = "port %s and host %s and port %s";

        // Build string rep of hosts/ports
        char *port1 = NULL, *port2 = NULL, *ip1 = NULL, *ip2 = NULL;
        if (addr1) {
                if (!(port1 = alloc_port_str(addr1))) goto error_out;
                if (!(ip1 = alloc_ip_str(addr1))) goto error1;
        }
        if (addr2) {
                if (!(port2 = alloc_port_str(addr2))) goto error2;
                if (!(ip2 = alloc_ip_str(addr2))) goto error3;
        }

        // Build filter string
        static int n = 200;
        char *filter = (char *)my_malloc(sizeof(char) * n);

        if (addr1 && addr2)
                snprintf(filter, n, DOUBLE_FILTER, port1, ip2, port2);
        else if (addr1)
                snprintf(filter, n, PORT_FILTER, port1);
        else if (addr2)
                snprintf(filter, n, SINGLE_FILTER, ip2, port2);

        LOG(INFO, "Capture filter: '%s'.", filter);
        free(port1);
        free(ip1);
        free(port2);
        free(ip2);
        return filter;
error3:
        free(port2);
error2:
        free(ip1);
error1:
        free(port1);
error_out:
        LOG_FUNC_ERROR;
        return NULL;
}

bool *start_capture(const char *filter_str, const char *path) {
        LOG_FUNC_INFO;
        // Get handle
        pcap_t *handle = get_capture_handle();
        if (!handle) goto error_out;

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
        bool *switch_flag = my_malloc(sizeof(bool));
        (*switch_flag) = true;

        // Start capture in another thread.
        CaptureThreadArgs *args =
            (CaptureThreadArgs *)my_malloc(sizeof(CaptureThreadArgs));
        args->handle = handle;
        args->dump = dump;
        args->switch_flag = switch_flag;

        pthread_t thread;
        if (my_pthread_create(&thread, NULL, capture_thread, args)) goto error4;
        return switch_flag;
error4:
        free(args);
        free(switch_flag);
        pcap_dump_close(dump);
error1:
        pcap_close(handle);
error_out:
        LOG_FUNC_ERROR;
        return NULL;
}

int stop_capture(bool *switch_flag, int delay_ms) {
        LOG_FUNC_INFO;
        // Prepare args for thread
        DelayStopThreadArgs *args =
            (DelayStopThreadArgs *)my_malloc(sizeof(DelayStopThreadArgs));
        args->switch_flag = switch_flag;
        args->delay_ms = delay_ms;

        // Start thread
        pthread_t thread;
        if (my_pthread_create(&thread, NULL, delayed_stop_thread, args)) {
                *(switch_flag) = false;
                goto error;
        }
        return 0;
error:
        LOG(ERROR, "Ending packet capture immediately.");
        LOG_FUNC_ERROR;
        return -1;
}
