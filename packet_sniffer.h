#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include <netinet/in.h>
#include <pcap.h>
#include <pthread.h>
#include <stdbool.h>

char *alloc_capture_filter(const struct sockaddr *addr1,
                           const struct sockaddr *addr2);

bool *start_capture(const char *filters, const char *path);
int stop_capture(bool *switch_flag, int delay_ms);

#endif
