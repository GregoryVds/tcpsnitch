#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include <pcap.h>
#include <pthread.h>
#include <netinet/in.h>
#include <stdbool.h>

char *build_capture_filter(const struct sockaddr_storage *addr1,
			   const struct sockaddr_storage *addr2);

bool *start_capture(const char *filters, const char *path);
int stop_capture(bool *switch_flag, int delay_ms);

#endif
