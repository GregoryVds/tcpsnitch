#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include <pcap.h>
#include <pthread.h>
#include <netinet/in.h>
#include <stdbool.h>

#define FILTER_SIZE 200

bool *start_capture(char *filters, char *path);
char *build_capture_filter(const struct sockaddr_storage *bound_addr,
			   const struct sockaddr_storage *connect_addr);
int stop_capture(bool *switch_flag, int delay_ms);

#endif
