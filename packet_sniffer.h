#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include <pcap.h>
#include <pthread.h>

#define FILTER_SIZE 200

pcap_t *start_capture(char *filters, char *path, pthread_t *thread);
int stop_capture(pcap_t *pcap, pthread_t *thread);
char *build_capture_filter(const struct sockaddr *addr);

#endif
