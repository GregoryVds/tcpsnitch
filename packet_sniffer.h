#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include <pcap.h>
#include <pthread.h>

pcap_t *start_capture(char *filters, char *path, pthread_t *thread);
int stop_capture(pcap_t *pcap, pthread_t *thread);

#endif
