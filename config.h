#ifndef CONFIG_H
#define CONFIG_H

#define NETSPY_DEFAULT_PATH "/tmp/netspy" // Default path for log filee
#define NETSPY_JSON_FILE "dump.json" // Name of tcp_spy capture file
#define NETSPY_PCAP_FILE "dump.pcap" // Name of PCAP capture file
#define NETSPY_LOG_FILE "logs"

/* Env variables */
#define ENV_PATH "NETSPY_PATH"
#define ENV_DEV "NETSPY_DEV"

/* LOWER bounds for capture of tcp_info. If either one if not fullfiled, then
 * we do NOT dump. */
#define ENV_BYTES_IVAL "NETSPY_BYTES_IVAL"
#define ENV_MICROS_IVAL "NETSPY_MICROS_IVAL"


#endif

