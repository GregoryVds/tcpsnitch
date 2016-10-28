#ifndef CONFIG_H
#define CONFIG_H

/* Configure program behavior */
#define NETSPY_LOG true // Log to stdout if set to true.
#define NETSPY_LOG_TO_FILE true // Log to file it set to true.

#define NETSPY_DEFAULT_PATH "/tmp/netspy" // Default path for log filee
#define NETSPY_JSON_FILE "dump.json" // Name of tcp_spy capture file
#define NETSPY_PCAP_FILE "dump.pcap" // Name of PCAP capture file
#define NETSPY_LOG_FILE "log.txt" // Name of lag file

/* Env variables */
#define ENV_NETSPY_PATH "NETSPY_PATH"
#define ENV_NETSPY_DEV "NETSPY_DEV"

/* LOWER bounds for capture of tcp_info. If either one if not fullfiled, then
 * we do NOT dump. */
#define ENV_NETSPY_TCPINFO_BYTES_IVAL "NETSPY_TCPINFO_BYTES_IVAL"
#define ENV_NETSPY_TCPINFO_MICROS_IVAL "NETSPY_TCPINFO_MICROS_IVAL"


#endif

