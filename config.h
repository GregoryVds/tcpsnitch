#ifndef CONFIG_H
#define CONFIG_H

#define NETSPY_DEFAULT_PATH "/tmp/netspy" // Default path for log filee
#define NETSPY_JSON_FILE "dump.json" // Name of tcp_spy capture file
#define NETSPY_PCAP_FILE "dump.pcap" // Name of PCAP capture file
#define NETSPY_LOG_FILE "logs"

#define TCPSPY_INIT_LOGS_FILE "init"

/* Env variables */
#define ENV_DIR "TCPSNITCH_DIR"
#define ENV_STDERR_LOG_LVL "TCPSNITCH_STDERR_LOG_LVL"
#define ENV_FILE_LOG_LVL "TCPSNITCH_FILE_LOG_LVL"
#define ENV_BYTES_IVAL "TCPSNITCH_BYTES_IVAL"
#define ENV_MICROS_IVAL "TCPSNITCH_MICROS_IVAL"
#define ENV_VERBOSITY "TCPSNITCH_VERBOSITY" 
#endif
