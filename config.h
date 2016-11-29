#ifndef CONFIG_H
#define CONFIG_H

#define NETSPY_DEFAULT_PATH "/tmp/netspy" // Default path for log filee
#define NETSPY_JSON_FILE "dump.json" // Name of tcp_spy capture file
#define NETSPY_PCAP_FILE "dump.pcap" // Name of PCAP capture file
#define NETSPY_LOG_FILE "logs"

#define TCPSPY_INIT_LOGS_FILE "init"

/* Env variables */
#define ENV_DIR "TCPSPY_DIR"
#define ENV_STDERR_LOG_LVL "TCPSPY_STDERR_LOG_LVL"
#define ENV_FILE_LOG_LVL "TCPSPY_FILE_LOG_LVL"
#define ENV_BYTES_IVAL "TCPSPY_BYTES_IVAL"
#define ENV_MICROS_IVAL "TCPSPY_MICROS_IVAL"

#endif
