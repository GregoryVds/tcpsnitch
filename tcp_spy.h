#ifndef TCP_SPY_H
#define TCP_SPY_H

#include <stdbool.h>
#include <sys/socket.h>
#include <time.h>
#include <stdio.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>

typedef enum TcpEventType
{
	TCP_EV_SOCK_OPENED,
	TCP_EV_SOCK_CLOSED,
	TCP_EV_DATA_SENT,
	TCP_EV_DATA_RECEIVED,
	TCP_EV_CONNECT,
	TCP_EV_INFO_DUMP,
	TCP_EV_SETSOCKOPT,
	TCP_EV_SHUTDOWN,
	TCP_EV_LISTEN
} TcpEventType;

const char *string_from_tcp_event_type(TcpEventType type);

typedef struct {
	TcpEventType type;
	struct timeval timestamp;
	int return_value;
	bool success;
	char *error_str;
} TcpEvent;

typedef struct {
	TcpEvent super;
	int domain;
	int type;
	int protocol;
	bool sock_cloexec;
	bool sock_nonblock;
} TcpEvSockOpened;

typedef struct {
	TcpEvent super;
	bool detected;
} TcpEvSockClosed;

typedef struct {
	TcpEvent super;
	size_t bytes;
} TcpEvDataSent;

typedef struct {
	TcpEvent super;
	size_t bytes;
} TcpEvDataReceived;

typedef struct {
	TcpEvent super;
	struct sockaddr_storage addr;
} TcpEvConnect;

typedef struct {
	TcpEvent super;
	struct tcp_info info;
} TcpEvInfoDump;

typedef struct {
	TcpEvent super;
	int level;
	int optname;
} TcpEvSetsockopt;

typedef struct {
	TcpEvent super;
	bool shut_rd;
	bool shut_wr;
} TcpEvShutdown;

typedef struct {
	TcpEvent super;
	int backlog;
} TcpEvListen;

typedef struct TcpEventNode TcpEventNode;

struct TcpEventNode {
	TcpEvent *data;
	TcpEventNode *next;
};

typedef struct {
	// To be freed
	char *app_name; // Application name with args.
	char *cmdline; // Cmdline (app name + args).
	char *dirname; // Directory name for log files.
	char *kernel; // Kernel version.
	TcpEventNode *head; // Head for list of events.
	TcpEventNode *tail; // Tail for list of events.
	// Others
	int id; // Connection id, starting at 0.
	int events_count; // List of events size.
	unsigned long bytes_sent; // Total bytes sent.
	unsigned long bytes_received; // Total bytes received.
	pthread_t capture_thread; // pthread used for capturing packets.
	pcap_t *capture_handle; // Pcap capture handle.
	bool got_pcap_handle; // Succesfully acquired a pcap handle.
	bool successful_pcap; // Successfully captured packets on handle. 
	long last_info_dump_micros; // Time of last info dump in microseconds.
	long last_info_dump_bytes; // Total bytes (sent+recv) at last dump.
	time_t timestamp; // When tcp_spy started tracking the connection.
} TcpConnection;


void tcp_sock_opened(int fd, int domain, int protocol, bool sock_cloexec, 
		bool sock_nonblock);
void tcp_sock_closed(int fd, int return_value, bool detected);
void tcp_data_sent(int fd, int return_value, size_t bytes);
void tcp_data_received(int fd, int return_value, size_t bytes);
void tcp_pre_connect(int fd, const struct sockaddr *addr);
void tcp_connect(int fd, int return_value, const struct sockaddr *addr,
		socklen_t len);
void tcp_info_dump(int fd);
void tcp_setsockopt(int fd, int return_value, int level, int optname);
void tcp_shutdown(int fd, int return_value, int how);
void tcp_listen(int fd, int return_value, int backlog);

#endif
