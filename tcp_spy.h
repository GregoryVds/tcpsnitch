/* tcp_spy.h exposes a set of functions to record all "events" that happened
 * for a given TCP connection.
 */

#ifndef TCP_SPY_H
#define TCP_SPY_H

#include <netinet/tcp.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <time.h>

typedef enum TcpEventType {
	TCP_EV_SOCK_OPENED,
	TCP_EV_SOCK_CLOSED,
	TCP_EV_SEND,
	TCP_EV_SENDTO,
	TCP_EV_RECV,
	TCP_EV_RECVFROM,
	TCP_EV_CONNECT,
	TCP_EV_INFO_DUMP,
	TCP_EV_SETSOCKOPT,
	TCP_EV_SHUTDOWN,
	TCP_EV_LISTEN,
	TCP_EV_BIND
} TcpEventType;

typedef struct {
	bool msg_confirm;
	bool msg_dontroute;
	bool msg_dontwait;
	bool msg_eor;
	bool msg_more;
	bool msg_nosignal;
	bool msg_oob;
} TcpSendFlags;

typedef struct {
	bool msg_cmsg_cloexec;
	bool msg_dontwait;
	bool msg_errqueue;
	bool msg_oob;
	bool msg_peek;
	bool msg_trunc;
	bool msg_waitall;
} TcpRecvFlags;

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
	TcpSendFlags flags;
} TcpEvSend;

typedef struct {
	TcpEvent super;
	size_t bytes;
	TcpSendFlags flags;
	struct sockaddr_storage addr;
} TcpEvSendto;

typedef struct {
	TcpEvent super;
	size_t bytes;
	TcpRecvFlags flags;
} TcpEvRecv;

typedef struct {
	TcpEvent super;
	size_t bytes;
	TcpRecvFlags flags;
	struct sockaddr_storage addr;
} TcpEvRecvfrom;

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

typedef struct {
	TcpEvent super;
	bool force_bind;
	struct sockaddr_storage addr;
} TcpEvBind;

typedef struct TcpEventNode TcpEventNode;
struct TcpEventNode {
	TcpEvent *data;
	TcpEventNode *next;
};

typedef struct {
	// To be freed
	char *app_name;      // Application name with args.
	char *cmdline;       // Cmdline (app name + args).
	char *kernel;	// Kernel version.
	char *directory;     // Directory for all logging purpose.
	TcpEventNode *head;  // Head for list of events.
	TcpEventNode *tail;  // Tail for list of events.
	// Others
	int id;			       // Connection id, starting at 0.
	int events_count;	      // List of events size.
	unsigned long bytes_sent;      // Total bytes sent.
	unsigned long bytes_received;  // Total bytes received.
	pthread_t capture_thread;      // pthread used for capturing packets.
	pcap_t *capture_handle;	// Pcap capture handle.
	bool successful_pcap;	// Successfully captured packets on handle.
	long last_info_dump_micros;  // Time of last info dump in microseconds.
	long last_info_dump_bytes;   // Total bytes (sent+recv) at last dump.
	time_t timestamp;  // When tcp_spy started tracking the connection.
	bool force_bind;
	TcpEvBind *bind_ev;
} TcpConnection;

const char *string_from_tcp_event_type(TcpEventType type);

// Packet capture

void tcp_start_packet_capture(int fd,
			      const struct sockaddr_storage *connect_addr);
void tcp_stop_packet_capture(TcpConnection *con);

// Events

void tcp_sock_opened(int fd, int domain, int type, int protocol);
void tcp_sock_closed(int fd, int return_value, int err, bool detected);
void tcp_send(int fd, int return_value, int err, size_t bytes, int flags);
void tcp_sendto(int fd, int return_value, int err, size_t bytes, int flags,
		const struct sockaddr *addr, socklen_t len);
void tcp_recv(int fd, int return_value, int err, size_t bytes, int flags);
void tcp_recvfrom(int fd, int return_value, int err, size_t bytes, int flags,
		  const struct sockaddr *addr, socklen_t len);
void tcp_connect(int fd, int return_value, int err, const struct sockaddr *addr,
		 socklen_t len);
void tcp_info_dump(int fd);
void tcp_setsockopt(int fd, int return_value, int err, int level, int optname);
void tcp_shutdown(int fd, int return_value, int err, int how);
void tcp_listen(int fd, int return_value, int err, int backlog);
void tcp_bind(int fd, int return_value, int err, const struct sockaddr *addr,
	      socklen_t len);
#endif
