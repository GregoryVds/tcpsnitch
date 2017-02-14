#ifndef TCP_SPY_H
#define TCP_SPY_H

#include <netinet/tcp.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <time.h>

typedef enum TcpEventType {
	TCP_EV_SOCKET,
	TCP_EV_BIND,
	TCP_EV_CONNECT,
	TCP_EV_SHUTDOWN,
	TCP_EV_LISTEN,
	TCP_EV_ACCEPT,
	TCP_EV_GETSOCKOPT,
	TCP_EV_SETSOCKOPT,
	TCP_EV_SEND,
	TCP_EV_RECV,
	TCP_EV_SENDTO,
	TCP_EV_RECVFROM,
	TCP_EV_SENDMSG,
	TCP_EV_RECVMSG,
#if !defined(__ANDROID__) || __ANDROID_API__ >= 21
	TCP_EV_SENDMMSG,
	TCP_EV_RECVMMSG,
#endif
	// unistd.h
	TCP_EV_WRITE,
	TCP_EV_READ,
	TCP_EV_CLOSE,
	TCP_EV_DUP,
	TCP_EV_DUP2,
	TCP_EV_DUP3,
	// sys/uio.h
	TCP_EV_WRITEV,
	TCP_EV_READV,
	// sys/ioctl.h
	TCP_EV_IOCTL,
	// others
	TCP_EV_TCP_INFO
} TcpEventType;

typedef struct {
	TcpEventType type;
	struct timeval timestamp;
	int return_value;
	bool success;
	char *error_str;
	long id;
} TcpEvent;

typedef struct {
	TcpEvent super;
	int domain;
	int type;
	int protocol;
	bool sock_cloexec;
	bool sock_nonblock;
} TcpEvSocket;

typedef struct {
	struct sockaddr_storage addr_sto;
	char *ip;
	char *port;
	char *name;
	char *serv;
} TcpAddr;

typedef struct {
	TcpEvent super;
	bool force_bind;
	TcpAddr addr;
} TcpEvBind;

typedef struct {
	TcpEvent super;
	TcpAddr addr;
} TcpEvConnect;

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
	TcpAddr addr;
} TcpEvAccept;

typedef struct {
	int level;
	char *level_str;
	int optname;
	char *optname_str;
} TcpSockopt;

typedef struct {
	TcpEvent super;
	TcpSockopt sockopt;
} TcpEvGetsockopt;

typedef struct {
	TcpEvent super;
	TcpSockopt sockopt;
} TcpEvSetsockopt;

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
	TcpEvent super;
	size_t bytes;
	TcpSendFlags flags;
} TcpEvSend;

typedef struct {
	TcpEvent super;
	size_t bytes;
	TcpRecvFlags flags;
} TcpEvRecv;

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
	struct sockaddr_storage addr;
} TcpEvRecvfrom;

typedef struct {
	int iovec_count;
	size_t *iovec_sizes;
} TcpIovec;

typedef struct {
	TcpIovec iovec;
	bool control_data;
	struct sockaddr_storage addr;
} TcpMsghdr;

typedef struct {
	TcpEvent super;
	size_t bytes;
	TcpSendFlags flags;
	TcpMsghdr msghdr;
} TcpEvSendmsg;

typedef struct {
	TcpEvent super;
	size_t bytes;
	TcpRecvFlags flags;
	TcpMsghdr msghdr;
} TcpEvRecvmsg;

#if !defined(__ANDROID__) || __ANDROID_API__ >= 21
typedef struct {
	TcpMsghdr msghdr;
	unsigned int msg_len;
} TcpMmsghdr;

typedef struct {
	TcpEvent super;
	size_t bytes;
	TcpSendFlags flags;
	int mmsghdr_count;
	TcpMmsghdr **msghdr;
} TcpEvSendmmsg;

typedef struct {
	TcpEvent super;
	size_t bytes;
	TcpRecvFlags flags;
	int mmsghdr_count;
	TcpMmsghdr **msghdr;
} TcpEvRecvmmsg;
#endif

typedef struct {
	TcpEvent super;
	size_t bytes;
} TcpEvWrite;

typedef struct {
	TcpEvent super;
	size_t bytes;
} TcpEvRead;

typedef struct {
	TcpEvent super;
	bool detected;
} TcpEvClose;

typedef struct { TcpEvent super; } TcpEvDup;

typedef struct {
	TcpEvent super;
	int newfd;
} TcpEvDup2;

typedef struct {
	TcpEvent super;
	int newfd;
	bool o_cloexec;
} TcpEvDup3;

typedef struct {
	TcpEvent super;
	size_t bytes;
	TcpIovec iovec;
} TcpEvWritev;

typedef struct {
	TcpEvent super;
	size_t bytes;
	TcpIovec iovec;
} TcpEvReadv;

typedef struct {
	TcpEvent super;
#ifdef __ANDROID__
	int request;
#else
	unsigned long int request;
#endif
} TcpEvIoctl;

typedef struct {
	TcpEvent super;
	struct tcp_info info;
} TcpEvTcpInfo;

typedef struct TcpEventNode TcpEventNode;
struct TcpEventNode {
	TcpEvent *data;
	TcpEventNode *next;
};

typedef struct {
	// To be freed
	char *directory;     // Directory for all logging purpose.
	TcpEventNode *head;  // Head for list of events.
	TcpEventNode *tail;  // Tail for list of events.
	// Others
	int id;
	int fd;
	long events_count;
	unsigned long bytes_sent;      // Total bytes sent.
	unsigned long bytes_received;  // Total bytes received.
	long last_info_dump_micros;  // Time of last info dump in microseconds.
	long last_info_dump_bytes;   // Total bytes (sent+recv) at last dump.
	long last_json_dump_micros;
	long last_json_dump_evcount;
	bool force_bind;
	bool bound;
	struct sockaddr_storage bound_addr;
	int rtt;
	bool *capture_switch;
	bool *json_dump_switch;
} TcpConnection;

const char *string_from_tcp_event_type(TcpEventType type);

void free_connection(TcpConnection *con);

// Packet capture

void tcp_start_capture(int fd, const struct sockaddr *connect_addr);

void tcp_stop_capture(TcpConnection *con);

// Events hooks

void tcp_ev_socket(int fd, int domain, int type, int protocol);

void tcp_ev_bind(int fd, int ret, int err, const struct sockaddr *addr,
		 socklen_t len);

void tcp_ev_connect(int fd, int ret, int err, const struct sockaddr *addr,
		    socklen_t len);

void tcp_ev_shutdown(int fd, int ret, int err, int how);

void tcp_ev_listen(int fd, int ret, int err, int backlog);

void tcp_ev_accept(int fd, int ret, int err, struct sockaddr *addr,
		   socklen_t *addr_len);

void tcp_ev_getsockopt(int fd, int ret, int err, int level, int optname);

void tcp_ev_setsockopt(int fd, int ret, int err, int level, int optname);

void tcp_ev_send(int fd, int ret, int err, size_t bytes, int flags);

void tcp_ev_recv(int fd, int ret, int err, size_t bytes, int flags);

void tcp_ev_sendto(int fd, int ret, int err, size_t bytes, int flags,
		   const struct sockaddr *addr, socklen_t len);

void tcp_ev_recvfrom(int fd, int ret, int err, size_t bytes, int flags,
		     const struct sockaddr *addr, socklen_t *len);

void tcp_ev_sendmsg(int fd, int ret, int err, const struct msghdr *msg,
		    int flags);

void tcp_ev_recvmsg(int fd, int ret, int err, const struct msghdr *msg,
		    int flags);
#if !defined(__ANDROID__)
void tcp_ev_sendmmsg(int fd, int ret, int err, struct mmsghdr *vmessages,
		     unsigned int vlen, int flags);
#elif __ANDROID_API__ >= 21
void tcp_ev_sendmmsg(int fd, int ret, int err, const struct mmsghdr *vmessages,
		     unsigned int vlen, int flags);
#endif

#if !defined(__ANDROID__)
void tcp_ev_recvmmsg(int fd, int ret, int err, struct mmsghdr *vmessages,
		     unsigned int vlen, int flags, struct timespec *tmo);
#elif __ANDROID_API__ >= 21
void tcp_ev_recvmmsg(int fd, int ret, int err, struct mmsghdr *vmessages,
		     unsigned int vlen, int flags, const struct timespec *tmo);
#endif

void tcp_ev_write(int fd, int ret, int err, size_t bytes);

void tcp_ev_read(int fd, int ret, int err, size_t bytes);

void tcp_ev_close(int fd, int ret, int err, bool detected);

void tcp_ev_dup(int fd, int ret, int err);

void tcp_ev_dup2(int fd, int ret, int err, int newfd);

void tcp_ev_dup3(int fd, int ret, int err, int newfd, int flags);

void tcp_ev_writev(int fd, int ret, int err, const struct iovec *iovec,
		   int iovec_count);

void tcp_ev_readv(int fd, int ret, int err, const struct iovec *iovec,
		  int iovec_count);

#ifdef __ANDROID__
void tcp_ev_ioctl(int fd, int ret, int err, int request);
#else
void tcp_ev_ioctl(int fd, int ret, int err, unsigned long int request);
#endif

void tcp_ev_tcp_info(int fd, int ret, int err, struct tcp_info *info);

void tcp_close_unclosed_connections(void);

void tcp_free(void);  // Free state.
// Free state and restore to default state (called after fork()).
void tcp_reset(void);

#endif
