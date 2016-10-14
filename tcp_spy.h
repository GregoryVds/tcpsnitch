#ifndef TCP_SPY_H
#define TCP_SPY_H

#include <stdbool.h>
#include <sys/socket.h>
#include <time.h>
#include <stdio.h>
#include <netinet/tcp.h>

typedef enum TcpEventType
{
	SOCK_OPENED,
	SOCK_CLOSED,
	DATA_SENT,
	DATA_RECEIVED,
	CONNECT,
	INFO_DUMP,
	SETSOCKOPT
} TcpEventType;

const char *string_from_tcp_event_type(TcpEventType type);

typedef struct {
	TcpEventType type;
	struct timeval timestamp;
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

typedef struct TcpEventNode TcpEventNode;

struct TcpEventNode {
	TcpEvent *data;
	TcpEventNode *next;
};

typedef struct {
	int id;
	TcpEventNode *head;
	TcpEventNode *tail;
	int events_count;
	bool connected;
	unsigned long bytes_sent;
	unsigned long bytes_received;
	bool closed;
} TcpConnection;


void tcp_sock_opened(int fd, int domain, int protocol, bool sock_cloexec, 
		bool sock_nonblock);
void tcp_sock_closed(int fd);
void tcp_data_sent(int fd, size_t bytes);
void tcp_data_received(int fd, size_t bytes);
void tcp_connect(int fd, const struct sockaddr *addr, socklen_t len);
void tcp_info_dump(int fd);
void tcp_setsockopt(int fd, int level, int optname);
#endif
