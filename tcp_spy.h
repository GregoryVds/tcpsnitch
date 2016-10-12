#ifndef DATA_COLLECTION_H
#define DATA_COLLECTION_H

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <time.h>

typedef enum TcpEventType
{
	SOCK_OPENED,
	SOCK_CLOSED,
	DATA_SENT,
	DATA_RECEIVED,
	CONNECTED
} TcpEventType;

typedef struct {
	TcpEventType type;
	struct timeval timestamp;
} TcpEvent;

typedef struct {
	TcpEvent super;
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
} TcpEvConnected;

typedef struct {
	TcpEvent super;
	struct tcp_info info;
} TcpEvTcpInfoDump;

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
	size_t bytes_out;
	unsigned long bytes_sent;
	unsigned long bytes_received;
	struct sockaddr_storage peer_addr;
	bool closed;
} TcpConnection;

TcpConnection *new_connection();
TcpEvent *new_event(TcpEventType type);

void fill_timestamp(TcpEvent *ev);
void push(TcpConnection *con, TcpEvent *ev);

void tcp_sock_opened(int fd, bool sock_cloexec, bool sock_nonblock);
void tcp_sock_closed(int fd);
void tcp_data_sent(int fd, size_t bytes);
void tcp_data_received(int fd, size_t bytes);
void tcp_connected(int fd, __CONST_SOCKADDR_ARG addr, socklen_t len);

#endif
