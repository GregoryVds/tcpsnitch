#ifndef DATA_COLLECTION_H
#define DATA_COLLECTION_H

#include <stdio.h>
#include <time.h>

typedef enum TcpEventType
{
	OPEN,
	CLOSE,
	SEND,
	RECV
} TcpEventType;

typedef struct {
	TcpEventType type;
	struct timeval timestamp;
} TcpEvent;

typedef struct {
	TcpEvent super;
	bool sock_cloexec;
	bool sock_nonblock;
} TcpEventOpen;

typedef struct {
	TcpEvent super;
} TcpEventClose;

typedef struct {
	TcpEvent super;
	size_t bytes;
} TcpEventSend;

typedef struct {
	TcpEvent super;
	size_t bytes;
} TcpEventRecv;

typedef struct TcpEventNode TcpEventNode;

struct TcpEventNode {
	TcpEvent *data;
	TcpEventNode *next;
};

typedef struct {
	int id;
	TcpEventNode *head;
	TcpEventNode *tail;
	int eventsCount;
} TcpConnection;

TcpConnection *new_connection();
TcpEvent *new_event(TcpEventType type);

void fill_timestamp(TcpEvent *ev);
void push(TcpConnection *con, TcpEvent *ev);

void tcp_connection_opened(int fd, bool sock_cloexec, bool sock_nonblock);
void tcp_connection_closed(int fd);
void tcp_data_sent(int fd, size_t bytes);
void tcp_data_received(int fd, size_t bytes);

#endif
