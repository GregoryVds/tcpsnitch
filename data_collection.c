#include <sys/time.h>
#include <stdlib.h>
#include "data_collection.h"
#include "lib.h"

/* We keep a mapping from file descriptors to TCP connections structs for all
 * opened connections. This allows to easily identify to which connection a 
 * given function call belongs to. 
 * 
 * This also allows us to identify when a new TCP connection is started with 
 * the same file descriptor as en existing one (meaning we missed the close()
 * call).
 *
 * This data structure is clearly NOT optimal. It could be sparse and will
 * mostly be empty. It is however extremely easy to use and provides O(1) 
 * access time. We will see later if we need something else like a hashtable 
 * or binary tree. */

#define MAX_FD 1024
TcpConnection *fd_con_map[MAX_FD];
int connections_count = 0;

void fill_timestamp(TcpEvent *event)
{
	gettimeofday(&(event->timestamp), NULL);
}

TcpEvent *new_event(TcpEventType type) 
{
	TcpEvent *ev;

	switch(type) {
		case OPEN:  ev = (TcpEvent *)  malloc(sizeof(TcpEventOpen)); 
		case CLOSE: ev = (TcpEvent *)  malloc(sizeof(TcpEventClose));
		case SEND:  ev = (TcpEvent *)  malloc(sizeof(TcpEventSend));
		case RECV:  ev = (TcpEvent *)  malloc(sizeof(TcpEventRecv));
	}
	
	fill_timestamp(ev);
	return ev;
}

TcpConnection *new_connection() 
{
	TcpConnection *con = (TcpConnection *) malloc(sizeof(TcpConnection));
	con->id = connections_count;
	con->head = NULL;
	con->tail = NULL;
	con->eventsCount = 0;
	connections_count++;
	return con;	
}

void push(TcpConnection *con, TcpEvent *ev) 
{
	TcpEventNode *node = (TcpEventNode *) malloc(sizeof(TcpEventNode));
	node->data = ev;
	node->next = NULL;

	if (!con->tail) 
		con->head = node;
	else 
		con->tail->next = node;

	con->tail = node;
	con->eventsCount++;
}

void tcp_connection_opened(int fd, bool sock_cloexec, bool sock_nonblock)
{
	DEBUG(INFO, "TCP (id %d) opened.", connections_count);

	/* Check if connection was not properly closed. */
	if (fd_con_map[fd]) {
		DEBUG(INFO, "Closing of TCP (id %d) was not properly detected."
				"Now assuming it closed.", connections_count);
		tcp_connection_closed(fd);
	}
	
	/* Track new connection */
	TcpConnection *con = new_connection();
	TcpEvent *ev = new_event(OPEN);
	push(con, ev);
	fd_con_map[fd] = con;
}

void tcp_connection_closed(int fd)
{
	DEBUG(INFO, "TCP (id %d) closed.", fd_con_map[fd]->id);
	/* TODO: Free structures & dump to file. */
	fd_con_map[fd] = NULL;
}

void tcp_data_sent(int fd, size_t bytes) 
{
	DEBUG(INFO, "%zu bytes sent on TCP (id %d).", bytes,
			fd_con_map[fd]->id); 
}

void tcp_data_received(int fd, size_t bytes)
{
	DEBUG(INFO, "%zu bytes received on TCP (id %d).", bytes,
			fd_con_map[fd]->id);
}

