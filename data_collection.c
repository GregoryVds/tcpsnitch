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
		case SOCK_OPENED:
			ev = (TcpEvent *) malloc(sizeof(TcpEvSockOpened));
		case SOCK_CLOSED:
			ev = (TcpEvent *) malloc(sizeof(TcpEvSockClosed));
		case DATA_SENT:
			ev = (TcpEvent *) malloc(sizeof(TcpEvDataSent));
		case DATA_RECEIVED:
			ev = (TcpEvent *) malloc(sizeof(TcpEvDataReceived));
		case CONNECTED: 
			ev = (TcpEvent *) malloc(sizeof(TcpEvConnected));	
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

void dump_connection(TcpConnection *con) 
{
	DEBUG(INFO, "Dumping connection info for %d.", con->id);
}

void free_tcp_event(TcpEvent *ev) 
{
	free(ev);
}

void free_tcp_events_list(TcpEventNode *head) 
{
	TcpEventNode *cur = head;
	while (cur != NULL) {
		free_tcp_event(head->data);
		cur = head->next;
		free(head);
	}
}

void free_connection(TcpConnection *con)
{
	free_tcp_events_list(con->head);
	free(con);
}

void log_event(int fd, const char *msg) 
{
	DEBUG(TCP, "%d: %s.", fd_con_map[fd]->id, msg);
}

void tcp_sock_opened(int fd, bool sock_cloexec, bool sock_nonblock)
{
	/* Check if connection was not properly closed. */
	if (fd_con_map[fd]) {
		log_event(fd, "socket was closed earlier but close() was not "
			"detected. Assuming it closed from now on.");
		tcp_sock_closed(fd);
	}
	
	/* Track new connection */
	TcpConnection *con = new_connection();
	TcpEvent *ev = new_event(SOCK_OPENED);
	push(con, ev);
	fd_con_map[fd] = con;

	log_event(fd, "socket opened");
}

void tcp_sock_closed(int fd)
{
	log_event(fd, "socket closed");
	dump_connection(fd_con_map[fd]);
	free_connection(fd_con_map[fd]);
	fd_con_map[fd] = NULL;
}

void tcp_data_sent(int fd, size_t bytes) 
{
	log_event(fd, "data sent");

	DEBUG(INFO, "%zu bytes sent on TCP (id %d).", bytes,
			fd_con_map[fd]->id); 
}

void tcp_data_received(int fd, size_t bytes)
{
	log_event(fd, "data received");
	DEBUG(INFO, "%zu bytes received on TCP (id %d).", bytes,
			fd_con_map[fd]->id);
}

void tcp_connected(int fd)
{
	log_event(fd, "connected");
}

