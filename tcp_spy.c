#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include "tcp_spy.h"
#include "lib.h"
#include "tcp_json_builder.h"

#define ENV_NETSPY_PATH "NETSPY_PATH"

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

const char *string_from_tcp_event_type(TcpEventType type)
{
	
	static const char *strings[] = { "SOCK_OPENED", "SOCK_CLOSED", 
		"DATA_SENT", "DATA_RECEIVED", "CONNECT", "INFO_DUMP",
		"SETSOCKOPT" };
	return strings[type];
}


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
			break;
		case SOCK_CLOSED:
			ev = (TcpEvent *) malloc(sizeof(TcpEvSockClosed));
			break;
		case DATA_SENT:
			ev = (TcpEvent *) malloc(sizeof(TcpEvDataSent));
			break;
		case DATA_RECEIVED:
			ev = (TcpEvent *) malloc(sizeof(TcpEvDataReceived));
			break;
		case CONNECT: 
			ev = (TcpEvent *) malloc(sizeof(TcpEvConnect));	
			break;
		case INFO_DUMP:
			ev = (TcpEvent *) malloc(sizeof(TcpEvInfoDump));
			break;
		case SETSOCKOPT:
			ev = (TcpEvent *) malloc(sizeof(TcpEvSetsockopt));
			break;
		default:
			DEBUG(ERROR, "Event type not managed.");
			exit(EXIT_FAILURE);
	}

	ev->type = type;
	fill_timestamp(ev);
	return ev;
}

TcpConnection *new_connection() 
{
	TcpConnection *con = (TcpConnection *) calloc(sizeof(TcpConnection), 1);
	con->id = connections_count;
	connections_count++;
	return con;	
}

void push(TcpConnection *con, TcpEvent *ev) 
{
	TcpEventNode *node = (TcpEventNode *) malloc(sizeof(TcpEventNode));
	node->data = ev;
	node->next = NULL;

	if (!con->head) 
		con->head = node;
	else 
		con->tail->next = node;

	con->tail = node;
	con->events_count++;
}

void free_tcp_event(TcpEvent *ev) 
{
	switch (ev->type) {
		case CONNECT: 
		{
			TcpEvConnect *cast = (TcpEvConnect *) ev;
			if (cast->error_str != NULL) free(cast->error_str);
			break;
		}
		default: break;
	}
	free(ev);
}

void free_tcp_events_list(TcpEventNode *head) 
{
	TcpEventNode *tmp;

	while (head != NULL) {
		free_tcp_event(head->data);
		tmp = head;
		head = head->next;
		free(tmp);
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

/*
  _____                 _         _                 _        
 | ____|_   _____ _ __ | |_ ___  | |__   ___   ___ | | _____ 
 |  _| \ \ / / _ \ '_ \| __/ __| | '_ \ / _ \ / _ \| |/ / __|
 | |___ \ V /  __/ | | | |_\__ \ | | | | (_) | (_) |   <\__ \
 |_____| \_/ \___|_| |_|\__|___/ |_| |_|\___/ \___/|_|\_\___/

 Functions for registering new events on a given connection.
*/

void tcp_sock_opened(int fd, int domain, int protocol, bool sock_cloexec,
		bool sock_nonblock)
{
	/* Check if connection was not properly closed. */
	if (fd_con_map[fd]) {
		log_event(fd, "socket was closed earlier but close() was not "
			"detected. Assuming it closed from now on.");
		tcp_sock_closed(fd);
	}
	
	/* Create new connection */
	TcpConnection *con = new_connection();
	fd_con_map[fd] = con;

	/* Create event */
	TcpEvSockOpened *ev = (TcpEvSockOpened *) new_event(SOCK_OPENED);
	ev->domain = domain;
	ev->type = SOCK_STREAM;
	ev->protocol = protocol;
	ev->sock_cloexec = sock_cloexec;
	ev->sock_nonblock = sock_nonblock;
	push(con, (TcpEvent *) ev);

	log_event(fd, "socket opened");
}

void tcp_sock_closed(int fd)
{
	/* Update con */
	TcpConnection *con = fd_con_map[fd];
	con->closed = false;

	/* Create event */
	TcpEvent *ev = new_event(SOCK_CLOSED);
	push(con, ev);

	/* Save data */
	char *json = build_tcp_connection_json(con);
	const char *file_path = getenv(ENV_NETSPY_PATH);
	if (append_string_to_file((const char *) json, file_path) == -1) {
		DEBUG(ERROR, "Problems when dumping to file.");
	}
	log_event(fd, "socket closed");

	/* Cleanup */
	free_connection(con);
	fd_con_map[fd] = NULL; // Must be done after log_event.
}

void tcp_data_sent(int fd, size_t bytes) 
{
	/* Update con */
	TcpConnection *con = fd_con_map[fd];
	con->bytes_sent+=bytes;

	/* Create event */
	TcpEvDataSent *ev = (TcpEvDataSent *) new_event(DATA_SENT);
	ev->bytes = bytes;
	push(con, (TcpEvent *) ev);
	
	log_event(fd, "data sent");
}

void tcp_data_received(int fd, size_t bytes)
{
	/* Update con */
	TcpConnection *con = fd_con_map[fd];
	con->bytes_received+=bytes;
	
	/* Create event */
	TcpEvDataReceived *ev = (TcpEvDataReceived *) new_event(DATA_RECEIVED);
	ev->bytes = bytes;
	push(con, (TcpEvent *) ev);

	log_event(fd, "data received");
}

void tcp_connect(int fd, const struct sockaddr *addr, socklen_t len, 
		int return_value)
{
	/* Update con */
	TcpConnection *con = fd_con_map[fd];	
			
	/* Create event */
	TcpEvConnect *ev = (TcpEvConnect *) new_event(CONNECT);
	memcpy(&(ev->addr), addr, len);
	ev->return_value = return_value;
	if (return_value == -1) {
		char *err_str = strerror(errno);
		size_t str_len = strlen(err_str)+1;
		ev->error_str = (char *) malloc(str_len);
		strncpy(ev->error_str, err_str, str_len);
	} else
		ev->error_str = NULL;

	push(con, (TcpEvent *) ev);

	log_event(fd, "connect");
}

void tcp_info_dump(int fd)
{
	/* Update con */
	TcpConnection *con = fd_con_map[fd];	
			
	/* Create event */
	TcpEvInfoDump *ev = (TcpEvInfoDump *) new_event(INFO_DUMP);
	socklen_t tcp_info_len = sizeof(struct tcp_info);
	if (getsockopt(fd, SOL_TCP, TCP_INFO, (void *)&(ev->info), 
				&tcp_info_len) == -1) {
		die_with_system_msg("getsockopt() failed");		
	}
	push(con, (TcpEvent *) ev);

	log_event(fd, "info dump");
}

void tcp_setsockopt(int fd, int level, int optname)
{
	/* Update con */
	TcpConnection *con = fd_con_map[fd];	
			
	/* Create event */
	TcpEvSetsockopt *ev = (TcpEvSetsockopt *) new_event(SETSOCKOPT);
	ev->level = level;
	ev->optname = optname;
	push(con, (TcpEvent *) ev);

	log_event(fd, "setsockopt");
}

