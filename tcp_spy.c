#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include <pcap/pcap.h>
#include "tcp_spy.h"
#include "lib.h"
#include "tcp_json_builder.h"
#include "packet_sniffer.h"
#include "config.h"

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

// TODO: Add mutexes to protect accesses to this array.
#define MAX_FD 1024
TcpConnection *fd_con_map[MAX_FD];
int connections_count = 0;
long tcp_info_bytes_ival = -1; // Set to -1 when not parsed. 0 if ommited.
long tcp_info_time_ival = -1; // Set to -1 when not parsed. 0 if ommited.

const char *string_from_tcp_event_type(TcpEventType type)
{
	
	static const char *strings[] = { "TCP_EV_SOCK_OPENED", 
					 "TCP_EV_SOCK_CLOSED", 
					 "TCP_EV_DATA_SENT",
					 "TCP_EV_DATA_RECEIVED",
					 "TCP_EV_CONNECT",
					 "TCP_EV_INFO_DUMP",
					 "TCP_EV_SETSOCKOPT",
					 "TCP_EV_SHUTDOWN",
					 "TCP_EV_LISTEN" };
	return strings[type];
}


void fill_timestamp(TcpEvent *event)
{
	gettimeofday(&(event->timestamp), NULL);
}

TcpEvent *new_event(TcpEventType type, bool success, int return_value)
{
	TcpEvent *ev;

	switch(type) {
		case TCP_EV_SOCK_OPENED:
			ev = (TcpEvent *) malloc(sizeof(TcpEvSockOpened));
			break;
		case TCP_EV_SOCK_CLOSED:
			ev = (TcpEvent *) malloc(sizeof(TcpEvSockClosed));
			break;
		case TCP_EV_DATA_SENT:
			ev = (TcpEvent *) malloc(sizeof(TcpEvDataSent));
			break;
		case TCP_EV_DATA_RECEIVED:
			ev = (TcpEvent *) malloc(sizeof(TcpEvDataReceived));
			break;
		case TCP_EV_CONNECT: 
			ev = (TcpEvent *) malloc(sizeof(TcpEvConnect));	
			break;
		case TCP_EV_INFO_DUMP:
			ev = (TcpEvent *) malloc(sizeof(TcpEvInfoDump));
			break;
		case TCP_EV_SETSOCKOPT:
			ev = (TcpEvent *) malloc(sizeof(TcpEvSetsockopt));
			break;
		case TCP_EV_SHUTDOWN:
			ev = (TcpEvent *) malloc(sizeof(TcpEvShutdown));
			break;
		case TCP_EV_LISTEN:
			ev = (TcpEvent *) malloc(sizeof(TcpEvListen));
			break;
	}

	fill_timestamp(ev);
	ev->type = type;
	ev->return_value = return_value;
	ev->success = success;
	if (success) 
		ev->error_str = NULL;
	else { // Fill error string form errno.
		char *err_str = strerror(errno);
		size_t str_len = strlen(err_str)+1;
		ev->error_str = (char *) malloc(str_len);
		strncpy(ev->error_str, err_str, str_len);	
	}

	return ev;
}

#define TIMESTAMP_WIDTH 10
char *build_dirname(char *app_name)
{
	int app_name_length = strlen(app_name);
	int n = app_name_length+TIMESTAMP_WIDTH+2; // APP_TIMESTAMP\0
	char *dirname = (char *) calloc(sizeof(char), n);
	strncat(dirname, app_name, app_name_length);
	strncat(dirname, "_", 1);
	snprintf(dirname+strlen(dirname), TIMESTAMP_WIDTH,
			"%lu", get_time_sec());
	return dirname;
}

TcpConnection *new_connection() 
{
	TcpConnection *con = (TcpConnection *) calloc(sizeof(TcpConnection), 1);
	con->id = connections_count;
	con->cmdline= build_cmdline(&(con->app_name)); 
	con->timestamp = get_time_sec();
	con->dirname = build_dirname(con->app_name);
	con->kernel = build_kernel();
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
	if (ev->error_str != NULL) free(ev->error_str);
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
	free(con->app_name);
	free(con->cmdline);
	free(con->dirname);
	free(con->kernel);
	free(con);
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
	if (fd_con_map[fd]) tcp_sock_closed(fd, 0, false);

	/* Create new connection */
	TcpConnection *con = new_connection();
	fd_con_map[fd] = con;

	/* Create event */
	TcpEvSockOpened *ev = (TcpEvSockOpened *) new_event(TCP_EV_SOCK_OPENED,
			true, fd);
	ev->domain = domain;
	ev->type = SOCK_STREAM;
	ev->protocol = protocol;
	ev->sock_cloexec = sock_cloexec;
	ev->sock_nonblock = sock_nonblock;
	push(con, (TcpEvent *) ev);
}

void tcp_sock_closed(int fd, int return_value, bool detected)
{
	/* Update con */
	TcpConnection *con = fd_con_map[fd];

	/* Create event */
	TcpEvSockClosed *ev = (TcpEvSockClosed *) new_event(TCP_EV_SOCK_CLOSED,
			return_value!=-1, return_value);
	ev->detected = detected;
	push(con, (TcpEvent *) ev);

	/* Stop packet capture */
	int rc = 0;
	if (con->capture_handle != NULL) {
		rc = stop_capture(con->capture_handle, &(con->capture_thread));
	}
	con->successful_pcap = (rc==-2);

	/* Save data */
	char *json = build_tcp_connection_json(con);
	char *file_path = build_json_path(); 
	if (append_string_to_file((const char *) json, file_path) == -1) {
		DEBUG(ERROR, "Problems when dumping to file.");
	}
	free(file_path);

	/* Cleanup */
	free_connection(con);
	fd_con_map[fd] = NULL;
}

void tcp_data_sent(int fd, int return_value, size_t bytes) 
{
	/* Update con */
	TcpConnection *con = fd_con_map[fd];
	con->bytes_sent+=bytes;

	/* Create event */
	TcpEvDataSent *ev = (TcpEvDataSent *) new_event(TCP_EV_DATA_SENT,
			return_value!=-1, return_value);
	ev->bytes = bytes;
	push(con, (TcpEvent *) ev);
}

void tcp_data_received(int fd, int return_value, size_t bytes)
{
	/* Update con */
	TcpConnection *con = fd_con_map[fd];
	con->bytes_received+=bytes;
	
	/* Create event */
	TcpEvDataReceived *ev = (TcpEvDataReceived *) new_event(
			TCP_EV_DATA_RECEIVED, return_value!=-1, return_value);
	ev->bytes = bytes;
	push(con, (TcpEvent *) ev);
}

void tcp_pre_connect(int fd, const struct sockaddr *addr)
{
	/* Update con */
	 TcpConnection *con = fd_con_map[fd];	

	/* Start packet capture */
	char *file_path = build_pcap_path(); 
	char *filter = build_capture_filter(addr);
	con->capture_handle = start_capture(filter, file_path, 
			&(con->capture_thread));
	con->got_pcap_handle = (con->capture_handle!=NULL);
	free(filter);
	free(file_path);
}

void tcp_connect(int fd, int return_value, const struct sockaddr *addr, 
		socklen_t len)
{
	/* Update con */
	TcpConnection *con = fd_con_map[fd];	
			
	/* Create event */
	TcpEvConnect *ev = (TcpEvConnect *) new_event(TCP_EV_CONNECT,
			return_value!=-1, return_value);
	memcpy(&(ev->addr), addr, len);
	push(con, (TcpEvent *) ev);
}

/* Retrieve interval for tcpinfo (could be byte ou time interval).
 * If not set or in incorrect format, we assume 0 and thus no lower bound. */
long get_tcpinfo_ival(const char *env_var)
{
	long t = get_long_env(env_var);
	if (t == -1) DEBUG(WARN, "No interval set with %s.", env_var);
	if (t == -2) DEBUG(ERROR, "Invalid interval set with %s.", env_var);
	if (t == -3) DEBUG(ERROR, "Interval set with %s overflows.", env_var);
	if (t < 0) {
		DEBUG(WARN, "Interval %s assumed to be 0. No lower bound "
			"set on tcp_info capture frequency.", env_var);
	}
	return (t < 0) ? 0 : t;
}

void extract_tcpinfo_ivals()
{
	tcp_info_bytes_ival = get_tcpinfo_ival(ENV_NETSPY_TCPINFO_BYTES_IVAL);
	DEBUG(WARN, "tcp_info min bytes interval set to %lu", tcp_info_bytes_ival);
	tcp_info_time_ival = get_tcpinfo_ival(ENV_NETSPY_TCPINFO_MICROS_IVAL);
	DEBUG(WARN, "tcp_info min micros interval set to %lu", tcp_info_time_ival);
}


bool should_dump_tcp_info(TcpConnection *con)
{
	/* Extract env variables if not done yet (set to -1) */
	if (tcp_info_bytes_ival == -1 || tcp_info_time_ival == -1)
		extract_tcpinfo_ivals();

	/* Check if time lower bound is set, otherwise assume no lower bound */
	if (tcp_info_time_ival > 0) {
		long cur_time = get_time_micros();
		long time_elasped = cur_time - con->last_info_dump_micros;
		if (time_elasped < tcp_info_time_ival) return false;
	}
	
	/* Check if bytes lower bound set, otherwise assume no lower bound */
	if (tcp_info_bytes_ival > 0) {
		long cur_bytes = con->bytes_sent+con->bytes_received;
		long bytes_elapsed = cur_bytes - con->last_info_dump_bytes;
		if (bytes_elapsed < tcp_info_bytes_ival) return false;
	}
	
	/* If we reach this point, no lower bound prevents from dumping */
	return true;
}

void tcp_info_dump(int fd)
{
	/* Update con */
	TcpConnection *con = fd_con_map[fd];	
	
	/* Check if should dump */
	if (!should_dump_tcp_info(con)) return;	
	DEBUG(INFO, "Dumping tcp_info");

	/* Create event */
	TcpEvInfoDump *ev = (TcpEvInfoDump *) new_event(TCP_EV_INFO_DUMP, true,
			0);
	socklen_t tcp_info_len = sizeof(struct tcp_info);
	if (getsockopt(fd, SOL_TCP, TCP_INFO, (void *)&(ev->info), 
				&tcp_info_len) == -1) {
		DEBUG(ERROR, "getsockopt() failed. %s", strerror(errno));
	}
	
	/* Register time/bytes of last dump */
	con->last_info_dump_bytes = con->bytes_sent+con->bytes_received;
	con->last_info_dump_micros = get_time_micros();

	push(con, (TcpEvent *) ev);
}

void tcp_setsockopt(int fd, int return_value, int level, int optname)
{
	/* Update con */
	TcpConnection *con = fd_con_map[fd];	
			
	/* Create event */
	TcpEvSetsockopt *ev = (TcpEvSetsockopt *) new_event(TCP_EV_SETSOCKOPT,
			return_value!=1, return_value);
	ev->level = level;
	ev->optname = optname;
	push(con, (TcpEvent *) ev);
}

void tcp_shutdown(int fd, int return_value, int how) 
{
	/* Update con */
	TcpConnection *con = fd_con_map[fd];

	/* Create event */
	TcpEvShutdown *ev = (TcpEvShutdown *) new_event(TCP_EV_SHUTDOWN,
			return_value!=-1, return_value);
	ev->shut_rd = (how == SHUT_RD) || (how == SHUT_RDWR);
	ev->shut_wr = (how == SHUT_WR) || (how == SHUT_RDWR);
	push(con, (TcpEvent *) ev);
}

void tcp_listen(int fd, int return_value, int backlog) 
{
	/* Update con */
	TcpConnection *con = fd_con_map[fd];

	/* Create event */
	TcpEvListen *ev = (TcpEvListen *) new_event(TCP_EV_LISTEN,
			return_value!=-1, return_value);
	ev->backlog = backlog;
	push(con, (TcpEvent *) ev);
}
