#define _GNU_SOURCE

#include "tcp_spy.h"
#include <dirent.h>
#include <errno.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include "config.h"
#include "lib.h"
#include "logger.h"
#include "packet_sniffer.h"
#include "string_helpers.h"
#include "tcp_spy_json.h"
#include "init.h"

///////////////////////////////////////////////////////////////////////////////

/*
  ___ _   _ _____ _____ ____  _   _    _    _          _    ____ ___
 |_ _| \ | |_   _| ____|  _ \| \ | |  / \  | |        / \  |  _ \_ _|
  | ||  \| | | | |  _| | |_) |  \| | / _ \ | |       / _ \ | |_) | |
  | || |\  | | | | |___|  _ <| |\  |/ ___ \| |___   / ___ \|  __/| |
 |___|_| \_| |_| |_____|_| \_\_| \_/_/   \_\_____| /_/   \_\_|  |___|

*/

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
 * or binary tree.
 */

#define MAX_FD 1024
static TcpConnection *fd_con_map[MAX_FD];
static int connections_count = 0;
///////////////////////////////////////////////////////////////////////////////

/* CREATING & FREEING OBJECTS */
static char *create_logs_dir(TcpConnection *con);
static TcpConnection *alloc_connection(void);
static TcpEvent *alloc_event(TcpEventType type, int return_value, int err);
static void free_connection(TcpConnection *con);
static void free_events_list(TcpEventNode *head);
static void free_event(TcpEvent *ev);
static void push_event(TcpConnection *con, TcpEvent *ev);

/* HELPERS */
static TcpConnection *get_tcp_connection(int fd);
static bool should_dump_tcp_info(TcpConnection *con);
static void fill_send_flags(TcpSendFlags *s, int flags);
static void fill_recv_flags(TcpRecvFlags *s, int flags);

void tcp_dump_json(TcpConnection *con);

///////////////////////////////////////////////////////////////////////////////

char *create_logs_dir(TcpConnection *con) {
	// Log dir is [LOG_DIR]/[ID]
	int n = get_int_len(con->id)+1;
	char dirname[n];
	snprintf(dirname, n, "%d", con->id);

	char *dir_path = alloc_concat_path(log_path, dirname);
	if (dir_path == NULL) {
		LOG(ERROR, "alloc_concat_path() failed.");
		return NULL;
	}

	int ret = mkdir(dir_path, 0700);
	if (ret == -1) {
		LOG(ERROR, "mkdir() failed. %s.", strerror(errno));
		return NULL;
	}

	return dir_path;
}

static TcpConnection *alloc_connection(void) {
	TcpConnection *con = (TcpConnection *)calloc(sizeof(TcpConnection), 1);
	if (con == NULL) {
		LOG(ERROR, "calloc() failed. Cannot alloc TcpConnection.");
		return NULL;
	}

	con->id = connections_count;
	con->cmdline = alloc_cmdline_str(&(con->app_name));
	con->timestamp = get_time_sec();
	con->kernel = alloc_kernel_str();
	con->directory = create_logs_dir(con);

	connections_count++;
	return con;
}

static TcpEvent *alloc_event(TcpEventType type, int return_value, int err) {
	bool success;
	TcpEvent *ev;
	switch (type) {
		case TCP_EV_SOCK_OPENED:
			ev = (TcpEvent *)malloc(sizeof(TcpEvSockOpened));
			success = (return_value != 0);
			break;
		case TCP_EV_SOCK_CLOSED:
			success = (return_value == 0);
			ev = (TcpEvent *)malloc(sizeof(TcpEvSockClosed));
			break;
		case TCP_EV_SEND:
			success = (return_value != -1);
			ev = (TcpEvent *)malloc(sizeof(TcpEvSend));
			break;
		case TCP_EV_SENDTO:
			success = (return_value != -1);
			ev = (TcpEvent *)malloc(sizeof(TcpEvSendto));
			break;
		case TCP_EV_RECV:
			success = (return_value != -1);
			ev = (TcpEvent *)malloc(sizeof(TcpEvRecv));
			break;
		case TCP_EV_RECVFROM:
			success = (return_value != -1);
			ev = (TcpEvent *)malloc(sizeof(TcpEvRecvfrom));
			break;
		case TCP_EV_CONNECT:
			success = (return_value != -1);
			ev = (TcpEvent *)malloc(sizeof(TcpEvConnect));
			break;
		case TCP_EV_INFO_DUMP:
			success = (return_value != -1);
			ev = (TcpEvent *)malloc(sizeof(TcpEvInfoDump));
			break;
		case TCP_EV_SETSOCKOPT:
			success = (return_value != -1);
			ev = (TcpEvent *)malloc(sizeof(TcpEvSetsockopt));
			break;
		case TCP_EV_SHUTDOWN:
			success = (return_value != -1);
			ev = (TcpEvent *)malloc(sizeof(TcpEvShutdown));
			break;
		case TCP_EV_LISTEN:
			success = (return_value != -1);
			ev = (TcpEvent *)malloc(sizeof(TcpEvListen));
			break;
		case TCP_EV_BIND:
			success = (return_value != -1);
			ev = (TcpEvent *)malloc(sizeof(TcpEvBind));
			break;
	}

	if (ev == NULL) {
		LOG(ERROR, "malloc() failed. Cannot allocate TcpEvent.");
		return NULL;
	}

	fill_timeval(&(ev->timestamp));
	ev->type = type;
	ev->return_value = return_value;
	ev->success = success;
	ev->error_str = success ? NULL : alloc_error_str(err);
	return ev;
}

static void free_connection(TcpConnection *con) {
	free_events_list(con->head);
	free(con->app_name);
	free(con->cmdline);
	free(con->kernel);
	free(con->directory);
	free(con);
}

static void free_events_list(TcpEventNode *head) {
	TcpEventNode *tmp;
	while (head != NULL) {
		free_event(head->data);
		tmp = head;
		head = head->next;
		free(tmp);
	}
}

static void free_event(TcpEvent *ev) {
	free(ev->error_str);
	free(ev);
}

static void push_event(TcpConnection *con, TcpEvent *ev) {
	TcpEventNode *node = (TcpEventNode *)malloc(sizeof(TcpEventNode));
	if (node == NULL) {
		LOG(ERROR, "malloc() failed. Cannot allocate TcpEventNode.");
		return;
	}

	node->data = ev;
	node->next = NULL;
	if (!con->head)
		con->head = node;
	else
		con->tail->next = node;

	con->tail = node;
	con->events_count++;
}

//////////////////////////////////////////////////////////////////////////////

static TcpConnection *get_tcp_connection(int fd) {
	TcpConnection *con = fd_con_map[fd];
	if (con == NULL) {
		LOG(ERROR, "Cannot find matching TcpConnection for fd %d.", fd);
	}
	return con;
}

static bool should_dump_tcp_info(TcpConnection *con) {
	/* Check if time lower bound is set, otherwise assume no lower bound */
	if (tcp_info_time_ival > 0) {
		long cur_time = get_time_micros();
		long time_elasped = cur_time - con->last_info_dump_micros;
		if (time_elasped < tcp_info_time_ival) return false;
	}

	/* Check if bytes lower bound set, otherwise assume no lower bound */
	if (tcp_info_bytes_ival > 0) {
		long cur_bytes = con->bytes_sent + con->bytes_received;
		long bytes_elapsed = cur_bytes - con->last_info_dump_bytes;
		if (bytes_elapsed < tcp_info_bytes_ival) return false;
	}

	/* If we reach this point, no lower bound prevents from dumping */
	return true;
}

///////////////////////////////////////////////////////////////////////////////

static void fill_send_flags(TcpSendFlags *s, int flags) {
	if (flags & MSG_CONFIRM) s->msg_confirm = true;
	if (flags & MSG_DONTROUTE) s->msg_dontroute = true;
	if (flags & MSG_DONTWAIT) s->msg_dontwait = true;
	if (flags & MSG_EOR) s->msg_eor = true;
	if (flags & MSG_MORE) s->msg_more = true;
	if (flags & MSG_NOSIGNAL) s->msg_nosignal = true;
	if (flags & MSG_OOB) s->msg_oob = true;
}

static void fill_recv_flags(TcpRecvFlags *s, int flags) {
	if (flags & MSG_CMSG_CLOEXEC) s->msg_cmsg_cloexec = true;
	if (flags & MSG_DONTWAIT) s->msg_dontwait = true;
	if (flags & MSG_ERRQUEUE) s->msg_errqueue = true;
	if (flags & MSG_OOB) s->msg_oob = true;
	if (flags & MSG_PEEK) s->msg_peek = true;
	if (flags & MSG_TRUNC) s->msg_trunc = true;
	if (flags & MSG_WAITALL) s->msg_waitall = true;
}

///////////////////////////////////////////////////////////////////////////////

void tcp_dump_json(TcpConnection *con) {
	if (con->directory == NULL) {
		LOG(ERROR, "Cannot dump JSON to file. Con directory is NULL.");
		return;
	}

	char *json = build_tcp_connection_json(con);
	char *json_file = alloc_json_path_str(con);
	if (json == NULL || json_file == NULL) {
		LOG(ERROR, "Cannot save capture to file.");
		return;
	}

	int ret = append_string_to_file((const char *)json, json_file);
	if (ret != 0) {
		LOG(ERROR, "Error when dumping TcpConnection JSON to file.");
	}

	free(json_file);
}

///////////////////////////////////////////////////////////////////////////////

/*
  ____  _   _ ____  _     ___ ____      _    ____ ___
 |  _ \| | | | __ )| |   |_ _/ ___|    / \  |  _ \_ _|
 | |_) | | | |  _ \| |    | | |       / _ \ | |_) | |
 |  __/| |_| | |_) | |___ | | |___   / ___ \|  __/| |
 |_|    \___/|____/|_____|___\____| /_/   \_\_|  |___|

*/
///////////////////////////////////////////////////////////////////////////////

void tcp_start_packet_capture(int fd, const struct sockaddr *addr) {
	TcpConnection *con = get_tcp_connection(fd);
	if (con == NULL) {
		LOG(ERROR,
		    "Abort packet capture. Cannot find related connection.");
		return;
	}

	if (con->directory == NULL) {
		LOG(ERROR,
		    "Abort packet capture. A directory was not created"
		    " for the TCP connection.");
		return;
	}

	char *pcap_file = alloc_pcap_path_str(con);
	char *filter = build_capture_filter(addr);
	if (pcap_file == NULL || filter == NULL) {
		LOG(ERROR, "Abort packet capture. NULL variable.");
		return;
	}

	con->capture_handle =
	    start_capture(filter, pcap_file, &(con->capture_thread));

	free(filter);
	free(pcap_file);
}

void tcp_stop_packet_capture(TcpConnection *con) {
	int rc = stop_capture(con->capture_handle, &(con->capture_thread));
	con->successful_pcap = (rc == -2);
}

///////////////////////////////////////////////////////////////////////////////

#define FAIL_IF_NULL(var, ev_type_cons)                                     \
	if (var == NULL) {                                                  \
		const char *str = string_from_tcp_event_type(ev_type_cons); \
		LOG(ERROR, "Event %s dropped for fd %d. Variable was NULL", \
		    str, fd);                                               \
		return;                                                     \
	}

#define TCP_EV_PRELUDE(ev_type_cons, ev_type)                                  \
	TcpConnection *con = get_tcp_connection(fd);                           \
	FAIL_IF_NULL(con, ev_type_cons);                                       \
	ev_type *ev = (ev_type *)alloc_event(ev_type_cons, return_value, err); \
	FAIL_IF_NULL(ev, ev_type_cons);

const char *string_from_tcp_event_type(TcpEventType type) {
	static const char *strings[] = {
	    "TCP_EV_SOCK_OPENED", "TCP_EV_SOCK_CLOSED", "TCP_EV_SEND",
	    "TCP_EV_SENDTO",      "TCP_EV_RECV",	"TCP_EV_RECVFROM",
	    "TCP_EV_CONNECT",     "TCP_EV_INFO_DUMP",   "TCP_EV_SETSOCKOPT",
	    "TCP_EV_SHUTDOWN",    "TCP_EV_LISTEN",      "TCP_EV_BIND"};
	return strings[type];
}

///////////////////////////////////////////////////////////////////////////////

#define SOCK_TYPE_MASK 0b1111
void tcp_sock_opened(int fd, int domain, int type, int protocol) {
	/* Check if connection was not properly closed. */
	if (fd_con_map[fd]) tcp_sock_closed(fd, 0, 0, false);

	/* Create new connection */
	TcpConnection *con = alloc_connection();
	FAIL_IF_NULL(con, TCP_EV_SOCK_OPENED);
	fd_con_map[fd] = con;

	/* Create event */
	TcpEvSockOpened *ev =
	    (TcpEvSockOpened *)alloc_event(TCP_EV_SOCK_OPENED, fd, 0);
	FAIL_IF_NULL(ev, TCP_EV_SOCK_OPENED);

	ev->domain = domain;
	ev->type = type & SOCK_TYPE_MASK;
	ev->protocol = protocol;
	ev->sock_cloexec = type & SOCK_CLOEXEC;
	ev->sock_nonblock = type & SOCK_NONBLOCK;
	push_event(con, (TcpEvent *)ev);
}

void tcp_info_dump(int fd) {
	/* Get TcpConnection */
	TcpConnection *con = get_tcp_connection(fd);
	FAIL_IF_NULL(con, TCP_EV_INFO_DUMP);

	/* Check if should dump based on byte/time lower bounds */
	if (!should_dump_tcp_info(con)) return;
	LOG(INFO, "Dumping tcp_info.");

	/* Get TCP_INFO */
	struct tcp_info info;
	int ret = fill_tcpinfo(fd, &info);
	int err = errno;

	/* Create event */
	TcpEvInfoDump *ev =
	    (TcpEvInfoDump *)alloc_event(TCP_EV_INFO_DUMP, ret, err);
	FAIL_IF_NULL(ev, TCP_EV_INFO_DUMP);

	/* Register time/bytes of last dump */
	memcpy(&(ev->info), &info, sizeof(info));
	con->last_info_dump_bytes = con->bytes_sent + con->bytes_received;
	con->last_info_dump_micros = get_time_micros();

	push_event(con, (TcpEvent *)ev);
}

void tcp_sock_closed(int fd, int return_value, int err, bool detected) {
	// Instantiate local vars TcpConnection *con & TcpEvSockClosed
	// *ev
	TCP_EV_PRELUDE(TCP_EV_SOCK_CLOSED, TcpEvSockClosed);

	ev->detected = detected;
	push_event(con, (TcpEvent *)ev);

	if (con->capture_handle != NULL) tcp_stop_packet_capture(con);
	if (con->directory != NULL) tcp_dump_json(con);

	/* Cleanup */
	free_connection(con);
	fd_con_map[fd] = NULL;
}

void tcp_send(int fd, int return_value, int err, size_t bytes, int flags) {
	// Instantiate local vars TcpConnection *con & TcpEvSend *ev
	TCP_EV_PRELUDE(TCP_EV_SEND, TcpEvSend);

	con->bytes_sent += bytes;
	ev->bytes = bytes;
	fill_send_flags(&(ev->flags), flags);
	push_event(con, (TcpEvent *)ev);
}

void tcp_sendto(int fd, int return_value, int err, size_t bytes, int flags,
		const struct sockaddr *addr, socklen_t len) {
	// Instantiate local vars TcpConnection *con & TcpEvSendto *ev
	TCP_EV_PRELUDE(TCP_EV_SENDTO, TcpEvSendto);

	con->bytes_sent += bytes;
	ev->bytes = bytes;
	fill_send_flags(&(ev->flags), flags);
	memcpy(&(ev->addr), addr, len);

	push_event(con, (TcpEvent *)ev);
}

void tcp_recv(int fd, int return_value, int err, size_t bytes, int flags) {
	// Instantiate local vars TcpConnection *con & TcpEvRecv *ev
	TCP_EV_PRELUDE(TCP_EV_RECV, TcpEvRecv);

	con->bytes_received += bytes;
	ev->bytes = bytes;
	fill_recv_flags(&(ev->flags), flags);

	push_event(con, (TcpEvent *)ev);
}

void tcp_recvfrom(int fd, int return_value, int err, size_t bytes, int flags,
		  const struct sockaddr *addr, socklen_t len) {
	// Instantiate local vars TcpConnection *con & TcpEvRecvfrom *ev
	TCP_EV_PRELUDE(TCP_EV_RECVFROM, TcpEvRecvfrom);

	con->bytes_received += bytes;
	ev->bytes = bytes;
	fill_recv_flags(&(ev->flags), flags);
	memcpy(&(ev->addr), addr, len);

	push_event(con, (TcpEvent *)ev);
}

void tcp_connect(int fd, int return_value, int err, const struct sockaddr *addr,
		 socklen_t len) {
	// Instantiate local vars TcpConnection *con & TcpEvConnect *ev
	TCP_EV_PRELUDE(TCP_EV_CONNECT, TcpEvConnect);

	memcpy(&(ev->addr), addr, len);

	push_event(con, (TcpEvent *)ev);
}
void tcp_setsockopt(int fd, int return_value, int err, int level, int optname) {
	// Instantiate local vars TcpConnection *con & TcpEvSetsockopt
	// *ev
	TCP_EV_PRELUDE(TCP_EV_SETSOCKOPT, TcpEvSetsockopt);

	ev->level = level;
	ev->optname = optname;

	push_event(con, (TcpEvent *)ev);
}

void tcp_shutdown(int fd, int return_value, int err, int how) {
	// Instantiate local vars TcpConnection *con & TcpEvShutdown *ev
	TCP_EV_PRELUDE(TCP_EV_SHUTDOWN, TcpEvShutdown);

	ev->shut_rd = (how == SHUT_RD) || (how == SHUT_RDWR);
	ev->shut_wr = (how == SHUT_WR) || (how == SHUT_RDWR);

	push_event(con, (TcpEvent *)ev);
}

void tcp_listen(int fd, int return_value, int err, int backlog) {
	// Instantiate local vars TcpConnection *con & TcpEvListen *ev
	TCP_EV_PRELUDE(TCP_EV_LISTEN, TcpEvListen);

	ev->backlog = backlog;

	push_event(con, (TcpEvent *)ev);
}

void tcp_bind(int fd, int return_value, int err, const struct sockaddr *addr,
	      socklen_t len) {
	// Instantiate local vars TcpConnection *con & TcpEvBind *ev
	TCP_EV_PRELUDE(TCP_EV_BIND, TcpEvBind);

	memcpy(&(ev->addr), addr, len);	
	con->bind_ev = ev; 

	push_event(con, (TcpEvent *)ev);
}


