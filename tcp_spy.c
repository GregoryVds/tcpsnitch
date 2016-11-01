#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include <pcap/pcap.h>
#include "tcp_spy.h"
#include "lib.h"
#include "tcp_spy_json.h"
#include "packet_sniffer.h"
#include "config.h"
#include "string_helpers.h"
#include "logger.h"

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
static long tcp_info_bytes_ival =
    -1;  // Set to -1 when not parsed. 0 if ommited.
static long tcp_info_time_ival =
    -1;  // Set to -1 when not parsed. 0 if ommited.

/* CREATING & FREEING OBJECTS */

static TcpConnection *alloc_connection();
static TcpEvent *alloc_event(TcpEventType type, int return_value, int err);
static void free_connection(TcpConnection *con);
static void free_events_list(TcpEventNode *head);
static void free_event(TcpEvent *ev);
static void push_event(TcpConnection *con, TcpEvent *ev);

/* HELPERS */

static TcpConnection *get_tcp_connection(int fd);
static long get_tcpinfo_ival(const char *env_var);
static void extract_tcpinfo_ivals();
static bool should_dump_tcp_info(TcpConnection *con);

///////////////////////////////////////////////////////////////////////////////

static TcpConnection *alloc_connection() {
	TcpConnection *con = (TcpConnection *)calloc(sizeof(TcpConnection), 1);
	if (con == NULL) {
		LOG(ERROR, "calloc() failed. Cannot alloc TcpConnection.");
		return NULL;
	}

	con->id = connections_count;
	con->cmdline = alloc_cmdline_str(&(con->app_name));
	con->timestamp = get_time_sec();
	con->dirname = alloc_dirname_str(con->app_name);
	con->kernel = alloc_kernel_str();
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
		case TCP_EV_DATA_SENT:
			success = (return_value != -1);
			ev = (TcpEvent *)malloc(sizeof(TcpEvDataSent));
			break;
		case TCP_EV_DATA_RECEIVED:
			success = (return_value != -1);
			ev = (TcpEvent *)malloc(sizeof(TcpEvDataReceived));
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
	free(con->dirname);
	free(con->kernel);
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
		LOG(ERROR, "Cannot find matching TcpConnection for fd %d.",
		      fd);
	}
	return con;
}

/* Retrieve interval for tcpinfo (could be byte ou time interval).
 * If not set or in incorrect format, we assume 0 and thus no lower bound. */
static long get_tcpinfo_ival(const char *env_var) {
	long t = get_long_env(env_var);
	if (t == -1) LOG(WARN, "No interval set with %s.", env_var);
	if (t == -2) LOG(ERROR, "Invalid interval set with %s.", env_var);
	if (t == -3) LOG(ERROR, "Interval set with %s overflows.", env_var);
	// On error, we use a default value of 0.
	if (t < 0) {
		LOG(WARN,
		      "Interval %s assumed to be 0. No lower bound "
		      "set on tcp_info capture frequency.",
		      env_var);
	}
	return (t < 0) ? 0 : t;
}

static void extract_tcpinfo_ivals() {
	tcp_info_bytes_ival = get_tcpinfo_ival(ENV_NETSPY_TCPINFO_BYTES_IVAL);
	LOG(WARN, "tcp_info min bytes interval set to %lu.",
	      tcp_info_bytes_ival);
	tcp_info_time_ival = get_tcpinfo_ival(ENV_NETSPY_TCPINFO_MICROS_IVAL);
	LOG(WARN, "tcp_info min microseconds interval set to %lu.",
	      tcp_info_time_ival);
}

static bool should_dump_tcp_info(TcpConnection *con) {
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
		long cur_bytes = con->bytes_sent + con->bytes_received;
		long bytes_elapsed = cur_bytes - con->last_info_dump_bytes;
		if (bytes_elapsed < tcp_info_bytes_ival) return false;
	}

	/* If we reach this point, no lower bound prevents from dumping */
	return true;
}

///////////////////////////////////////////////////////////////////////////////

/*
  ____  _   _ ____  _     ___ ____      _    ____ ___
 |  _ \| | | | __ )| |   |_ _/ ___|    / \  |  _ \_ _|
 | |_) | | | |  _ \| |    | | |       / _ \ | |_) | |
 |  __/| |_| | |_) | |___ | | |___   / ___ \|  __/| |
 |_|    \___/|____/|_____|___\____| /_/   \_\_|  |___|

*/

void tcp_start_capture(int fd, const struct sockaddr *addr) {
	TcpConnection *con = get_tcp_connection(fd);
	char *file_path = alloc_pcap_path_str();
	char *filter = build_capture_filter(addr);

	if (con == NULL || file_path == NULL || filter == NULL) {
		LOG(ERROR, "Abort packet capture. NULL variable.");
		return;
	}

	con->capture_handle =
	    start_capture(filter, file_path, &(con->capture_thread));

	free(filter);
	free(file_path);
}

void tcp_stop_capture(TcpConnection *con) {
	int rc = stop_capture(con->capture_handle, &(con->capture_thread));
	con->successful_pcap = (rc == -2);

	char *json = build_tcp_connection_json(con);
	char *file_path = alloc_json_path_str();
	if (json == NULL || file_path == NULL) {
		LOG(ERROR, "Cannot save capture to file.");
		return;
	}

	int ret = append_string_to_file((const char *)json, file_path);
	if (ret != 0) {
		LOG(ERROR, "Error when dumping TcpConnection JSON to file.");
	}

	free(file_path);
}

///////////////////////////////////////////////////////////////////////////////

#define FAIL_IF_NULL(var, ev_type_cons)                                       \
	if (var == NULL) {                                                    \
		const char *str = string_from_tcp_event_type(ev_type_cons);   \
		LOG(ERROR, "Event %s dropped for fd %d. Variable was NULL", \
		      str, fd);                                               \
		return;                                                       \
	}

#define TCP_EV_PRELUDE(ev_type_cons, ev_type)                                  \
	TcpConnection *con = get_tcp_connection(fd);                           \
	FAIL_IF_NULL(con, ev_type_cons);                                       \
	ev_type *ev = (ev_type *)alloc_event(ev_type_cons, return_value, err); \
	FAIL_IF_NULL(ev, ev_type_cons);

const char *string_from_tcp_event_type(TcpEventType type) {
	static const char *strings[] = {
	    "TCP_EV_SOCK_OPENED",   "TCP_EV_SOCK_CLOSED", "TCP_EV_DATA_SENT",
	    "TCP_EV_DATA_RECEIVED", "TCP_EV_CONNECT",     "TCP_EV_INFO_DUMP",
	    "TCP_EV_SETSOCKOPT",    "TCP_EV_SHUTDOWN",    "TCP_EV_LISTEN",
	    "TCP_EV_PRECONNECT"};
	return strings[type];
}

///////////////////////////////////////////////////////////////////////////////

void tcp_sock_opened(int fd, int domain, int protocol, bool sock_cloexec,
		     bool sock_nonblock) {
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
	ev->type = SOCK_STREAM;
	ev->protocol = protocol;
	ev->sock_cloexec = sock_cloexec;
	ev->sock_nonblock = sock_nonblock;
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
	// Instantiate local vars TcpConnection *con & TcpEvSockClosed *ev
	TCP_EV_PRELUDE(TCP_EV_SOCK_CLOSED, TcpEvSockClosed);

	ev->detected = detected;
	push_event(con, (TcpEvent *)ev);

	if (con->capture_handle != NULL) tcp_stop_capture(con);

	/* Cleanup */
	free_connection(con);
	fd_con_map[fd] = NULL;
}

void tcp_data_sent(int fd, int return_value, int err, size_t bytes) {
	// Instantiate local vars TcpConnection *con & TcpEvDataSent *ev
	TCP_EV_PRELUDE(TCP_EV_DATA_SENT, TcpEvDataSent);

	con->bytes_sent += bytes;
	ev->bytes = bytes;

	push_event(con, (TcpEvent *)ev);
}

void tcp_data_received(int fd, int return_value, int err, size_t bytes) {
	// Instantiate local vars TcpConnection *con & TcpEvDataReceived *ev
	TCP_EV_PRELUDE(TCP_EV_DATA_RECEIVED, TcpEvDataReceived);

	con->bytes_received += bytes;
	ev->bytes = bytes;

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
	// Instantiate local vars TcpConnection *con & TcpEvSetsockopt *ev
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
