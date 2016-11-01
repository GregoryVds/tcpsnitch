#include <jansson.h>
#include <netdb.h>
#include "tcp_spy_json.h"
#include "string_helpers.h"
#include "lib.h"
#include "logger.h"

///////////////////////////////////////////////////////////////////////////////

/*
  ___ _   _ _____ _____ ____  _   _    _    _          _    ____ ___
 |_ _| \ | |_   _| ____|  _ \| \ | |  / \  | |        / \  |  _ \_ _|
  | ||  \| | | | |  _| | |_) |  \| | / _ \ | |       / _ \ | |_) | |
  | || |\  | | | | |___|  _ <| |\  |/ ___ \| |___   / ___ \|  __/| |
 |___|_| \_| |_| |_____|_| \_\_| \_/_/   \_\_____| /_/   \_\_|  |___|

*/

/* Save reference to pointer with shorter name */
typedef int (*add_type)(json_t *o, const char *k, json_t *v);
static add_type add = &json_object_set_new;

static json_t *build_tcp_connection(TcpConnection *con);
static json_t *build_event(TcpEvent *ev);
static void build_shared_fields(json_t *json_ev, TcpEvent *ev);
static json_t *build_sock_opened_ev(TcpEvSockOpened *ev);
static json_t *build_sock_closed_ev(TcpEvSockClosed *ev);
static json_t *build_data_sent_ev(TcpEvDataSent *ev);
static json_t *build_data_received_ev(TcpEvDataReceived *ev);
static json_t *build_connect_ev(TcpEvConnect *ev);
static json_t *build_info_dump_ev(TcpEvInfoDump *ev);
static json_t *build_setsockopt_ev(TcpEvSetsockopt *ev);
static json_t *build_shutdown_ev(TcpEvShutdown *ev);
static json_t *build_listen_ev(TcpEvListen *ev);

#define EV_FAILURE "json_object() failed. Cannot build TCP event."
#define DETAILS_FAILURE "json_object() failed. Cannot build event details."
#define CON_FAILURE "json_object() failed. Cannot build TCP connection."
#define SHARED_FAILURE "json_object() failed. Cannot build shared fields."

#define BUILD_EV_PRELUDE()                            \
	json_t *json_ev = json_object();              \
	if (json_ev == NULL) {                        \
		LOG(ERROR, EV_FAILURE);               \
		return NULL;                          \
	}                                             \
	build_shared_fields(json_ev, (TcpEvent *)ev); \
	json_t *json_details = json_object();         \
	if (json_details == NULL) {                   \
		LOG(ERROR, DETAILS_FAILURE);          \
		return json_ev;                       \
	}                                             \
	add(json_ev, "details", json_details);

///////////////////////////////////////////////////////////////////////////////

static json_t *build_tcp_connection(TcpConnection *con) {
	json_t *json_con = json_object();
	json_t *events = json_array();
	if (json_con == NULL || events == NULL) {
		LOG(ERROR, CON_FAILURE);
		return NULL;
	}

	add(json_con, "app_name", json_string(con->app_name));
	add(json_con, "cmdline", json_string(con->cmdline));
	add(json_con, "dirname", json_string(con->dirname));
	add(json_con, "kernel", json_string(con->kernel));
	add(json_con, "timestamp", json_integer(con->timestamp));
	add(json_con, "id", json_integer(con->id));
	add(json_con, "eventsCount", json_integer(con->events_count));
	add(json_con, "bytesSent", json_integer(con->bytes_sent));
	add(json_con, "bytesReceived", json_integer(con->bytes_received));
	add(json_con, "gotPcapHandle",
	    json_boolean(con->capture_handle != NULL));
	add(json_con, "successfulPcap", json_boolean(con->successful_pcap));

	/* Loop through all events to build JSON */
	add(json_con, "events", events);
	json_t *json_event;
	TcpEventNode *cur = con->head;
	while (cur != NULL) {
		json_event = build_event(cur->data);
		json_array_append_new(events, json_event);
		cur = cur->next;
	}

	return json_con;
}

static json_t *build_event(TcpEvent *ev) {
	json_t *r;
	switch (ev->type) {
		case TCP_EV_SOCK_OPENED:
			r = build_sock_opened_ev((TcpEvSockOpened *)ev);
			break;
		case TCP_EV_SOCK_CLOSED:
			r = build_sock_closed_ev((TcpEvSockClosed *)ev);
			break;
		case TCP_EV_DATA_SENT:
			r = build_data_sent_ev((TcpEvDataSent *)ev);
			break;
		case TCP_EV_DATA_RECEIVED:
			r = build_data_received_ev((TcpEvDataReceived *)ev);
			break;
		case TCP_EV_CONNECT:
			r = build_connect_ev((TcpEvConnect *)ev);
			break;
		case TCP_EV_INFO_DUMP:
			r = build_info_dump_ev((TcpEvInfoDump *)ev);
			break;
		case TCP_EV_SETSOCKOPT:
			r = build_setsockopt_ev((TcpEvSetsockopt *)ev);
			break;
		case TCP_EV_SHUTDOWN:
			r = build_shutdown_ev((TcpEvShutdown *)ev);
			break;
		case TCP_EV_LISTEN:
			r = build_listen_ev((TcpEvListen *)ev);
			break;
	}
	return r;
}

static void build_shared_fields(json_t *json_ev, TcpEvent *ev) {
	const char *type_str = string_from_tcp_event_type(ev->type);
	add(json_ev, "eventType", json_string(type_str));

	/* Time stamp */
	json_t *timestamp_json = json_object();
	if (timestamp_json == NULL) {
		LOG(ERROR, SHARED_FAILURE);
	} else {
		add(timestamp_json, "sec", json_integer(ev->timestamp.tv_sec));
		add(timestamp_json, "usec",
		    json_integer(ev->timestamp.tv_usec));
	}
	add(json_ev, "timestamp", timestamp_json);

	/* Return value & err string */
	add(json_ev, "returnValue", json_integer(ev->return_value));
	add(json_ev, "success", json_boolean(ev->success));
	add(json_ev, "errorStr", json_string(ev->error_str));
}

///////////////////////////////////////////////////////////////////////////////

static json_t *build_sock_opened_ev(TcpEvSockOpened *ev) {
	BUILD_EV_PRELUDE()  // Expose local vars json_ev & json_details

	char *dom_str = alloc_sock_domain_str(ev->domain);
	char *type_str = alloc_sock_type_str(ev->type);

	add(json_details, "domain", json_string(dom_str));
	add(json_details, "type", json_string(type_str));
	add(json_details, "protocol", json_integer(ev->protocol));
	add(json_details, "sockCloexec", json_boolean(ev->sock_cloexec));
	add(json_details, "sockNonblock", json_boolean(ev->sock_nonblock));

	free(dom_str);
	free(type_str);

	return json_ev;
}

static json_t *build_sock_closed_ev(TcpEvSockClosed *ev) {
	BUILD_EV_PRELUDE()  // Expose local vars json_ev & json_details

	add(json_details, "detected", json_boolean(ev->detected));

	return json_ev;
}

static json_t *build_data_sent_ev(TcpEvDataSent *ev) {
	BUILD_EV_PRELUDE()  // Expose local vars json_ev & json_details

	add(json_details, "bytes", json_integer(ev->bytes));

	return json_ev;
}

static json_t *build_data_received_ev(TcpEvDataReceived *ev) {
	BUILD_EV_PRELUDE()  // Expose local vars json_ev & json_details

	add(json_details, "bytes", json_integer(ev->bytes));

	return json_ev;
}

static json_t *build_connect_ev(TcpEvConnect *ev) {
	BUILD_EV_PRELUDE()  // Expose local vars json_ev & json_details

	/* Extract IP address to human readable string */
	char *addr_str = alloc_host_str(&(ev->addr));
	char *port_str = alloc_port_str(&(ev->addr));

	add(json_details, "addr", json_string(addr_str));
	add(json_details, "port", json_string(port_str));

	free(addr_str);
	free(port_str);

	return json_ev;
}

static json_t *build_info_dump_ev(TcpEvInfoDump *ev) {
	BUILD_EV_PRELUDE()  // Expose local vars json_ev & json_details

	struct tcp_info i = ev->info;

	add(json_details, "state", json_integer(i.tcpi_state));
	add(json_details, "ca_state", json_integer(i.tcpi_ca_state));
	add(json_details, "retransmits", json_integer(i.tcpi_retransmits));
	add(json_details, "probes", json_integer(i.tcpi_probes));
	add(json_details, "backoff", json_integer(i.tcpi_backoff));
	add(json_details, "options", json_integer(i.tcpi_options));
	add(json_details, "snd_wscale", json_integer(i.tcpi_snd_wscale));
	add(json_details, "rcv_wscale", json_integer(i.tcpi_rcv_wscale));

	add(json_details, "rto", json_integer(i.tcpi_rto));
	add(json_details, "ato", json_integer(i.tcpi_ato));
	add(json_details, "snd_mss", json_integer(i.tcpi_snd_mss));
	add(json_details, "rcv_mss", json_integer(i.tcpi_rcv_mss));

	add(json_details, "unacked", json_integer(i.tcpi_unacked));
	add(json_details, "sacked", json_integer(i.tcpi_sacked));
	add(json_details, "lost", json_integer(i.tcpi_lost));
	add(json_details, "retrans", json_integer(i.tcpi_retrans));
	add(json_details, "fackets", json_integer(i.tcpi_fackets));

	/* Times */
	add(json_details, "last_data_sent",
	    json_integer(i.tcpi_last_data_sent));
	add(json_details, "last_ack_sent", json_integer(i.tcpi_last_ack_sent));
	add(json_details, "last_data_recv",
	    json_integer(i.tcpi_last_data_recv));
	add(json_details, "last_ack_recv", json_integer(i.tcpi_last_ack_recv));

	/* Metrics */
	add(json_details, "pmtu", json_integer(i.tcpi_pmtu));
	add(json_details, "rcv_ssthresh", json_integer(i.tcpi_rcv_ssthresh));
	add(json_details, "rtt", json_integer(i.tcpi_rtt));
	add(json_details, "rttvar", json_integer(i.tcpi_rttvar));
	add(json_details, "snd_ssthresh", json_integer(i.tcpi_snd_ssthresh));
	add(json_details, "snd_cwnd", json_integer(i.tcpi_snd_cwnd));
	add(json_details, "advmss", json_integer(i.tcpi_advmss));
	add(json_details, "reordering", json_integer(i.tcpi_reordering));

	add(json_details, "rcv_rtt", json_integer(i.tcpi_rcv_rtt));
	add(json_details, "rcv_space", json_integer(i.tcpi_rcv_space));

	add(json_details, "total_retrans", json_integer(i.tcpi_total_retrans));

	return json_ev;
}

static json_t *build_setsockopt_ev(TcpEvSetsockopt *ev) {
	BUILD_EV_PRELUDE()  // Expose local vars json_ev & json_details

	struct protoent *protocol = getprotobynumber(ev->level);
	char *optname_str = alloc_sock_optname_str(ev->optname);

	add(json_details, "level", json_string(protocol->p_name));
	add(json_details, "optname", json_string(optname_str));

	free(optname_str);

	return json_ev;
}

static json_t *build_shutdown_ev(TcpEvShutdown *ev) {
	BUILD_EV_PRELUDE()  // Expose local vars json_ev & json_details

	add(json_details, "shut_rd", json_boolean(ev->shut_rd));
	add(json_details, "shut_wr", json_boolean(ev->shut_wr));

	return json_ev;
}

static json_t *build_listen_ev(TcpEvListen *ev) {
	BUILD_EV_PRELUDE()  // Expose local vars json_ev & json_details

	add(json_details, "backlog", json_integer(ev->backlog));

	return json_ev;
}

///////////////////////////////////////////////////////////////////////////////

/*
  ____  _   _ ____  _     ___ ____      _    ____ ___
 |  _ \| | | | __ )| |   |_ _/ ___|    / \  |  _ \_ _|
 | |_) | | | |  _ \| |    | | |       / _ \ | |_) | |
 |  __/| |_| | |_) | |___ | | |___   / ___ \|  __/| |
 |_|    \___/|____/|_____|___\____| /_/   \_\_|  |___|
*/

char *build_tcp_connection_json(TcpConnection *con) {
	json_t *json_con = build_tcp_connection(con);
	if (json_con == NULL) {
		LOG(ERROR,
		    "build_tcp_connection() failed. Could not generate JSON "
		    "representation for TCP connection");
		return NULL;
	}

	char *json_string = json_dumps(json_con, 0);
	json_decref(json_con);
	return json_string;
}

///////////////////////////////////////////////////////////////////////////////
