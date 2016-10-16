#include <jansson.h>
#include <netdb.h>
#include "tcp_json_builder.h"
#include "strings.h"
#include "lib.h"

json_t *build_tcp_connection(TcpConnection *con);
json_t *build_event(TcpEvent *ev);
json_t *build_sock_opened_ev(TcpEvSockOpened *ev);
json_t *build_sock_closed_ev(TcpEvSockClosed *ev);
json_t *build_data_sent_ev(TcpEvDataSent *ev);
json_t *build_data_received_ev(TcpEvDataReceived *ev);
json_t *build_connect_ev(TcpEvConnect *ev);
json_t *build_info_dump_ev(TcpEvInfoDump *ev);
json_t *build_setsockopt_ev(TcpEvSetsockopt *ev);

char *build_tcp_connection_json(TcpConnection *con) 
{
	json_t *json_con = build_tcp_connection(con);
	char *json_string = json_dumps(json_con, 0);
	json_decref(json_con);
	return json_string;
}

json_t *build_tcp_connection(TcpConnection *con) 
{
	json_t *json_con = json_object();
	json_t *events = json_array();
	json_object_set_new(json_con, "id", json_integer(con->id));
	json_object_set_new(json_con, "eventsCount", json_integer(con->events_count));
	json_object_set_new(json_con, "bytesSent", json_integer(con->bytes_sent));
	json_object_set_new(json_con, "bytesReceived", json_integer(con->bytes_received));
	json_object_set_new(json_con, "events",	events);

	json_t *json_event;
	TcpEventNode *cur = con->head;
	while (cur != NULL) {
		json_event = build_event(cur->data);	
		json_array_append_new(events, json_event);
		cur = cur->next;
	}

	return json_con;
}

json_t *build_event(TcpEvent *ev)
{	
	switch(ev->type) {
		case SOCK_OPENED:   
			return build_sock_opened_ev((TcpEvSockOpened *) ev);
		case SOCK_CLOSED:   
			return build_sock_closed_ev((TcpEvSockClosed *) ev);
		case DATA_SENT:     
			return build_data_sent_ev((TcpEvDataSent *) ev);
		case DATA_RECEIVED: 
			return build_data_received_ev((TcpEvDataReceived *)ev);
		case CONNECT:	    
			return build_connect_ev((TcpEvConnect *) ev);
		case INFO_DUMP:     
			return build_info_dump_ev((TcpEvInfoDump *) ev);
		case SETSOCKOPT:
			return build_setsockopt_ev((TcpEvSetsockopt *) ev);
		default:
			DEBUG(ERROR, "build_event() failed. Unrecognized event"
					" type %d.", ev->type);
			exit(EXIT_FAILURE);
	}
}

void build_shared_fields(json_t *json_ev, TcpEvent *ev)
{
	const char *type_str = string_from_tcp_event_type(ev->type);
	json_object_set_new(json_ev, "eventType", json_string(type_str));

	/* Time stamp */	
	json_t *timestamp_json = json_object();
	json_object_set_new(timestamp_json, "sec",
			json_integer(ev->timestamp.tv_sec));
	json_object_set_new(timestamp_json, "usec",
			json_integer(ev->timestamp.tv_usec));
	json_object_set_new(json_ev, "timestamp", timestamp_json);
	
	/* Return value & err string */ 
	json_object_set_new(json_ev, "returnValue", json_integer(ev->return_value));
	json_object_set_new(json_ev, "success", json_boolean(ev->success));
	json_object_set_new(json_ev, "errorStr", json_string(ev->error_str));
}

json_t *build_sock_opened_ev(TcpEvSockOpened *ev)
{
	json_t *json_ev = json_object();
	build_shared_fields(json_ev, (TcpEvent *) ev);

	/* Translate socket domain */
	int domain_buf_size=MEMBER_SIZE(IntStrPair, str);
	char domain_buf[domain_buf_size];
	if (!string_from_cons(ev->domain, domain_buf, domain_buf_size,
		SOCKET_DOMAINS, sizeof(SOCKET_DOMAINS)/sizeof(IntStrPair))) {
		DEBUG(WARN, "Unknown translation socket domain: %d", ev->domain);
		snprintf(domain_buf, domain_buf_size, "%d", ev->domain);
	} 

	/* Translates socket type */
	int type_buf_size=MEMBER_SIZE(IntStrPair, str);
	char type_buf[type_buf_size];
	if (!string_from_cons(ev->type, type_buf, type_buf_size,
		SOCKET_TYPES, sizeof(SOCKET_TYPES)/sizeof(IntStrPair))) {
		DEBUG(WARN, "Unknown translation socket type: %d", ev->type);	
		snprintf(type_buf, type_buf_size, "%d", ev->type);
	}

	json_t *json_details = json_object();
	json_object_set_new(json_details, "domain", 
			json_string(domain_buf));
	json_object_set_new(json_details, "type", 
			json_string(type_buf));
	json_object_set_new(json_details, "protocol", 
			json_integer(ev->protocol));
	json_object_set_new(json_details, "sockCloexec",
			json_boolean(ev->sock_cloexec));
	json_object_set_new(json_details, "sockNonblock", 
			json_boolean(ev->sock_nonblock));
	json_object_set_new(json_ev, "details", json_details);
	
	return json_ev;
}

json_t *build_sock_closed_ev(TcpEvSockClosed *ev)
{
	json_t *json_ev = json_object();
	build_shared_fields(json_ev, (TcpEvent *) ev);

	json_t *json_details = json_object();
	json_object_set_new(json_details, "detected", json_boolean(ev->detected));
	json_object_set_new(json_ev, "details", json_details);
	return json_ev;
}

json_t *build_data_sent_ev(TcpEvDataSent *ev)
{
	json_t *json_ev = json_object();
	build_shared_fields(json_ev, (TcpEvent *) ev);

	json_t *json_details = json_object();
	json_object_set_new(json_details, "bytes", json_integer(ev->bytes));
	json_object_set_new(json_ev, "details", json_details);

	return json_ev;
}

json_t *build_data_received_ev(TcpEvDataReceived *ev)
{
	json_t *json_ev = json_object();
	build_shared_fields(json_ev, (TcpEvent *) ev);

	json_t *json_details = json_object();
	json_object_set_new(json_details, "bytes", json_integer(ev->bytes));
	json_object_set_new(json_ev, "details", json_details);

	return json_ev;
}

json_t *build_connect_ev(TcpEvConnect *ev)
{
	json_t *json_ev = json_object();
	build_shared_fields(json_ev, (TcpEvent *) ev);

	/* Extract IP address to human readable string */
	char addr_buf[50];
	addr_string_from_sockaddr(&(ev->addr), addr_buf, sizeof(addr_buf));
	char port_buf[PORT_WIDTH];
	port_string_from_sockaddr(&(ev->addr), port_buf, sizeof(port_buf));

	json_t *json_details = json_object();
	json_object_set_new(json_details, "addr", json_string(addr_buf));
	json_object_set_new(json_details, "port", json_string(port_buf));
	json_object_set_new(json_ev, "details", json_details);
	return json_ev;
}

json_t *build_info_dump_ev(TcpEvInfoDump *ev)
{
	json_t *json_ev = json_object();
	build_shared_fields(json_ev, (TcpEvent *) ev);

	struct tcp_info i = ev->info;
	json_t *json_details = json_object();

	json_object_set_new(json_details, "state", json_integer(i.tcpi_state));
	json_object_set_new(json_details, "ca_state", json_integer(i.tcpi_ca_state));
	json_object_set_new(json_details, "retransmits", json_integer(i.tcpi_retransmits));
	json_object_set_new(json_details, "probes", json_integer(i.tcpi_probes));
	json_object_set_new(json_details, "backoff", json_integer(i.tcpi_backoff));
	json_object_set_new(json_details, "options", json_integer(i.tcpi_options));
	json_object_set_new(json_details, "snd_wscale", json_integer(i.tcpi_snd_wscale));
	json_object_set_new(json_details, "rcv_wscale", json_integer(i.tcpi_rcv_wscale));

	json_object_set_new(json_details, "rto", json_integer(i.tcpi_rto));
	json_object_set_new(json_details, "ato", json_integer(i.tcpi_ato));
	json_object_set_new(json_details, "snd_mss", json_integer(i.tcpi_snd_mss));
	json_object_set_new(json_details, "rcv_mss", json_integer(i.tcpi_rcv_mss));

	json_object_set_new(json_details, "unacked", json_integer(i.tcpi_unacked));
	json_object_set_new(json_details, "sacked", json_integer(i.tcpi_sacked));
	json_object_set_new(json_details, "lost", json_integer(i.tcpi_lost));
	json_object_set_new(json_details, "retrans", json_integer(i.tcpi_retrans));
	json_object_set_new(json_details, "fackets", json_integer(i.tcpi_fackets));

	/* Times */
	json_object_set_new(json_details, "last_data_sent", json_integer(i.tcpi_last_data_sent));
	json_object_set_new(json_details, "last_ack_sent", json_integer(i.tcpi_last_ack_sent));
	json_object_set_new(json_details, "last_data_recv", json_integer(i.tcpi_last_data_recv));
	json_object_set_new(json_details, "last_ack_recv", json_integer(i.tcpi_last_ack_recv));
	
	/* Metrics */
	json_object_set_new(json_details, "pmtu", json_integer(i.tcpi_pmtu));
	json_object_set_new(json_details, "rcv_ssthresh", json_integer(i.tcpi_rcv_ssthresh));
	json_object_set_new(json_details, "rtt", json_integer(i.tcpi_rtt));
	json_object_set_new(json_details, "rttvar", json_integer(i.tcpi_rttvar));
	json_object_set_new(json_details, "snd_ssthresh", json_integer(i.tcpi_snd_ssthresh));
	json_object_set_new(json_details, "snd_cwnd", json_integer(i.tcpi_snd_cwnd));
	json_object_set_new(json_details, "advmss", json_integer(i.tcpi_advmss));
	json_object_set_new(json_details, "reordering", json_integer(i.tcpi_reordering));

	json_object_set_new(json_details, "rcv_rtt", json_integer(i.tcpi_rcv_rtt));
	json_object_set_new(json_details, "rcv_space", json_integer(i.tcpi_rcv_space));

	json_object_set_new(json_details, "total_retrans", json_integer(i.tcpi_total_retrans));
	
	json_object_set_new(json_ev, "details", json_details);

	return json_ev;
}

json_t *build_setsockopt_ev(TcpEvSetsockopt *ev)
{
	json_t *json_ev = json_object();
	build_shared_fields(json_ev, (TcpEvent *) ev);

	/* Translate level to protocol name */
	struct protoent *protocol = getprotobynumber(ev->level);

	/* Translate optname */
	int optname_buf_size=MEMBER_SIZE(IntStrPair, str);
	char optname_buf[optname_buf_size];
	if (!string_from_cons(ev->optname, optname_buf, optname_buf_size,
		SOCKET_OPTIONS, sizeof(SOCKET_OPTIONS)/sizeof(IntStrPair))) {
		DEBUG(WARN, "Unknown setsockopt optname: %d", ev->optname);	
		snprintf(optname_buf, optname_buf_size, "%d", ev->optname);
	}

	json_t *json_details = json_object();
	json_object_set_new(json_details, "level", json_string(protocol->p_name));
	json_object_set_new(json_details, "optname", json_string(optname_buf));
	json_object_set_new(json_ev, "details", json_details);

	return json_ev;
}

	
