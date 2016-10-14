#include <jansson.h>
#include "tcp_json_builder.h"
#include "lib.h"

json_t *build_tcp_connection(TcpConnection *con);
json_t *build_event(TcpEvent *ev);
json_t *build_sock_opened_ev(TcpEvSockOpened *ev);
json_t *build_sock_closed_ev(TcpEvSockClosed *ev);
json_t *build_data_sent_ev(TcpEvDataSent *ev);
json_t *build_data_received_ev(TcpEvDataReceived *ev);
json_t *build_connected_ev(TcpEvConnected *ev);
json_t *build_info_dump_ev(TcpEvInfoDump *ev);

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

	json_object_set_new(json_con, "id",
			json_integer(con->id));
	json_object_set_new(json_con, "eventsCount", 
			json_integer(con->events_count));
	json_object_set_new(json_con, "bytesSent", 
			json_integer(con->bytes_sent));
	json_object_set_new(json_con, "bytesReceived", 
			json_integer(con->bytes_received));
	json_object_set_new(json_con, "events",
			events);

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
		case CONNECTED:	    
			return build_connected_ev((TcpEvConnected *) ev);
		case INFO_DUMP:     
			return build_info_dump_ev((TcpEvInfoDump *) ev);
		default:
			DEBUG(ERROR, "build_event() failed. Unrecognized event"
					" type %d.", ev->type);
			exit(EXIT_FAILURE);
			return NULL; // Will not reach this.
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
}

json_t *build_sock_opened_ev(TcpEvSockOpened *ev)
{
	json_t *json_ev = json_object();
	build_shared_fields(json_ev, (TcpEvent *) ev);

	json_t *json_details = json_object();
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

json_t *build_connected_ev(TcpEvConnected *ev)
{
	json_t *json_ev = json_object();
	build_shared_fields(json_ev, (TcpEvent *) ev);

	json_t *json_details = json_object();
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

