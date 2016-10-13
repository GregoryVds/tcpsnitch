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

	json_object_set_new(json_con, "id", json_integer(con->id));
	json_object_set_new(json_con, "eventsCount", json_integer(con->events_count));
	json_object_set_new(json_con, "bytesSent", json_integer(con->bytes_sent));
	json_object_set_new(json_con, "bytesReceived", json_integer(con->bytes_received));
	json_object_set_new(json_con, "events", events);

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
			return build_data_received_ev((TcpEvDataReceived *) ev);
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
	json_object_set_new(json_ev, "type", json_string(type_str));
	json_object_set_new(json_ev, "timestampSec", json_integer(ev->timestamp.tv_sec));
	json_object_set_new(json_ev, "timestampUsec", json_integer(ev->timestamp.tv_usec));
}

json_t *build_sock_opened_ev(TcpEvSockOpened *ev)
{
	json_t *json_ev = json_object();
	build_shared_fields(json_ev, (TcpEvent *) ev);
	return json_ev;
}

json_t *build_sock_closed_ev(TcpEvSockClosed *ev)
{
	json_t *json_ev = json_object();
	build_shared_fields(json_ev, (TcpEvent *) ev);
	return json_ev;
}

json_t *build_data_sent_ev(TcpEvDataSent *ev)
{
	json_t *json_ev = json_object();
	build_shared_fields(json_ev, (TcpEvent *) ev);
	return json_ev;
}

json_t *build_data_received_ev(TcpEvDataReceived *ev)
{
	json_t *json_ev = json_object();
	build_shared_fields(json_ev, (TcpEvent *) ev);
	return json_ev;
}

json_t *build_connected_ev(TcpEvConnected *ev)
{
	json_t *json_ev = json_object();
	build_shared_fields(json_ev, (TcpEvent *) ev);
	return json_ev;
}

json_t *build_info_dump_ev(TcpEvInfoDump *ev)
{
	json_t *json_ev = json_object();
	build_shared_fields(json_ev, (TcpEvent *) ev);
	return json_ev;
}


