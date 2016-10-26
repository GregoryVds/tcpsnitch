#ifndef TCP_JSON_BUILDER_H
#define TCP_JSON_BUILDER_H

#include "tcp_spy.h"

char *build_tcp_connection_json(TcpConnection *con);
char *build_capture_filter(const struct sockaddr *addr); 

#endif

