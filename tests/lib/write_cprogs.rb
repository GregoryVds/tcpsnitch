require './lib/cprog.rb'
require './lib/webserver.rb'

SOCKET_STREAM = CProg.new(<<-EOT, "socket_stream")
  int sock;
  if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    return(EXIT_FAILURE);
EOT

SOCKET_DGRAM = CProg.new(<<-EOT, "socket_dgram")
  int sock;
  if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    return(EXIT_FAILURE);
EOT

SOCKET_FAIL = CProg.new(<<-EOT, "socket_fail")
  int sock;
  if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_UDP)) != -1)
    return(EXIT_FAILURE);
EOT

def sockaddr_in(port)
<<-EOT
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(#{port});
  inet_aton("127.0.0.1", &addr.sin_addr);
EOT
end

BIND_STREAM = CProg.new(<<-EOT, "bind_stream")
#{SOCKET_STREAM}
#{sockaddr_in(55555)}
  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    return(EXIT_FAILURE);
EOT

BIND_DGRAM = CProg.new(<<-EOT, "bind_dgram")
#{SOCKET_DGRAM}
#{sockaddr_in(55555)}
  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    return(EXIT_FAILURE);
EOT

BIND_FAIL = CProg.new(<<-EOT, "bind_fail")
#{SOCKET_STREAM}
#{sockaddr_in(WebServer::PORT)}
  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != -1)
    return(EXIT_FAILURE);
EOT

CONNECT_STREAM = CProg.new(<<-EOT, "connect_stream")
#{SOCKET_STREAM}
#{sockaddr_in(WebServer::PORT)}
  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    return(EXIT_FAILURE);
EOT

CONNECT_DGRAM = CProg.new(<<-EOT, "connect_dgram")
#{SOCKET_DGRAM}
#{sockaddr_in(WebServer::PORT)}
  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    return(EXIT_FAILURE);
EOT

CONNECT_FAIL = CProg.new(<<-EOT, "connect_fail")
#{SOCKET_STREAM}
#{sockaddr_in(1234)}
  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != -1)
    return(EXIT_FAILURE);
EOT

SHUTDOWN_STREAM = CProg.new(<<-EOT, "shutdown_stream")
#{CONNECT_STREAM}
  if (shutdown(sock, SHUT_WR) < 0)
    return(EXIT_FAILURE);
EOT

SHUTDOWN_DGRAM = CProg.new(<<-EOT, "shutdown_dgram")
#{CONNECT_DGRAM}
  if (shutdown(sock, SHUT_WR) < 0)
    return(EXIT_FAILURE);
EOT

SHUTDOWN_FAIL = CProg.new(<<-EOT, "shutdown_fail")
#{CONNECT_STREAM}
  if (shutdown(sock, -1) != -1)
    return(EXIT_FAILURE);
EOT

LISTEN_STREAM = CProg.new(<<-EOT, "listen_stream")
#{SOCKET_STREAM}
  if (listen(sock, 10) < 0)
    return(EXIT_FAILURE);
EOT

LISTEN_FAIL = CProg.new(<<-EOT, "listen_fail")
#{SOCKET_STREAM}
  if (listen(42, 10) != -1)
    return(EXIT_FAILURE);
EOT

SETSOCKOPT_STREAM = CProg.new(<<-EOT, "setsockopt_stream")
#{SOCKET_STREAM}
  int optval = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
    return(EXIT_FAILURE);
EOT

SETSOCKOPT_DGRAM = CProg.new(<<-EOT, "setsockopt_dgram")
#{SOCKET_DGRAM}
  int optval = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
    return(EXIT_FAILURE);
EOT

SETSOCKOPT_FAIL = CProg.new(<<-EOT, "setsockopt_fail")
#{SOCKET_STREAM}
  int optval = 1;
  if (setsockopt(sock, -42, SO_REUSEADDR, &optval, sizeof(optval)) != -1)
    return(EXIT_FAILURE);
EOT

SEND_STREAM = CProg.new(<<-EOT, "send_stream")
#{CONNECT_STREAM}
  int data = 42;
  if (send(sock, &data, sizeof(data), 0) < 0)
    return(EXIT_FAILURE); 
EOT

SEND_DGRAM = CProg.new(<<-EOT, "send_dgram")
#{CONNECT_DGRAM}
  int data = 42;
  if (send(sock, &data, sizeof(data), 0) < 0)
    return(EXIT_FAILURE); 
EOT

SEND_FAIL = CProg.new(<<-EOT, "send_fail")
#{SOCKET_STREAM}
  int data = 42;
  if (send(sock, &data, sizeof(data), -1) != -1)
    return(EXIT_FAILURE); 
EOT

def send_http_get
<<-EOT
  char *req = "GET / HTTP/1.0\\r\\n\\r\\n";
  send(sock, req, sizeof(char)*strlen(req), 0); 
EOT
end

RECV_STREAM = CProg.new(<<-EOT, "recv_stream")
#{CONNECT_STREAM}
#{send_http_get}
  char buf[42];
  if (recv(sock, &buf, sizeof(buf), 0) < 0)
    return(EXIT_FAILURE); 
EOT

RECV_DGRAM = CProg.new(<<-EOT, "recv_dgram")
#{SOCKET_DGRAM}
  fcntl(sock, F_SETFL, O_NONBLOCK);
  char buf[42];
  if (recv(sock, &buf, sizeof(buf), 0) != -1)
    return(EXIT_FAILURE); 
EOT

RECV_FAIL = CProg.new(<<-EOT, "recv_fail")
#{CONNECT_STREAM}
  fcntl(sock, F_SETFL, O_NONBLOCK);
  char buf[42];
  if (recv(sock, &buf, sizeof(buf), 0) != -1)
    return(EXIT_FAILURE); 
EOT

SENDTO_STREAM = CProg.new(<<-EOT, "sendto_stream")
#{CONNECT_STREAM}
  int data = 42;
  if (sendto(sock, &data, sizeof(data), 0, (struct sockaddr *)&addr, 
             sizeof(addr)) < 0) {
    return(EXIT_FAILURE);
  }
EOT

SENDTO_DGRAM = CProg.new(<<-EOT, "sendto_dgram")
#{SOCKET_DGRAM}
#{sockaddr_in(WebServer::PORT)}
  int data = 42;
  if (sendto(sock, &data, sizeof(data), 0, (struct sockaddr *)&addr,
             sizeof(addr)) < 0) {
    return(EXIT_FAILURE);
  }
EOT

SENDTO_FAIL = CProg.new(<<-EOT, "sendto_fail")
#{CONNECT_STREAM}
  int data = 42;
  if (sendto(sock, &data, sizeof(data), -1, (struct sockaddr *)&addr,
             sizeof(addr)) != -1) {
    return(EXIT_FAILURE);
  }
EOT

RECVFROM_STREAM = CProg.new(<<-EOT, "recvfrom_stream")
#{CONNECT_STREAM}
#{send_http_get}
  char buf[42];
  socklen_t fromlen = sizeof(buf);
  if (recvfrom(sock, &buf, sizeof(buf), 0, (struct sockaddr *)&addr, 
               &fromlen) < 0) {
    return(EXIT_FAILURE); 
  }
EOT

RECVFROM_DGRAM = CProg.new(<<-EOT, "recvfrom_dgram")
#{CONNECT_DGRAM}
  fcntl(sock, F_SETFL, O_NONBLOCK);
  char buf[42];
  socklen_t fromlen = sizeof(buf);
  if (recvfrom(sock, &buf, sizeof(buf), 0, (struct sockaddr *)&addr, 
               &fromlen) != -1) {
    return(EXIT_FAILURE); 
  }
EOT

RECVFROM_FAIL = CProg.new(<<-EOT, "recvfrom_fail")
#{CONNECT_STREAM}
  fcntl(sock, F_SETFL, O_NONBLOCK);
  char buf[42];
  socklen_t fromlen = sizeof(buf);
  if (recvfrom(sock, &buf, sizeof(buf), 0, (struct sockaddr *)&addr, 
               &fromlen) != -1) {
    return(EXIT_FAILURE); 
  }
EOT

WRITE_STREAM = CProg.new(<<-EOT, "write_stream")
#{CONNECT_STREAM}
  int data = 42;
  if (write(sock, &data, sizeof(data)) < 0)
    return(EXIT_FAILURE);
EOT

WRITE_DGRAM = CProg.new(<<-EOT, "write_dgram")
#{CONNECT_DGRAM}
  int data = 42;
  if (write(sock, &data, sizeof(data)) < 0)
    return(EXIT_FAILURE);
EOT

WRITE_FAIL = CProg.new(<<-EOT, "write_fail")
#{CONNECT_STREAM}
  int data = 42;
  if (write(sock, &data, -1) != -1)
    return(EXIT_FAILURE);
EOT

READ_STREAM = CProg.new(<<-EOT, "read_stream")
#{CONNECT_STREAM}
#{send_http_get}
  char buf[42];
  if (read(sock, &buf, sizeof(buf)) < 0)
    return(EXIT_FAILURE); 
EOT

READ_DGRAM = CProg.new(<<-EOT, "read_dgram")
#{SOCKET_DGRAM}
  fcntl(sock, F_SETFL, O_NONBLOCK);
  char buf[42];
  if (read(sock, &buf, sizeof(buf)) != -1)
    return(EXIT_FAILURE); 
EOT

READ_FAIL = CProg.new(<<-EOT, "read_fail")
#{CONNECT_STREAM}
  fcntl(sock, F_SETFL, O_NONBLOCK);
  char buf[42];
  if (read(sock, &buf, -1) != -1)
    return(EXIT_FAILURE); 
EOT

CLOSE_STREAM = CProg.new(<<-EOT, "close_stream")
#{SOCKET_STREAM}
  if (close(sock) < 0)
    return(EXIT_FAILURE);
EOT

CLOSE_DGRAM = CProg.new(<<-EOT, "close_dgram")
#{SOCKET_DGRAM}
  if (close(sock) < 0)
    return(EXIT_FAILURE);
EOT

CLOSE_FAIL = CProg.new(<<-EOT, "close_fail")
  if (close(42) != -1)
    return(EXIT_FAILURE);
EOT

