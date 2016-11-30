require './lib/cprog.rb'
require './lib/webserver.rb'

def socket(type, protocol, test)
<<-EOT
  int sock;
  if (!((sock = socket(AF_INET, #{type}, #{protocol})) #{test}))
    return(EXIT_FAILURE);
EOT
end

SOCKET_STREAM = CProg.new(<<-EOT, "socket_stream")
#{socket("SOCK_STREAM", "IPPROTO_TCP", ">-1")}
EOT

SOCKET_DGRAM = CProg.new(<<-EOT, "socket_dgram")
#{socket("SOCK_DGRAM", "IPPROTO_UDP", ">-1")}
EOT

SOCKET_FAIL = CProg.new(<<-EOT, "socket_fail")
#{socket("SOCK_STREAM", "IPPROTO_UDP", "==-1")}
EOT

def sockaddr_in(port)
<<-EOT
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(#{port});
  inet_aton("127.0.0.1", &addr.sin_addr);
EOT
end

def bind(port, test)
<<-EOT
#{sockaddr_in(port)}
  if (!(bind(sock, (struct sockaddr *)&addr, sizeof(addr)) #{test}))
    return(EXIT_FAILURE);
EOT
end

BIND_STREAM = CProg.new(<<-EOT, "bind_stream")
#{SOCKET_STREAM}
#{bind(55555, "==0")}
EOT

BIND_DGRAM = CProg.new(<<-EOT, "bind_dgram")
#{SOCKET_DGRAM}
#{bind(55555, "==0")}
EOT

BIND_FAIL = CProg.new(<<-EOT, "bind_fail")
#{SOCKET_STREAM}
#{bind(WebServer::PORT, "==-1")}
EOT

def connect(sock, test)
<<-EOT
  if (!(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) #{test}))
    return(EXIT_FAILURE);
EOT
end

CONNECT_STREAM = CProg.new(<<-EOT, "connect_stream")
#{SOCKET_STREAM}
#{sockaddr_in(WebServer::PORT)}
#{connect("sock", "==0")}
EOT

CONNECT_DGRAM = CProg.new(<<-EOT, "connect_dgram")
#{SOCKET_DGRAM}
#{sockaddr_in(WebServer::PORT)}
#{connect("sock", "==0")}
EOT

CONNECT_FAIL = CProg.new(<<-EOT, "connect_fail")
#{SOCKET_STREAM}
#{sockaddr_in(1234)}
#{connect(42, "==-1")}
EOT

def shutdown(flag, test)
<<-EOT
  if (!(shutdown(sock, #{flag}) #{test}))
    return(EXIT_FAILURE);
EOT
end

SHUTDOWN_STREAM = CProg.new(<<-EOT, "shutdown_stream")
#{CONNECT_STREAM}
#{shutdown("SHUT_WR", "==0")}
EOT

SHUTDOWN_DGRAM = CProg.new(<<-EOT, "shutdown_dgram")
#{CONNECT_DGRAM}
#{shutdown("SHUT_WR", "==0")}
EOT

SHUTDOWN_FAIL = CProg.new(<<-EOT, "shutdown_fail")
#{CONNECT_STREAM}
#{shutdown("-1", "==-1")}
EOT

def listen(sock, backlog, test)
<<-EOT
  if (!(listen(#{sock}, #{backlog}) #{test}))
    return(EXIT_FAILURE);
EOT
end

LISTEN_STREAM = CProg.new(<<-EOT, "listen_stream")
#{SOCKET_STREAM}
#{listen("sock", 10, "==0")}
EOT

LISTEN_FAIL = CProg.new(<<-EOT, "listen_fail")
#{SOCKET_STREAM}
#{listen(42, 10, "==-1")}
EOT

def setsockopt(sock, test)
<<-EOT
  int optval = 1;
  if (!(setsockopt(#{sock}, SOL_SOCKET, SO_REUSEADDR, &optval, 
                   sizeof(optval)) #{test})) {
    return(EXIT_FAILURE);
  }
EOT
end

SETSOCKOPT_STREAM = CProg.new(<<-EOT, "setsockopt_stream")
#{SOCKET_STREAM}
#{setsockopt("sock", "==0")}
EOT

SETSOCKOPT_DGRAM = CProg.new(<<-EOT, "setsockopt_dgram")
#{SOCKET_DGRAM}
#{setsockopt("sock", "==0")}
EOT

SETSOCKOPT_FAIL = CProg.new(<<-EOT, "setsockopt_fail")
#{SOCKET_STREAM}
#{setsockopt(42, "==-1")}
EOT

def send(sock, test)
<<-EOT
  int data = 42;
  if (!(send(#{sock}, &data, sizeof(data), 0) #{test}))
    return(EXIT_FAILURE); 
EOT
end

SEND_STREAM = CProg.new(<<-EOT, "send_stream")
#{CONNECT_STREAM}
#{send("sock", ">0")}
EOT

SEND_DGRAM = CProg.new(<<-EOT, "send_dgram")
#{CONNECT_DGRAM}
#{send("sock", ">0")}
EOT

SEND_FAIL = CProg.new(<<-EOT, "send_fail")
#{CONNECT_STREAM}
#{send(42, "==-1")}
EOT

def send_http_get
<<-EOT
  char *req = "GET / HTTP/1.0\\r\\n\\r\\n";
  send(sock, req, sizeof(char)*strlen(req), 0); 
EOT
end

def recv(sock, test)
<<-EOT
#{send_http_get}
  char buf[42];
  if (!(recv(#{sock}, &buf, sizeof(buf), 0) #{test}))
    return(EXIT_FAILURE); 
EOT
end

RECV_STREAM = CProg.new(<<-EOT, "recv_stream")
#{CONNECT_STREAM}
#{recv("sock", ">=0")}
EOT

RECV_FAIL = CProg.new(<<-EOT, "recv_fail")
#{CONNECT_STREAM}
#{recv(42, "==-1")}
EOT

def sendto(sock, test)
<<-EOT
  int data = 42;
  if (!(sendto(#{sock}, &data, sizeof(data), 0, (struct sockaddr *)&addr,
               sizeof(addr)) #{test})) {
    return(EXIT_FAILURE);
  }
EOT
end

SENDTO_STREAM = CProg.new(<<-EOT, "sendto_stream")
#{CONNECT_STREAM}
#{sendto("sock", ">0")}
EOT

SENDTO_DGRAM = CProg.new(<<-EOT, "sendto_dgram")
#{SOCKET_DGRAM}
#{sockaddr_in(WebServer::PORT)}
#{sendto("sock", ">0")}
EOT

SENDTO_FAIL = CProg.new(<<-EOT, "sendto_fail")
#{CONNECT_STREAM}
#{sendto(42, "==-1")}
EOT

def recvfrom(sock, test)
<<-EOT
#{send_http_get}
  char buf[42];
  socklen_t fromlen = sizeof(buf);
  if (!(recvfrom(#{sock}, &buf, sizeof(buf), 0, (struct sockaddr *)&addr,
                 &fromlen) #{test})) {
    return(EXIT_FAILURE); 
  }
EOT
end

RECVFROM_STREAM = CProg.new(<<-EOT, "recvfrom_stream")
#{CONNECT_STREAM}
#{recvfrom("sock", ">=0")}
EOT

RECVFROM_FAIL = CProg.new(<<-EOT, "recvfrom_fail")
#{CONNECT_STREAM}
#{recvfrom(42, "==-1")}
EOT

def write(sock, test)
<<-EOT
  int data = 42;
  if (!(write(#{sock}, &data, sizeof(data)) #{test}))
    return(EXIT_FAILURE);
EOT
end

WRITE_STREAM = CProg.new(<<-EOT, "write_stream")
#{CONNECT_STREAM}
#{write("sock", ">0")}
EOT

WRITE_DGRAM = CProg.new(<<-EOT, "write_dgram")
#{CONNECT_DGRAM}
#{write("sock", ">0")}
EOT

WRITE_FAIL = CProg.new(<<-EOT, "write_fail")
#{CONNECT_STREAM}
#{write(42, "==-1")}
EOT

def read(sock, test)
<<-EOT
#{send_http_get}
  char buf[42];
  if (!(read(#{sock}, &buf, sizeof(buf)) #{test}))
    return(EXIT_FAILURE); 
EOT
end

READ_STREAM = CProg.new(<<-EOT, "read_stream")
#{CONNECT_STREAM}
#{read("sock", ">=0")}
EOT

READ_FAIL = CProg.new(<<-EOT, "read_fail")
#{CONNECT_STREAM}
#{read(42, "==-1")}
EOT

def close(sock, test)
<<-EOT
  if (!(close(#{sock}) #{test}))
    return(EXIT_FAILURE);
EOT
end

CLOSE_STREAM = CProg.new(<<-EOT, "close_stream")
#{SOCKET_STREAM}
#{close("sock", "==0")}
EOT

CLOSE_DGRAM = CProg.new(<<-EOT, "close_dgram")
#{SOCKET_DGRAM}
#{close("sock", ">0")}
EOT

CLOSE_FAIL = CProg.new(<<-EOT, "clos_fail")
#{SOCKET_STREAM}
#{close(42, "==-1")}
EOT

