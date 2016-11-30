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

