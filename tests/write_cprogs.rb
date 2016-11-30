require './lib/cprog.rb'
require './lib/webserver.rb'

SOCKET_STREAM = CProg.new(<<-EOT, "socket_stream")
  int sock;
  if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
    return(EXIT_FAILURE);
EOT

SOCKET_DGRAM = CProg.new(<<-EOT, "socket_dgram")
  int sock;
  if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    return(EXIT_FAILURE);
EOT

SOCKET_FAIL = CProg.new(<<-EOT, "socket_fail")
  int sock;
  sock = socket(AF_INET, SOCK_STREAM, IPPROTO_UDP);
  if (sock > -1)
    return(EXIT_FAILURE);
EOT

BIND = <<-EOT
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(55555);
  addr.sin_addr.s_addr = INADDR_ANY;
  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)))
    return(EXIT_FAILURE);
EOT

BIND_STREAM = CProg.new(<<-EOT, "bind_stream")
#{SOCKET_STREAM}
#{BIND}
EOT

BIND_DGRAM = CProg.new(<<-EOT, "bind_dgram")
#{SOCKET_DGRAM}
#{BIND}
EOT

BIND_FAIL = CProg.new(<<-EOT, "bind_fail")
#{SOCKET_STREAM}
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(#{WebServer::PORT}); // Already used by webserver. 
  addr.sin_addr.s_addr = INADDR_ANY;
  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != -1)
    return(EXIT_FAILURE);
EOT
