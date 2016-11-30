require './cprog.rb'

C_SOCKET_STREAM = CProg.new(<<-EOT, "socket_stream")
  int sock;
  if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
    return(EXIT_FAILURE);
EOT

C_SOCKET_DGRAM = CProg.new(<<-EOT, "socket_dgram")
  int sock;
  if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    return(EXIT_FAILURE);
EOT

C_SOCKET_FAIL = CProg.new(<<-EOT, "socket_fail")
  int sock;
  sock = socket(AF_INET, SOCK_STREAM, IPPROTO_UDP);
  if (sock > -1)
    return(EXIT_FAILURE);
EOT

C_BIND_STREAM = CProg.new(<<-EOT, "bind_stream")
  #{C_SOCKET_STREAM}
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(55555);
  addr.sin_addr.s_addr = INADDR_ANY;
  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)))
    return(EXIT_FAILURE);
EOT

