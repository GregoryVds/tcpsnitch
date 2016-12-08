require './lib/cprog.rb'
require './lib/webserver.rb'

SOCKET = CProg.new(<<-EOT, "socket")
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

BIND = CProg.new(<<-EOT, "bind")
#{SOCKET}
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
#{SOCKET}
#{sockaddr_in(WebServer::PORT)}
  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != -1)
    return(EXIT_FAILURE);
EOT

CONNECT = CProg.new(<<-EOT, "connect")
#{SOCKET}
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
#{SOCKET}
#{sockaddr_in(1234)}
  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != -1)
    return(EXIT_FAILURE);
EOT

SHUTDOWN = CProg.new(<<-EOT, "shutdown")
#{CONNECT}
  if (shutdown(sock, SHUT_WR) < 0)
    return(EXIT_FAILURE);
EOT

SHUTDOWN_DGRAM = CProg.new(<<-EOT, "shutdown_dgram")
#{CONNECT_DGRAM}
  if (shutdown(sock, SHUT_WR) < 0)
    return(EXIT_FAILURE);
EOT

SHUTDOWN_FAIL = CProg.new(<<-EOT, "shutdown_fail")
#{CONNECT}
  if (shutdown(sock, -1) != -1)
    return(EXIT_FAILURE);
EOT

LISTEN = CProg.new(<<-EOT, "listen")
#{SOCKET}
  if (listen(sock, 10) < 0)
    return(EXIT_FAILURE);
EOT

LISTEN_FAIL = CProg.new(<<-EOT, "listen_fail")
#{SOCKET}
  if (listen(42, 10) != -1)
    return(EXIT_FAILURE);
EOT

SETSOCKOPT = CProg.new(<<-EOT, "setsockopt")
#{SOCKET}
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
#{SOCKET}
  int optval = 1;
  if (setsockopt(sock, -42, SO_REUSEADDR, &optval, sizeof(optval)) != -1)
    return(EXIT_FAILURE);
EOT

SEND = CProg.new(<<-EOT, "send")
#{CONNECT}
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
#{SOCKET}
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

RECV = CProg.new(<<-EOT, "recv")
#{CONNECT}
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
#{CONNECT}
  fcntl(sock, F_SETFL, O_NONBLOCK);
  char buf[42];
  if (recv(sock, &buf, sizeof(buf), 0) != -1)
    return(EXIT_FAILURE); 
EOT

SENDTO = CProg.new(<<-EOT, "sendto")
#{CONNECT}
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
#{CONNECT}
  int data = 42;
  if (sendto(sock, &data, sizeof(data), -1, (struct sockaddr *)&addr,
             sizeof(addr)) != -1) {
    return(EXIT_FAILURE);
  }
EOT

RECVFROM = CProg.new(<<-EOT, "recvfrom")
#{CONNECT}
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
#{CONNECT}
  fcntl(sock, F_SETFL, O_NONBLOCK);
  char buf[42];
  socklen_t fromlen = sizeof(buf);
  if (recvfrom(sock, &buf, sizeof(buf), 0, (struct sockaddr *)&addr, 
               &fromlen) != -1) {
    return(EXIT_FAILURE); 
  }
EOT

WRITE_IOV = <<-EOT
  char *buf0 = \"short string\\n\";
  char *buf1 = \"This is a longer string\\n\";
  char *buf2 = \"This is the longest string in this example\\n\";

  struct iovec iov[3];
  iov[0].iov_base = buf0;
  iov[0].iov_len = strlen(buf0);
  iov[1].iov_base = buf1;
  iov[1].iov_len = strlen(buf1);
  iov[2].iov_base = buf2;
  iov[2].iov_len = strlen(buf2);
EOT

SEND_MSGHDR = <<-EOT
#{WRITE_IOV}
  struct msghdr msg;
  memset(&msg, '\\0', sizeof(msg));
  msg.msg_iov = iov;
  msg.msg_iovlen = sizeof(iov)/sizeof(struct iovec);
EOT

SENDMSG = CProg.new(<<-EOT, "sendmsg")
#{CONNECT}
#{SEND_MSGHDR}
  if (sendmsg(sock, &msg, 0) < 0)
    return(EXIT_FAILURE);
EOT

SENDMSG_DGRAM = CProg.new(<<-EOT, "sendmsg_dgram")
#{CONNECT_DGRAM}
#{SEND_MSGHDR}
  if (sendmsg(sock, &msg, 0) < 0)
    return(EXIT_FAILURE);
EOT

SENDMSG_FAIL = CProg.new(<<-EOT, "sendmsg_fail")
#{CONNECT}
#{SEND_MSGHDR}
  if (sendmsg(sock, &msg, -1) != -1)
    return(EXIT_FAILURE);
EOT

READ_IOV = <<-EOT
  char buf0[20];
  char buf1[30];
  char buf2[40];
  struct iovec iov[3];

  iov[0].iov_base = buf0;
  iov[0].iov_len = sizeof(buf0);
  iov[1].iov_base = buf1;
  iov[1].iov_len = sizeof(buf1);
  iov[2].iov_base = buf2;
  iov[2].iov_len = sizeof(buf2);
EOT

RECV_MSGHDR = <<-EOT
#{READ_IOV}
  struct msghdr msg;
  memset(&msg, '\\0', sizeof(msg));
  msg.msg_iov = iov;
  msg.msg_iovlen = sizeof(iov)/sizeof(struct iovec);
EOT

RECVMSG = CProg.new(<<-EOT, "recvmsg")
#{CONNECT}
#{send_http_get}
#{RECV_MSGHDR} 
  if (recvmsg(sock, &msg, 0) < 0)
    return(EXIT_FAILURE);
EOT

RECVMSG_DGRAM = CProg.new(<<-EOT, "recvmsg_dgram")
#{CONNECT_DGRAM}
#{RECV_MSGHDR} 
  fcntl(sock, F_SETFL, O_NONBLOCK);
  if (recvmsg(sock, &msg, 0) != -1)
    return(EXIT_FAILURE);
EOT

RECVMSG_FAIL = CProg.new(<<-EOT, "recvmsg_fail")
#{CONNECT}
#{send_http_get}
#{RECV_MSGHDR} 
  if (recvmsg(sock, &msg, -1) != -1)
    return(EXIT_FAILURE);
EOT

WRITE = CProg.new(<<-EOT, "write")
#{CONNECT}
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
#{CONNECT}
  int data = 42;
  if (write(sock, &data, -1) != -1)
    return(EXIT_FAILURE);
EOT

READ = CProg.new(<<-EOT, "read")
#{CONNECT}
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
#{CONNECT}
  fcntl(sock, F_SETFL, O_NONBLOCK);
  char buf[42];
  if (read(sock, &buf, -1) != -1)
    return(EXIT_FAILURE); 
EOT

CLOSE = CProg.new(<<-EOT, "close")
#{SOCKET}
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

FORK = CProg.new(<<-EOT, "fork")
#{SOCKET}
  pid_t pid;
  pid = fork();
  if (pid == -1) return (EXIT_FAILURE);
  if (pid == 0) { // Child
  #{SOCKET}
  } else { // Parent
    int status;
    waitpid(pid, &status, 0);
  }
EOT

WRITEV = CProg.new(<<-EOT, "writev")
#{CONNECT}
#{WRITE_IOV}
  if (writev(sock, iov, sizeof(iov)/sizeof(struct iovec)) < 0)
    return(EXIT_FAILURE);
EOT

WRITEV_DGRAM = CProg.new(<<-EOT, "writev_dgram")
#{CONNECT_DGRAM}
#{WRITE_IOV}
  if (writev(sock, iov, sizeof(iov)/sizeof(struct iovec)) < 0)
    return(EXIT_FAILURE);
EOT

WRITEV_FAIL = CProg.new(<<-EOT, "writev_fail")
#{CONNECT}
#{WRITE_IOV}
  if (writev(sock, iov, -1) != -1)
    return(EXIT_FAILURE);
EOT

READV = CProg.new(<<-EOT, "readv")
#{CONNECT}
#{send_http_get}
#{READ_IOV} 
  if (readv(sock, iov, sizeof(iov)/sizeof(struct iovec)) < 0)
    return(EXIT_FAILURE);
EOT

READV_DGRAM = CProg.new(<<-EOT, "readv_dgram")
#{SOCKET_DGRAM}
#{READ_IOV}
  fcntl(sock, F_SETFL, O_NONBLOCK);
  if (readv(sock, iov, sizeof(iov)/sizeof(struct iovec)) != -1)
    return(EXIT_FAILURE); 
EOT

READV_FAIL = CProg.new(<<-EOT, "readv_fail")
#{CONNECT}
#{send_http_get}
#{READ_IOV} 
  if (readv(sock, iov, -1) != -1)
    return(EXIT_FAILURE);
EOT


