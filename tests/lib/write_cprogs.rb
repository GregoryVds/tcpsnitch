require './lib/cprog.rb'
require './lib/webserver.rb'

SOCKET = CProg.new(<<-EOT, 'socket')
  int sock;
  if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
    fprintf(stderr, "socket() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

SOCKET_DGRAM = CProg.new(<<-EOT, 'socket_dgram')
  int sock;
  if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    fprintf(stderr, "socket() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

SOCKET_FAIL = CProg.new(<<-EOT, 'socket_fail')
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

BIND = CProg.new(<<-EOT, 'bind')
#{SOCKET}
#{sockaddr_in(55_555)}
  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    fprintf(stderr, "bind() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

BIND_DGRAM = CProg.new(<<-EOT, 'bind_dgram')
#{SOCKET_DGRAM}
#{sockaddr_in(55_555)}
  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    fprintf(stderr, "bind() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

BIND_FAIL = CProg.new(<<-EOT, 'bind_fail')
#{SOCKET}
#{sockaddr_in(WebServer::PORT)}
  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != -1)
    return(EXIT_FAILURE);
EOT

CONNECT = CProg.new(<<-EOT, 'connect')
#{SOCKET}
#{sockaddr_in(WebServer::PORT)}
  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    fprintf(stderr, "connect() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

CONNECT_DGRAM = CProg.new(<<-EOT, 'connect_dgram')
#{SOCKET_DGRAM}
#{sockaddr_in(WebServer::PORT)}
  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    fprintf(stderr, "connect() failed: %s\\n.", strerror(errno)); 
    return(EXIT_FAILURE);
  }
EOT

CONNECT_FAIL = CProg.new(<<-EOT, 'connect_fail')
#{SOCKET}
#{sockaddr_in(1234)}
  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != -1)
    return(EXIT_FAILURE);
EOT

SHUTDOWN = CProg.new(<<-EOT, 'shutdown')
#{CONNECT}
  if (shutdown(sock, SHUT_WR) < 0) {
    fprintf(stderr, "shutdown() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

SHUTDOWN_DGRAM = CProg.new(<<-EOT, 'shutdown_dgram')
#{CONNECT_DGRAM}
 if (shutdown(sock, SHUT_WR) < 0) {
    fprintf(stderr, "shutdown() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

SHUTDOWN_FAIL = CProg.new(<<-EOT, 'shutdown_fail')
#{CONNECT}
  if (shutdown(sock, -1) != -1)
    return(EXIT_FAILURE);
EOT

LISTEN = CProg.new(<<-EOT, 'listen')
#{SOCKET}
  if (listen(sock, 10) < 0) {
    fprintf(stderr, "listen() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

LISTEN_FAIL = CProg.new(<<-EOT, 'listen_fail')
#{SOCKET}
  if (listen(42, 10) != -1)
    return(EXIT_FAILURE);
EOT

GETSOCKOPT = CProg.new(<<-EOT, 'getsockopt')
#{SOCKET}
  int optval;
  socklen_t optlen = sizeof(optval);
  if (getsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, &optlen) < 0) {
    fprintf(stderr, "getsockopt() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

GETSOCKOPT_DGRAM = CProg.new(<<-EOT, 'getsockopt_dgram')
#{SOCKET_DGRAM}
  int optval;
  socklen_t optlen = sizeof(optval);
  if (getsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, &optlen) < 0) {
    fprintf(stderr, "getsockopt() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

GETSOCKOPT_FAIL = CProg.new(<<-EOT, 'getsockopt_fail')
#{SOCKET}
  int optval;
  socklen_t optlen = sizeof(optval);
  if (getsockopt(sock, -42, SO_REUSEADDR, &optval, &optlen) != -1)
    return(EXIT_FAILURE);
EOT

SETSOCKOPT = CProg.new(<<-EOT, 'setsockopt')
#{SOCKET}
  int optval = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
    fprintf(stderr, "setsockopt() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

SETSOCKOPT_DGRAM = CProg.new(<<-EOT, 'setsockopt_dgram')
#{SOCKET_DGRAM}
  int optval = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
    fprintf(stderr, "setsockopt() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

SETSOCKOPT_FAIL = CProg.new(<<-EOT, 'setsockopt_fail')
#{SOCKET}
  int optval = 1;
  if (setsockopt(sock, -42, SO_REUSEADDR, &optval, sizeof(optval)) != -1)
    return(EXIT_FAILURE);
EOT

SEND = CProg.new(<<-EOT, 'send')
#{CONNECT}
  int data = 42;
  if (send(sock, &data, sizeof(data), 0) < 0) {
    fprintf(stderr, "send() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

SEND_DGRAM = CProg.new(<<-EOT, 'send_dgram')
#{CONNECT_DGRAM}
  int data = 42;
  if (send(sock, &data, sizeof(data), 0) < 0) {
    fprintf(stderr, "send() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

SEND_FAIL = CProg.new(<<-EOT, 'send_fail')
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

RECV = CProg.new(<<-EOT, 'recv')
#{CONNECT}
#{send_http_get}
  char buf[42];
  if (recv(sock, &buf, sizeof(buf), 0) < 0) {
    fprintf(stderr, "recv() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

RECV_DGRAM = CProg.new(<<-EOT, 'recv_dgram')
#{SOCKET_DGRAM}
  fcntl(sock, F_SETFL, O_NONBLOCK);
  char buf[42];
  if (recv(sock, &buf, sizeof(buf), 0) != -1)
    return(EXIT_FAILURE);
EOT

RECV_FAIL = CProg.new(<<-EOT, 'recv_fail')
#{CONNECT}
  fcntl(sock, F_SETFL, O_NONBLOCK);
  char buf[42];
  if (recv(sock, &buf, sizeof(buf), 0) != -1)
    return(EXIT_FAILURE);
EOT

SENDTO = CProg.new(<<-EOT, 'sendto')
#{CONNECT}
  int data = 42;
  if (sendto(sock, &data, sizeof(data), 0, (struct sockaddr *)&addr,
             sizeof(addr)) < 0) {
    fprintf(stderr, "sendto() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

SENDTO_DGRAM = CProg.new(<<-EOT, 'sendto_dgram')
#{SOCKET_DGRAM}
#{sockaddr_in(WebServer::PORT)}
  int data = 42;
  if (sendto(sock, &data, sizeof(data), 0, (struct sockaddr *)&addr,
             sizeof(addr)) < 0) {
    fprintf(stderr, "sendto() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

SENDTO_FAIL = CProg.new(<<-EOT, 'sendto_fail')
#{CONNECT}
  int data = 42;
  if (sendto(sock, &data, sizeof(data), -1, (struct sockaddr *)&addr,
             sizeof(addr)) != -1) {
    return(EXIT_FAILURE);
  }
EOT

RECVFROM = CProg.new(<<-EOT, 'recvfrom')
#{CONNECT}
#{send_http_get}
  char buf[42];
  socklen_t fromlen = sizeof(buf);
  if (recvfrom(sock, &buf, sizeof(buf), 0, (struct sockaddr *)&addr,
               &fromlen) < 0) {
    fprintf(stderr, "recvfrom() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

RECVFROM_DGRAM = CProg.new(<<-EOT, 'recvfrom_dgram')
#{CONNECT_DGRAM}
  fcntl(sock, F_SETFL, O_NONBLOCK);
  char buf[42];
  socklen_t fromlen = sizeof(buf);
  if (recvfrom(sock, &buf, sizeof(buf), 0, (struct sockaddr *)&addr,
               &fromlen) != -1) {
    fprintf(stderr, "recvfrom() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

RECVFROM_FAIL = CProg.new(<<-EOT, 'recvfrom_fail')
#{CONNECT}
  fcntl(sock, F_SETFL, O_NONBLOCK);
  char buf[42];
  socklen_t fromlen = sizeof(buf);
  if (recvfrom(sock, &buf, sizeof(buf), 0, (struct sockaddr *)&addr,
               &fromlen) != -1) {
    return(EXIT_FAILURE);
  }
EOT

def write_iovec(iovec_name = 'iovec')
  <<-EOT
  char *#{iovec_name}_buf0 = "short string\\n";
  char *#{iovec_name}_buf1 = "This is a longer string\\n";
  char *#{iovec_name}_buf2 = "This is the longest string in this example\\n";

  struct iovec #{iovec_name}[3];
  #{iovec_name}[0].iov_base = #{iovec_name}_buf0;
  #{iovec_name}[0].iov_len = strlen(#{iovec_name}_buf0);
  #{iovec_name}[1].iov_base = #{iovec_name}_buf1;
  #{iovec_name}[1].iov_len = strlen(#{iovec_name}_buf1);
  #{iovec_name}[2].iov_base = #{iovec_name}_buf2;
  #{iovec_name}[2].iov_len = strlen(#{iovec_name}_buf2);
  EOT
end

def send_msghdr(msghdr_name = 'msg', iovec_name = 'iovec')
  <<-EOT
#{write_iovec(iovec_name)}
  struct msghdr #{msghdr_name};
  memset(&#{msghdr_name}, '\\0', sizeof(#{msghdr_name}));
  #{msghdr_name}.msg_iov = #{iovec_name};
  #{msghdr_name}.msg_iovlen = sizeof(#{iovec_name})/sizeof(struct iovec);
  EOT
end

SENDMSG = CProg.new(<<-EOT, 'sendmsg')
#{CONNECT}
#{send_msghdr}
  if (sendmsg(sock, &msg, 0) < 0) {
    fprintf(stderr, "sendmsg() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

SENDMSG_DGRAM = CProg.new(<<-EOT, 'sendmsg_dgram')
#{CONNECT_DGRAM}
#{send_msghdr}
  if (sendmsg(sock, &msg, 0) < 0) {
    fprintf(stderr, "sendmsg() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

SENDMSG_FAIL = CProg.new(<<-EOT, 'sendmsg_fail')
#{CONNECT}
#{send_msghdr}
  if (sendmsg(sock, &msg, -1) != -1)
    return(EXIT_FAILURE);
EOT

def read_iovec(iovec_name = 'iovec')
  <<-EOT
  char #{iovec_name}_buf0[20];
  char #{iovec_name}_buf1[30];
  char #{iovec_name}_buf2[40];
  struct iovec #{iovec_name}[3];

  #{iovec_name}[0].iov_base = #{iovec_name}_buf0;
  #{iovec_name}[0].iov_len = sizeof(#{iovec_name}_buf0);
  #{iovec_name}[1].iov_base = #{iovec_name}_buf1;
  #{iovec_name}[1].iov_len = sizeof(#{iovec_name}_buf1);
  #{iovec_name}[2].iov_base = #{iovec_name}_buf2;
  #{iovec_name}[2].iov_len = sizeof(#{iovec_name}_buf2);
  EOT
end

def recv_msghdr(msghdr_name = 'msg', iovec_name = 'iovec')
  <<-EOT
#{read_iovec(iovec_name)}
  struct msghdr #{msghdr_name};
  memset(&#{msghdr_name}, '\\0', sizeof(#{msghdr_name}));
  #{msghdr_name}.msg_iov = #{iovec_name};
  #{msghdr_name}.msg_iovlen = sizeof(#{iovec_name})/sizeof(struct iovec);
  EOT
end

RECVMSG = CProg.new(<<-EOT, 'recvmsg')
#{CONNECT}
#{send_http_get}
#{recv_msghdr}
  if (recvmsg(sock, &msg, 0) < 0) { 
    fprintf(stderr, "recvmsg() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
   }
EOT

RECVMSG_DGRAM = CProg.new(<<-EOT, 'recvmsg_dgram')
#{CONNECT_DGRAM}
#{recv_msghdr}
  fcntl(sock, F_SETFL, O_NONBLOCK);
  if (recvmsg(sock, &msg, 0) != -1)
    return(EXIT_FAILURE);
EOT

RECVMSG_FAIL = CProg.new(<<-EOT, 'recvmsg_fail')
#{CONNECT}
#{send_http_get}
#{recv_msghdr}
  if (recvmsg(sock, &msg, -1) != -1)
    return(EXIT_FAILURE);
EOT

MMSGHDR = <<-EOT.freeze
  struct mmsghdr mmsg[2];
	memset(mmsg, 0, sizeof(mmsg));
	mmsg[0].msg_hdr = msg1;
	mmsg[1].msg_hdr = msg2;
EOT

SENDMMSG = CProg.new(<<-EOT, 'sendmmsg')
#{CONNECT}
#{send_msghdr('msg1', 'iovec1')}
#{send_msghdr('msg2', 'iovec2')}
#{MMSGHDR}
	if (sendmmsg(sock, mmsg, 2, 0) < 0)
		return(EXIT_FAILURE);
EOT

SENDMMSG_DGRAM = CProg.new(<<-EOT, 'sendmmsg_dgram')
#{CONNECT_DGRAM}
#{send_msghdr('msg1', 'iovec1')}
#{send_msghdr('msg2', 'iovec2')}
#{MMSGHDR}
	if (sendmmsg(sock, mmsg, 2, 0) < 0) {
    fprintf(stderr, "sendmmsg() failed: %s\\n.", strerror(errno));
		return(EXIT_FAILURE);
  }
EOT

SENDMMSG_FAIL = CProg.new(<<-EOT, 'sendmmsg_fail')
#{CONNECT}
#{send_msghdr('msg1', 'iovec1')}
#{send_msghdr('msg2', 'iovec2')}
#{MMSGHDR}
	if (sendmmsg(sock, mmsg, 2, -1) != -1)
		return(EXIT_FAILURE);
EOT

RECVMMSG = CProg.new(<<-EOT, 'recvmmsg')
#{CONNECT}
#{recv_msghdr('msg1', 'iovec1')}
#{recv_msghdr('msg2', 'iovec2')}
#{MMSGHDR}
#{send_http_get}
	if (recvmmsg(sock, mmsg, 2, 0, NULL) < 0) {
    fprintf(stderr, "recvmmsg() failed: %s\\n.", strerror(errno));
		return(EXIT_FAILURE);
  }
EOT

RECVMMSG_DGRAM = CProg.new(<<-EOT, 'recvmmsg_dgram')
#{CONNECT_DGRAM}
#{recv_msghdr('msg1', 'iovec1')}
#{recv_msghdr('msg2', 'iovec2')}
#{MMSGHDR}
  fcntl(sock, F_SETFL, O_NONBLOCK);
	if (recvmmsg(sock, mmsg, 2, 0, NULL) != -1)
		return(EXIT_FAILURE);
EOT

RECVMMSG_FAIL = CProg.new(<<-EOT, 'recvmmsg_fail')
#{CONNECT}
#{recv_msghdr('msg1', 'iovec1')}
#{recv_msghdr('msg2', 'iovec2')}
#{MMSGHDR}
#{send_http_get}
	if (recvmmsg(sock, mmsg, 2, -1, NULL) != -1)
		return(EXIT_FAILURE);
EOT

GETSOCKNAME = CProg.new(<<-EOT, 'getsockname')
#{CONNECT}
  struct sockaddr_storage sa;
  socklen_t sa_len = sizeof(sa);

	if (getsockname(sock, (struct sockaddr *)&sa, &sa_len) < 0) {
    fprintf(stderr, "getsockname() failed: %s\\n.", strerror(errno));
		return(EXIT_FAILURE);
  }
EOT

GETSOCKNAME_DGRAM = CProg.new(<<-EOT, 'getsockname_dgram')
#{CONNECT_DGRAM}
  struct sockaddr_storage sa;
  socklen_t sa_len = sizeof(sa);

	if (getsockname(sock, (struct sockaddr *)&sa, &sa_len) < 0) {
    fprintf(stderr, "getsockname() failed: %s\\n.", strerror(errno));
		return(EXIT_FAILURE);
  }
EOT

GETSOCKNAME_FAIL = CProg.new(<<-EOT, 'getsockname_fail')
#{CONNECT}
  struct sockaddr_storage sa;
  socklen_t sa_len = -1;
  if (getsockname(sock, (struct sockaddr *)&sa, &sa_len) != -1)
    return(EXIT_FAILURE);
EOT

GETPEERNAME = CProg.new(<<-EOT, 'getpeername')
#{CONNECT}
  struct sockaddr_storage sa;
  socklen_t sa_len = sizeof(sa);

	if (getpeername(sock, (struct sockaddr *)&sa, &sa_len) < 0) {
    fprintf(stderr, "getpeername() failed: %s\\n.", strerror(errno));
		return(EXIT_FAILURE);
  }
EOT

GETPEERNAME_DGRAM = CProg.new(<<-EOT, 'getpeername_dgram')
#{CONNECT_DGRAM}
  struct sockaddr_storage sa;
  socklen_t sa_len = sizeof(sa);

	if (getpeername(sock, (struct sockaddr *)&sa, &sa_len) < 0) {
    fprintf(stderr, "getpeername() failed: %s\\n.", strerror(errno));
		return(EXIT_FAILURE);
  }
EOT

GETPEERNAME_FAIL = CProg.new(<<-EOT, 'getpeername_fail')
#{CONNECT}
  struct sockaddr_storage sa;
  socklen_t sa_len = -1;
  if (getpeername(sock, (struct sockaddr *)&sa, &sa_len) != -1)
    return(EXIT_FAILURE);
EOT

SOCKATMARK = CProg.new(<<-EOT, 'sockatmark')
#{CONNECT}
	if (sockatmark(sock) < 0) {
    fprintf(stderr, "sockatmark() failed: %s\\n.", strerror(errno));
		return(EXIT_FAILURE);
  }
EOT

ISFDTYPE = CProg.new(<<-EOT, 'isfdtype')
#{SOCKET}
	if (isfdtype(sock, S_IFSOCK) < 0) {
    fprintf(stderr, "isfdtype() failed: %s\\n.", strerror(errno));
		return(EXIT_FAILURE);
  }
EOT

ISFDTYPE_DGRAM = CProg.new(<<-EOT, 'isfdtype_dgram')
#{SOCKET_DGRAM}
	if (isfdtype(sock, S_IFSOCK) < 0) {
    fprintf(stderr, "isfdtype() failed: %s\\n.", strerror(errno));
		return(EXIT_FAILURE);
  }
EOT

ISFDTYPE_FAIL = CProg.new(<<-EOT, 'isfdtype_fail')
#{CONNECT}
  if (isfdtype(42, S_IFSOCK) != -1)
    return(EXIT_FAILURE);
EOT

WRITE = CProg.new(<<-EOT, 'write')
#{CONNECT}
  int data = 42;
  if (write(sock, &data, sizeof(data)) < 0) {
    fprintf(stderr, "write() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

WRITE_DGRAM = CProg.new(<<-EOT, 'write_dgram')
#{CONNECT_DGRAM}
  int data = 42;
  if (write(sock, &data, sizeof(data)) < 0) {
    fprintf(stderr, "write() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

WRITE_FAIL = CProg.new(<<-EOT, 'write_fail')
#{CONNECT}
  int data = 42;
  if (write(sock, &data, -1) != -1)
    return(EXIT_FAILURE);
EOT

READ = CProg.new(<<-EOT, 'read')
#{CONNECT}
#{send_http_get}
  char buf[42];
  if (read(sock, &buf, sizeof(buf)) < 0) {
    fprintf(stderr, "read() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

READ_DGRAM = CProg.new(<<-EOT, 'read_dgram')
#{SOCKET_DGRAM}
  fcntl(sock, F_SETFL, O_NONBLOCK);
  char buf[42];
  if (read(sock, &buf, sizeof(buf)) != -1)
    return(EXIT_FAILURE);
EOT

READ_FAIL = CProg.new(<<-EOT, 'read_fail')
#{CONNECT}
  fcntl(sock, F_SETFL, O_NONBLOCK);
  char buf[42];
  if (read(sock, &buf, -1) != -1)
    return(EXIT_FAILURE);
EOT

CLOSE = CProg.new(<<-EOT, 'close')
#{SOCKET}
  if (close(sock) < 0) {
    fprintf(stderr, "close() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

CLOSE_DGRAM = CProg.new(<<-EOT, 'close_dgram')
#{SOCKET_DGRAM}
  if (close(sock) < 0) {
    fprintf(stderr, "close() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

CLOSE_FAIL = CProg.new(<<-EOT, 'close_fail')
  if (close(42) != -1)
    return(EXIT_FAILURE);
EOT

DUP = CProg.new(<<-EOT, 'dup')
#{SOCKET}
  if (dup(sock) < 0) {
    fprintf(stderr, "dup() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

DUP_DGRAM = CProg.new(<<-EOT, 'dup_dgram')
#{SOCKET_DGRAM}
  if (dup(sock) < 0) {
    fprintf(stderr, "dup() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

DUP_FAIL = CProg.new(<<-EOT, 'dup_fail')
#{SOCKET}
  if (dup(42) != -1)
    return(EXIT_FAILURE);
EOT

DUP2 = CProg.new(<<-EOT, 'dup2')
#{SOCKET}
  if (dup2(sock, 42) < 0) {
    fprintf(stderr, "dup2() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

DUP2_DGRAM = CProg.new(<<-EOT, 'dup2_dgram')
#{SOCKET_DGRAM}
  if (dup2(sock, 42) < 0) {
    fprintf(stderr, "dup2() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

DUP2_FAIL = CProg.new(<<-EOT, 'dup2_fail')
#{SOCKET}
  if (dup2(sock, 9999999) != -1)
    return(EXIT_FAILURE);
EOT

DUP3 = CProg.new(<<-EOT, 'dup3')
#{SOCKET}
  if (dup3(sock, 42, O_CLOEXEC) < 0) {
    fprintf(stderr, "dup3() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

DUP3_DGRAM = CProg.new(<<-EOT, 'dup3_dgram')
#{SOCKET_DGRAM}
  if (dup3(sock, 42, O_CLOEXEC) < 0) {
    fprintf(stderr, "dup3() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

DUP3_FAIL = CProg.new(<<-EOT, 'dup3_fail')
#{SOCKET}
  if (dup3(sock, 999999, O_CLOEXEC) != -1)
    return(EXIT_FAILURE);
EOT

FORK = CProg.new(<<-EOT, 'fork')
#{SOCKET}
  pid_t pid;
  pid = fork();
  if (pid < 0) return (EXIT_FAILURE);
  if (pid == 0) { // Child
  #{SOCKET}
  } else { // Parent
    int status;
    waitpid(pid, &status, 0);
  }
EOT

WRITEV = CProg.new(<<-EOT, 'writev')
#{CONNECT}
#{write_iovec}
  if (writev(sock, iovec, sizeof(iovec)/sizeof(struct iovec)) < 0) {
    fprintf(stderr, "writev() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

WRITEV_DGRAM = CProg.new(<<-EOT, 'writev_dgram')
#{CONNECT_DGRAM}
#{write_iovec}
  if (writev(sock, iovec, sizeof(iovec)/sizeof(struct iovec)) < 0) {
    fprintf(stderr, "writev() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

WRITEV_FAIL = CProg.new(<<-EOT, 'writev_fail')
#{CONNECT}
#{write_iovec}
  if (writev(sock, iovec, -1) != -1)
    return(EXIT_FAILURE);
EOT

READV = CProg.new(<<-EOT, 'readv')
#{CONNECT}
#{send_http_get}
#{read_iovec}
  if (readv(sock, iovec, sizeof(iovec)/sizeof(struct iovec)) < 0) {
    fprintf(stderr, "readv() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

READV_DGRAM = CProg.new(<<-EOT, 'readv_dgram')
#{SOCKET_DGRAM}
#{read_iovec}
  fcntl(sock, F_SETFL, O_NONBLOCK);
  if (readv(sock, iovec, sizeof(iovec)/sizeof(struct iovec)) != -1)
    return(EXIT_FAILURE);
EOT

READV_FAIL = CProg.new(<<-EOT, 'readv_fail')
#{CONNECT}
#{send_http_get}
#{read_iovec}
  if (readv(sock, iovec, -1) != -1)
    return(EXIT_FAILURE);
EOT

IOCTL = CProg.new(<<-EOT, 'ioctl')
#{CONNECT}
#{send_http_get}
  int bytes;
  if (ioctl(sock, FIONREAD, &bytes) < 0) {
    fprintf(stderr, "ioctl() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

IOCTL_DGRAM = CProg.new(<<-EOT, 'ioctl_dgram')
#{SOCKET_DGRAM}
  int bytes;
  if (ioctl(sock, FIONREAD, &bytes) < 0) {
    fprintf(stderr, "ioctl() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

IOCTL_FAIL = CProg.new(<<-EOT, 'ioctl_fail')
#{SOCKET}
  int bytes;
  if (ioctl(sock, 42, &bytes) != -1)
    return(EXIT_FAILURE);
EOT

SENDFILE = CProg.new(<<-EOT, 'sendfile')
#{CONNECT}
  int fd = open("./c_programs/sendfile.c", O_RDONLY);
  if (sendfile(sock, fd, NULL, 10) < 0) {
    fprintf(stderr, "sendfile() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

SENDFILE_DGRAM = CProg.new(<<-EOT, 'sendfile_dgram')
#{CONNECT_DGRAM}
  int fd = open("./c_programs/sendfile_dgram.c", O_RDONLY);
  if (sendfile(sock, fd, NULL, 10) < 0) {
    fprintf(stderr, "sendfile() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

SENDFILE_FAIL = CProg.new(<<-EOT, 'sendfile_fail')
#{SOCKET}
  if (sendfile(sock, 42, NULL, 10) != -1)
    return(EXIT_FAILURE);
EOT

def two_sockets(type, proto)
  <<-EOT
  int sock1, sock2;
  if ((sock1 = socket(AF_INET, #{type}, #{proto})) < 0)
    return(EXIT_FAILURE);
  if ((sock2 = socket(AF_INET, #{type}, #{proto})) < 0)
    return(EXIT_FAILURE);
  EOT
end

def pollfds
  <<-EOT
  struct pollfd pollfds[2];
  pollfds[0].fd = sock1;
  pollfds[0].events = POLLHUP;
  pollfds[1].fd = sock2;
  pollfds[1].events = POLLIN;
  EOT
end

POLL = CProg.new(<<-EOT, 'poll')
#{two_sockets('SOCK_STREAM', 'IPPROTO_TCP')}
#{pollfds}
  if (poll(pollfds, sizeof(pollfds)/sizeof(struct pollfd), 1) < 0) {
    fprintf(stderr, "poll() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

POLL_DGRAM = CProg.new(<<-EOT, 'poll_dgram')
#{two_sockets('SOCK_DGRAM', 'IPPROTO_UDP')}
#{pollfds}
  if (poll(pollfds, sizeof(pollfds)/sizeof(struct pollfd), 1) < 0) {
    fprintf(stderr, "poll() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

def timespec
  <<-EOT
  struct timespec timeout;
  timeout.tv_sec = 1;
  timeout.tv_nsec = 1000;
  EOT
end

PPOLL = CProg.new(<<-EOT, 'ppoll')
#{two_sockets('SOCK_STREAM', 'IPPROTO_TCP')}
#{pollfds}
#{timespec}
  if (ppoll(pollfds, sizeof(pollfds)/sizeof(struct pollfd), &timeout, NULL) < 0) {
    fprintf(stderr, "ppoll() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

PPOLL_DGRAM = CProg.new(<<-EOT, 'ppoll_dgram')
#{two_sockets('SOCK_DGRAM', 'IPPROTO_UDP')}
#{pollfds}
#{timespec}
  if (ppoll(pollfds, sizeof(pollfds)/sizeof(struct pollfd), &timeout, NULL) < 0) {
    fprintf(stderr, "ppoll() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

def fdset
  <<-EOT
  fd_set fdset;
  FD_ZERO(&fdset);
  FD_SET(sock1, &fdset);
  FD_SET(sock2, &fdset);
  EOT
end

def timeval
  <<-EOT
  struct timeval timeout;
  timeout.tv_sec = 1;
  timeout.tv_usec = 1;
  EOT
end

SELECT = CProg.new(<<-EOT, 'select')
#{two_sockets('SOCK_STREAM', 'IPPROTO_TCP')}
#{fdset}
#{timeval}
  if (select(sock2+1, &fdset, NULL, NULL, &timeout) < 0) {
    fprintf(stderr, "select() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

SELECT_DGRAM = CProg.new(<<-EOT, 'select_dgram')
#{two_sockets('SOCK_DGRAM', 'IPPROTO_UDP')}
#{fdset}
#{timeval}
  if (select(sock2+1, &fdset, NULL, NULL, &timeout) < 0) {
    fprintf(stderr, "select() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

SELECT_FAIL = CProg.new(<<-EOT, 'select_fail')
#{two_sockets('SOCK_STREAM', 'IPPROTO_TCP')}
#{fdset}
#{timeval}
  close(sock2);
  if (select(sock2+1, &fdset, NULL, NULL, &timeout) != -1)
    return(EXIT_FAILURE);
EOT

PSELECT = CProg.new(<<-EOT, 'pselect')
#{two_sockets('SOCK_STREAM', 'IPPROTO_TCP')}
#{fdset}
#{timespec}
  if (pselect(sock2+1, &fdset, NULL, NULL, &timeout, NULL) < 0) {
    fprintf(stderr, "pselect() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

PSELECT_DGRAM = CProg.new(<<-EOT, 'pselect_dgram')
#{two_sockets('SOCK_STREAM', 'IPPROTO_TCP')}
#{fdset}
#{timespec}
  if (pselect(sock2+1, &fdset, NULL, NULL, &timeout, NULL) < 0) {
    fprintf(stderr, "pselect() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

PSELECT_FAIL = CProg.new(<<-EOT, 'pselect_fail')
#{two_sockets('SOCK_STREAM', 'IPPROTO_TCP')}
#{fdset}
#{timespec}
  close(sock2);
  if (pselect(sock2+1, &fdset, NULL, NULL, &timeout, NULL) != -1)
    return(EXIT_FAILURE);
EOT

FCNTL = CProg.new(<<-EOT, 'fcntl')
#{SOCKET}
  if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
    fprintf(stderr, "fcntl() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

FCNTL_DGRAM  = CProg.new(<<-EOT, 'fcntl_dgram')
#{SOCKET_DGRAM}
  if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
    fprintf(stderr, "fcntl() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

FCNTL_FAIL  = CProg.new(<<-EOT, 'fcntl_fail')
#{SOCKET}
  if (fcntl(42, F_SETFL) != -1)
    return(EXIT_FAILURE);
EOT

EPOLL_CTL = CProg.new(<<-EOT, 'epoll_ctl')
#{SOCKET}
  int efd = epoll_create1(0);
  struct epoll_event event;
  event.data.fd = sock;
  event.events = EPOLLIN|EPOLLOUT;
  if (epoll_ctl(efd, EPOLL_CTL_ADD, sock, &event) < 0) {
    fprintf(stderr, "epoll_ctl() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

EPOLL_CTL_DGRAM = CProg.new(<<-EOT, 'epoll_ctl_dgram')
#{SOCKET_DGRAM}
  int efd = epoll_create1(0);
  struct epoll_event event;
  event.data.fd = sock;
  event.events = EPOLLIN|EPOLLOUT;
  if (epoll_ctl(efd, EPOLL_CTL_ADD, sock, &event) < 0) {
    fprintf(stderr, "epoll_ctl() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

EPOLL_CTL_FAIL = CProg.new(<<-EOT, 'epoll_ctl_fail')
#{SOCKET}
  int efd = epoll_create1(0);
  struct epoll_event event;
  event.data.fd = sock;
  event.events = EPOLLIN|EPOLLOUT;
  if (epoll_ctl(efd, EPOLL_CTL_MOD, sock, &event) == 0)
    return(EXIT_FAILURE);
EOT

EPOLL_WAIT = CProg.new(<<-EOT, 'epoll_wait')
#{EPOLL_CTL}
  struct epoll_event events[2];
  if (epoll_wait(efd, events, 2, 0) < 0) {
    fprintf(stderr, "epoll_wait() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

EPOLL_WAIT_DGRAM = CProg.new(<<-EOT, 'epoll_wait_dgram')
#{EPOLL_CTL_DGRAM}
  struct epoll_event events[2];
  if (epoll_wait(efd, events, 2, 0) < 0) {
    fprintf(stderr, "epoll_wait() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

EPOLL_WAIT_FAIL = CProg.new(<<-EOT, 'epoll_wait_fail')
#{EPOLL_CTL}
  struct epoll_event events[2];
  if (epoll_wait(efd, events, -1, 0) != -1)
    return(EXIT_FAILURE);
EOT

EPOLL_PWAIT = CProg.new(<<-EOT, 'epoll_pwait')
#{EPOLL_CTL}
  struct epoll_event events[2];
  if (epoll_pwait(efd, events, 2, 0, NULL) < 0) {
    fprintf(stderr, "epoll_pwait() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

EPOLL_PWAIT_DGRAM = CProg.new(<<-EOT, 'epoll_pwait_dgram')
#{EPOLL_CTL_DGRAM}
  struct epoll_event events[2];
  if (epoll_pwait(efd, events, 2, 0, NULL) < 0) {
    fprintf(stderr, "epoll_pwait() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

EPOLL_PWAIT_FAIL = CProg.new(<<-EOT, 'epoll_pwait_fail')
#{EPOLL_CTL}
  struct epoll_event events[2];
  if (epoll_pwait(efd, events, -1, 0, NULL) != -1)
    return(EXIT_FAILURE);
EOT

FDOPEN = CProg.new(<<-EOT, 'fdopen')
#{SOCKET}
  if (fdopen(sock, "w") == NULL) {
    fprintf(stderr, "fdopen() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

FDOPEN_DGRAM = CProg.new(<<-EOT, 'fdopen_dgram')
#{SOCKET_DGRAM}
  if (fdopen(sock, "w") == NULL) {
    fprintf(stderr, "fdopen() failed: %s\\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
EOT

FDOPEN_FAIL = CProg.new(<<-EOT, 'fdopen_fail')
#{SOCKET}
  if (fdopen(sock, "Z") != NULL)
    return(EXIT_FAILURE);
EOT


CONSECUTIVE_CONNECTIONS = CProg.new(<<-EOT, 'consecutive_connections')
  int sock1, sock2;
  if ((sock1 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    return(EXIT_FAILURE);
  close(sock1);
  if ((sock2 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    return(EXIT_FAILURE);
  close(sock2);
EOT

CONCURRENT_CONNECTIONS = CProg.new(<<-EOT, 'concurrent_connections')
  int sock1, sock2;
  if ((sock1 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    return(EXIT_FAILURE);
  if ((sock2 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    return(EXIT_FAILURE);
  close(sock1);
  close(sock2);
EOT
