PKT_SOCKET_STREAM = <<-EOT
  0 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3 
EOT

PKT_SOCKET_DGRAM = <<-EOT
  0 socket(..., SOCK_DGRAM, IPPROTO_UDP) = 3 
EOT

PKT_SOCKET_INV = <<-EOT
  0 socket(..., -42, 0) = -1 
EOT

PKT_BIND_STREAM= <<-EOT
  #{PKT_SOCKET_STREAM}
  +0 bind(3, ..., ...) = 0
EOT

PKT_BIND_DGRAM = <<-EOT
  #{PKT_SOCKET_DGRAM}
  +0 bind(3, ..., ...) = 0 
EOT

PKT_CONNECT_STREAM= <<-EOT
  #{PKT_SOCKET_STREAM}
  0.0...0.1 connect(3, ..., ...) = 0
  *  > S  0:0(0) <...>
  +0 < S. 0:0(0) ack 1 win 1000
  *  > .  1:1(0) ack 1
EOT

PKT_CONNECT_DGRAM = <<-EOT
  #{PKT_SOCKET_DGRAM}
  +0 connect(3, ..., ...) = 0
EOT

PKT_SHUTDOWN_STREAM = <<-EOT
  #{PKT_CONNECT_STREAM}
  +0 shutdown(3, SHUT_RD) = 0
  +0 shutdown(3, SHUT_WR) = 0
EOT

PKT_SHUTDOWN_DGRAM = <<-EOT
  #{PKT_CONNECT_DGRAM}
  +0 shutdown(3, SHUT_RD) = 0
  +0 shutdown(3, SHUT_WR) = 0
EOT

PKT_LISTEN_STREAM = <<-EOT
  #{PKT_SOCKET_STREAM}
  +0 listen(3, 1) = 0
EOT

PKT_SETSOCKOPT_STREAM = <<-EOT
  #{PKT_SOCKET_STREAM}
  +0 setsockopt(3, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0
EOT

PKT_SETSOCKOPT_DGRAM = <<-EOT
  #{PKT_SOCKET_DGRAM}
  +0 setsockopt(3, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0
EOT

PKT_SEND_STREAM = <<-EOT
  #{PKT_CONNECT_STREAM}
  +0 send(3, ..., 100, 0) = 100
EOT

PKT_SEND_DGRAM = <<-EOT
  #{PKT_CONNECT_DGRAM}
  +0 send(3, ..., 100, 0) = 100
EOT

PKT_RECV_STREAM = <<-EOT
  #{PKT_CONNECT_STREAM}
  +0 < P. 1:1001(1000) ack 1 win 1000
  +0 recv(3, ..., 1000, 0) = 1000
EOT

PKT_RECV_DGRAM = <<-EOT
  #{PKT_CONNECT_DGRAM}
  +0 fcntl(3, F_SETFL, O_RDWR|O_NONBLOCK) = 0
  +0 recv(3, ..., 1000, 0) = -1
EOT

PKT_SENDTO_STREAM = <<-EOT
  #{PKT_CONNECT_STREAM}
  +0 sendto(3, ..., 100, 0, ..., ...) = 100
EOT

PKT_SENDTO_DGRAM = <<-EOT
  #{PKT_SOCKET_DGRAM}
  +0 sendto(3, ..., 100, 0, ..., ...) = 100
EOT

PKT_RECVFROM_STREAM = <<-EOT
  #{PKT_CONNECT_STREAM}
  +0 < P. 1:1001(1000) ack 1 win 1000
  +0 recvfrom(3, ..., 1000, 0, ..., ...) = 1000
EOT

PKT_RECVFROM_DGRAM = <<-EOT
  #{PKT_SOCKET_DGRAM}
  +0 fcntl(3, F_SETFL, O_RDWR|O_NONBLOCK) = 0
  +0 recvfrom(3, ..., 100, 0, ..., ...) = -1
EOT

PKT_WRITE_STREAM = <<-EOT
  #{PKT_CONNECT_STREAM}
  +0 write(3, ..., 100) = 100
EOT

PKT_WRITE_DGRAM = <<-EOT
  #{PKT_CONNECT_DGRAM}
  +0 write(3, ..., 100) = 100
EOT

PKT_READ_STREAM = <<-EOT
  #{PKT_CONNECT_STREAM}
  +0 < P. 1:1001(1000) ack 1 win 1000
  +0 read(3, ..., 1000) = 1000
EOT

PKT_READ_DGRAM = <<-EOT
  #{PKT_SOCKET_DGRAM}
  +0 fcntl(3, F_SETFL, O_RDWR|O_NONBLOCK) = 0
  +0 read(3, ..., 1000) = -1
EOT

PKT_CLOSE_STREAM = <<-EOT
  #{PKT_SOCKET_STREAM}
  +0 close(3) = 0
EOT

PKT_CLOSE_DGRAM = <<-EOT
  #{PKT_SOCKET_DGRAM}
  +0 close(3) = 0
EOT

PKT_CONNECTED_SOCK_STREAM = PKT_CONNECT_STREAM


