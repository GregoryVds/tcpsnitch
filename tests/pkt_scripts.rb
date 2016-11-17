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


PKT_BIND_STREAM= <<-EOT
  #{PKT_SOCKET_STREAM}
  +0 bind(3, ..., ...) = 0
EOT

PKT_BIND_DGRAM = <<-EOT
  #{PKT_SOCKET_DGRAM}
  +0 bind(3, ..., ...) = 0 
EOT


PKT_CONNECTED_SOCK_STREAM = PKT_CONNECT_STREAM


