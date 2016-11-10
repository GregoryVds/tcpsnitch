# Purpose: test that all libc overrides do not crash the main process.

require 'minitest/autorun'
require 'minitest/reporters'
require 'minitest/spec'
require './common.rb'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

describe "libc overrides" do
  let(:connected_sock_stream) {
    <<-EOT
        0 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3 
        0.0...0.1 connect(3, ..., ...) = 0
        *  > S  0:0(0) <...>
        +0 < S. 0:0(0) ack 1 win 1000
        *  > .  1:1(0) ack 1
    EOT
  }

=begin
  ____   ___   ____ _  _______ _____      _    ____ ___
 / ___| / _ \ / ___| |/ / ____|_   _|    / \  |  _ \_ _|
 \___ \| | | | |   | ' /|  _|   | |     / _ \ | |_) | |
  ___) | |_| | |___| . \| |___  | |    / ___ \|  __/| |
 |____/ \___/ \____|_|\_\_____| |_|   /_/   \_\_|  |___|

 sys/socket.h - Internet Protocol family

 functions: socket(), bind(), connect(), shutdown(), listen(), getsockopt(),
 setsockopt(), send(), sendto(), sendmsg(), recv(), recvfrom(), recvmsg(),

=end

  describe "when calling socket()" do
    it "socket() should not crash with SOCK_STREAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_STREAM, 0) = 3 
      EOT
    end

    it "socket() should not crash with SOCK_DGRAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_DGRAM, 0) = 3 
      EOT
    end

    it "should not crash with failing socket()" do
      skip
      assert run_pkt_script(<<-EOT)
        0 socket(..., -42, 0) = -1 
      EOT
    end
  end

  describe "when calling bind()" do
        it "bind() should not crash with SOCK_STREAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3 
        +0 bind(3, ..., ...) = 0
      EOT
    end

    it "bind() should not crash with SOCK_DGRAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_DGRAM, IPPROTO_UDP) = 3 
        +0 bind(3, ..., ...) = 0
      EOT
    end

    it "should not crash with failing bind()" do
      skip
    end
  end

  describe "when calling connect()" do
    it "connect() should not crash with SOCK_STREAM" do
      assert run_pkt_script(connected_sock_stream)
    end

    it "connect() should not crash with SOCK_DGRAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_DGRAM, IPPROTO_UDP) = 3 
        +0 connect(3, ..., ...) = 0
      EOT
    end

    it "should not crash with failing connect()" do
      skip
    end
  end

  describe "when calling shutdown()" do
    it "shutdown() should not crash with SOCK_STREAM" do
      assert run_pkt_script(<<-EOT)
        #{connected_sock_stream}
        +0 shutdown(3, SHUT_RD) = 0
        +0 shutdown(3, SHUT_WR) = 0
      EOT
    end
    
    it "shutdown() should not crash with SOCK_DGRAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_DGRAM, IPPROTO_UDP) = 3 
        +0 connect(3, ..., ...) = 0

        +0 shutdown(3, SHUT_RD) = 0
        +0 shutdown(3, SHUT_WR) = 0
      EOT
    end

    it "should not crash with failing shutdown()" do
      skip
    end
  end

  describe "when calling listen()" do
    it "listen() should not crash with SOCK_STREAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3 
        +0 listen(3, 1) = 0
      EOT
    end

    it "should not crash with failing listen()" do
      skip
    end
  end

  describe "when calling setsockopt()" do
    it "setsockopt() should not crash with SOCK_STREAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3 
        +0 setsockopt(3, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0
      EOT
    end
    
    it "setsockopt() should not crash with SOCK_DGRAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_DGRAM, IPPROTO_UDP) = 3 
        +0 setsockopt(3, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0
      EOT
    end

    it "should not crash with failing setsockopt()" do
      skip
    end
  end

  describe "when calling send()" do
    it "send() should not crash with SOCK_STREAM" do
      assert run_pkt_script(<<-EOT)
        #{connected_sock_stream} 
        +0 send(3, ..., 100, 0) = 100
      EOT
    end

    it "connect() should not crash with SOCK_DGRAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_DGRAM, IPPROTO_UDP) = 3 
        +0 connect(3, ..., ...) = 0
        +0 send(3, ..., 100, 0) = 100
      EOT
    end

    it "should not crash with failing send()" do
      skip
    end
  end

  describe "when calling recv()" do
    it "recv() should not crash with SOCK_STREAM" do
      assert run_pkt_script(<<-EOT)
        #{connected_sock_stream} 
        +0 < P. 1:1001(1000) ack 1 win 1000
        +0 recv(3, ..., 1000, 0) = 1000
      EOT
    end

    it "recv() should not crash with SOCK_DGRAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_DGRAM, IPPROTO_UDP) = 3 
        +0 fcntl(3, F_SETFL, O_RDWR|O_NONBLOCK) = 0
        +0 recv(3, ..., 1000, 0) = -1
      EOT
    end

    it "should not crash with failing recv()" do
      skip
    end
  end

  describe "when calling sendto()" do
    it "sendto() should not crash with SOCK_STREAM" do
      assert run_pkt_script(<<-EOT)
        #{connected_sock_stream} 
        +0 sendto(3, ..., 100, 0, ..., ...) = 100
      EOT
    end

    it "sendto() should not crash with SOCK_DGRAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_DGRAM, IPPROTO_UDP) = 3 
        +0 sendto(3, ..., 100, 0, ..., ...) = 100
      EOT
    end

    it "should not crash with failing sendto()" do
      skip
    end
  end

  describe "when calling recvfrom()" do
    it "recvfrom() should not crash with SOCK_STREAM" do
      assert run_pkt_script(<<-EOT)
        #{connected_sock_stream} 
        +0 < P. 1:1001(1000) ack 1 win 1000
        +0 recvfrom(3, ..., 1000, 0, ..., ...) = 1000
      EOT
    end

    it "recvfrom() should not crash with SOCK_DGRAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_DGRAM, IPPROTO_UDP) = 3 
        +0 fcntl(3, F_SETFL, O_RDWR|O_NONBLOCK) = 0
        +0 recvfrom(3, ..., 100, 0, ..., ...) = -1
      EOT
    end

    it "should not crash with failing recvfrom()" do
      skip
    end
  end

  describe "when calling sendmsg()" do
    it "sendmsg() should not crash with SOCK_STREAM" do
      skip
    end

    it "sendmsg() should not crash with SOCK_DGRAM" do
      skip
    end

    it "should not crash with failing sendmsg()" do
      skip
    end
  end

  describe "when calling recvmsg()" do
    it "recvmsg() should not crash with SOCK_STREAM" do
      skip
    end

    it "recvmsg() should not crash with SOCK_DGRAM" do
      skip
    end

    it "should not crash with failing recvmsg()" do
      skip
    end
  end

=begin
  _   _ _   _ ___ ____ _____ ____       _    ____ ___
 | | | | \ | |_ _/ ___|_   _|  _ \     / \  |  _ \_ _|
 | | | |  \| || |\___ \ | | | | | |   / _ \ | |_) | |
 | |_| | |\  || | ___) || | | |_| |  / ___ \|  __/| |
  \___/|_| \_|___|____/ |_| |____/  /_/   \_\_|  |___|

 unistd.h - standard symbolic constants and types

 functions: close(), write(), read().

=end

  describe "when calling close()" do
    it "close() should not crash with SOCK_STREAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_STREAM, 0) = 3 
        +0 close(3) = 0
      EOT
    end

    it "close() should not crash with SOCK_DGRAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_DGRAM, 0) = 3 
        +0 close(3) = 0
      EOT
    end

    it "should not crash with failing close()" do
      skip
    end
  end

  describe "when calling write()" do
    it "write() should not crash with SOCK_STREAM" do
      assert run_pkt_script(<<-EOT)
        #{connected_sock_stream} 
        +0 write(3, ..., 100) = 100
      EOT
    end

    it "connect() should not crash with SOCK_DGRAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_DGRAM, IPPROTO_UDP) = 3 
        +0 connect(3, ..., ...) = 0
        +0 write(3, ..., 100) = 100
      EOT
    end

    it "should not crash with failing write()" do
      skip
    end
  end

  describe "when calling read()" do
    it "read() should not crash with SOCK_STREAM" do
      assert run_pkt_script(<<-EOT)
        #{connected_sock_stream} 
        +0 < P. 1:1001(1000) ack 1 win 1000
        +0 read(3, ..., 1000) = 1000
      EOT
    end

    it "read() should not crash with SOCK_DGRAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_DGRAM, IPPROTO_UDP) = 3 
        +0 fcntl(3, F_SETFL, O_RDWR|O_NONBLOCK) = 0
        +0 read(3, ..., 1000) = -1
      EOT
    end

    it "should not crash with failing read()" do
      skip
    end
  end

=begin
  _   _ ___ ___       _    ____ ___
 | | | |_ _/ _ \     / \  |  _ \_ _|
 | | | || | | | |   / _ \ | |_) | |
 | |_| || | |_| |  / ___ \|  __/| |
  \___/|___\___/  /_/   \_\_|  |___|

 sys/uio.h - definitions for vector I/O operations

 functions: writev(), readv()

=end

  describe "when calling writev()" do
    it "writev() should not crash with SOCK_STREAM" do
      skip
    end

    it "writev() should not crash with SOCK_DGRAM" do
      skip
    end

    it "should not crash with failing writev()" do
      skip
    end
  end

  describe "when calling readv()" do
    it "readv() should not crash with SOCK_STREAM" do
      skip
    end

    it "readv() should not crash with SOCK_DGRAM" do
      skip
    end

    it "should not crash with failing readv()" do
      skip
    end
  end

=begin
  ____  _____ _   _ ____  _____ ___ _     _____      _    ____ ___
 / ___|| ____| \ | |  _ \|  ___|_ _| |   | ____|    / \  |  _ \_ _|
 \___ \|  _| |  \| | | | | |_   | || |   |  _|     / _ \ | |_) | |
  ___) | |___| |\  | |_| |  _|  | || |___| |___   / ___ \|  __/| |
 |____/|_____|_| \_|____/|_|   |___|_____|_____| /_/   \_\_|  |___|

 sendfile - transfer data between file descriptors

 functions: sendfile()

=end

  describe "when calling sendfile()" do
    it "sendfile() should not crash with SOCK_STREAM" do
      skip
    end

    it "sendfile() should not crash with SOCK_DGRAM" do
      skip
    end

    it "should not crash with failing sendfile()" do
      skip
    end
  end

=begin
  ____   ___  _     _          _    ____ ___
 |  _ \ / _ \| |   | |        / \  |  _ \_ _|
 | |_) | | | | |   | |       / _ \ | |_) | |
 |  __/| |_| | |___| |___   / ___ \|  __/| |
 |_|    \___/|_____|_____| /_/   \_\_|  |___|

 poll.h - definitions for the poll() function

 functions: poll()

=end

  describe "when calling poll()" do
    it "poll() should not crash with SOCK_STREAM" do
      skip
    end

    it "poll() should not crash with SOCK_DGRAM" do
      skip
    end

    it "should not crash with failing poll()" do
      skip
    end
  end

end
