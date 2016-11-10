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

  before do
    reset_dir(DEFAULT_PATH) 
  end


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

  describe "when calling #{TCP_EV_SOCKET}" do
    it "#{TCP_EV_SOCKET} should be tracked with SOCK_STREAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_STREAM, 0) = 3 
      EOT
      assert_event_present(TCP_EV_SOCKET)
    end

    it "#{TCP_EV_SOCKET} should not crash with SOCK_DGRAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_DGRAM, 0) = 3 
      EOT
    end

    it "#{TCP_EV_SOCKET} should not crash when failing" do
      skip
      assert run_pkt_script(<<-EOT)
        0 socket(..., -42, 0) = -1 
      EOT
    end
  end

  describe "when calling #{TCP_EV_BIND}" do
    it "#{TCP_EV_BIND} should be tracked with SOCK_STREAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3 
        +0 bind(3, ..., ...) = 0
      EOT
      assert_event_present(TCP_EV_BIND)
    end

    it "#{TCP_EV_BIND} should not crash with SOCK_DGRAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_DGRAM, IPPROTO_UDP) = 3 
        +0 bind(3, ..., ...) = 0
      EOT
    end

    it "#{TCP_EV_BIND} should be tracked when failing" do
      skip
    end
  end

  describe "when calling #{TCP_EV_CONNECT}" do
    it "#{TCP_EV_CONNECT} should be tracked with SOCK_STREAM" do
      assert run_pkt_script(connected_sock_stream)
      assert_event_present(TCP_EV_CONNECT)
    end

    it "#{TCP_EV_CONNECT} should not crash with SOCK_DGRAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_DGRAM, IPPROTO_UDP) = 3 
        +0 connect(3, ..., ...) = 0
      EOT
    end

    it "#{TCP_EV_CONNECT} should be tracked when failing" do
      skip
    end
  end

  describe "when calling #{TCP_EV_SHUTDOWN}" do
    it "#{TCP_EV_SHUTDOWN} should be tracked with SOCK_STREAM" do
      assert run_pkt_script(<<-EOT)
        #{connected_sock_stream}
        +0 shutdown(3, SHUT_RD) = 0
        +0 shutdown(3, SHUT_WR) = 0
      EOT
      assert_event_present(TCP_EV_SHUTDOWN)
    end
    
    it "#{TCP_EV_SHUTDOWN} should not crash with SOCK_DGRAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_DGRAM, IPPROTO_UDP) = 3 
        +0 connect(3, ..., ...) = 0

        +0 shutdown(3, SHUT_RD) = 0
        +0 shutdown(3, SHUT_WR) = 0
      EOT
    end

    it "#{TCP_EV_SHUTDOWN} should be tracked when failing" do
      skip
    end
  end

  describe "when calling #{TCP_EV_LISTEN}" do
    it "#{TCP_EV_LISTEN} should be tracked with SOCK_STREAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3 
        +0 listen(3, 1) = 0
      EOT
      assert_event_present(TCP_EV_LISTEN)
    end

    it "#{TCP_EV_LISTEN} should be tracked when failing" do
      skip
    end
  end

  describe "when calling #{TCP_EV_SETSOCKOPT}" do
    it "#{TCP_EV_SETSOCKOPT} should be tracked with SOCK_STREAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3 
        +0 setsockopt(3, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0
      EOT
      assert_event_present(TCP_EV_SETSOCKOPT)
    end
    
    it "#{TCP_EV_SETSOCKOPT} should not crash with SOCK_DGRAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_DGRAM, IPPROTO_UDP) = 3 
        +0 setsockopt(3, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0
      EOT
    end

    it "#{TCP_EV_SETSOCKOPT} should be tracked when failing" do
      skip
    end
  end

  describe "when calling #{TCP_EV_SEND}" do
    it "#{TCP_EV_SEND} should be tracked with SOCK_STREAM" do
      assert run_pkt_script(<<-EOT)
        #{connected_sock_stream} 
        +0 send(3, ..., 100, 0) = 100
      EOT
      assert_event_present(TCP_EV_SEND)
    end

    it "#{TCP_EV_SEND} should not crash with SOCK_DGRAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_DGRAM, IPPROTO_UDP) = 3 
        +0 connect(3, ..., ...) = 0
        +0 send(3, ..., 100, 0) = 100
      EOT
    end

    it "#{TCP_EV_SEND} should be tracked when failing" do
      skip
    end
  end

  describe "when calling #{TCP_EV_RECV}" do
    it "#{TCP_EV_RECV} should be tracked with SOCK_STREAM" do
      assert run_pkt_script(<<-EOT)
        #{connected_sock_stream} 
        +0 < P. 1:1001(1000) ack 1 win 1000
        +0 recv(3, ..., 1000, 0) = 1000
      EOT
      assert_event_present(TCP_EV_RECV)
    end

    it "#{TCP_EV_RECV} should not crash with SOCK_DGRAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_DGRAM, IPPROTO_UDP) = 3 
        +0 fcntl(3, F_SETFL, O_RDWR|O_NONBLOCK) = 0
        +0 recv(3, ..., 1000, 0) = -1
      EOT
    end

    it "#{TCP_EV_RECV} should be tracked when failing" do
      skip
    end
  end

  describe "when calling #{TCP_EV_SENDTO}" do
    it "#{TCP_EV_SENDTO} should be tracked with SOCK_STREAM" do
      assert run_pkt_script(<<-EOT)
        #{connected_sock_stream} 
        +0 sendto(3, ..., 100, 0, ..., ...) = 100
      EOT
      assert_event_present(TCP_EV_SENDTO)
    end

    it "#{TCP_EV_SENDTO} should not crash with SOCK_DGRAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_DGRAM, IPPROTO_UDP) = 3 
        +0 sendto(3, ..., 100, 0, ..., ...) = 100
      EOT
    end

    it "#{TCP_EV_SENDTO} should be tracked when failing" do
      skip
    end
  end

  describe "when calling #{TCP_EV_RECVFROM}" do
    it "#{TCP_EV_RECVFROM} should be tracked with SOCK_STREAM" do
      assert run_pkt_script(<<-EOT)
        #{connected_sock_stream} 
        +0 < P. 1:1001(1000) ack 1 win 1000
        +0 recvfrom(3, ..., 1000, 0, ..., ...) = 1000
      EOT
      assert_event_present(TCP_EV_RECVFROM)
    end

    it "#{TCP_EV_RECVFROM} should not crash with SOCK_DGRAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_DGRAM, IPPROTO_UDP) = 3 
        +0 fcntl(3, F_SETFL, O_RDWR|O_NONBLOCK) = 0
        +0 recvfrom(3, ..., 100, 0, ..., ...) = -1
      EOT
    end

    it "#{TCP_EV_RECVFROM} should be tracked when failing" do
      skip
    end
  end

  describe "when calling #{TCP_EV_SENDMSG}" do
    it "#{TCP_EV_SENDMSG} should be tracked with SOCK_STREAM" do
      skip
    end

    it "#{TCP_EV_SENDMSG} should not crash with SOCK_DGRAM" do
      skip
    end

    it "#{TCP_EV_SENDMSG} should be tracked when failing" do
      skip
    end
  end

  describe "when calling #{TCP_EV_RECVMSG}" do
    it "#{TCP_EV_RECVMSG} should be tracked with SOCK_STREAM" do
      skip
    end

    it "#{TCP_EV_RECVMSG} should not crash with SOCK_DGRAM" do
      skip
    end

    it "#{TCP_EV_RECVMSG} should be tracked when failing" do
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

  describe "when calling #{TCP_EV_CLOSE}" do
    it "#{TCP_EV_CLOSE} should be tracked with SOCK_STREAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_STREAM, 0) = 3 
        +0 close(3) = 0
      EOT
      assert_event_present(TCP_EV_CLOSE)
    end

    it "#{TCP_EV_CLOSE} should not crash with SOCK_DGRAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_DGRAM, 0) = 3 
        +0 close(3) = 0
      EOT
    end

    it "#{TCP_EV_CLOSE} should be tracked when failing" do
      skip
    end
  end

  describe "when calling #{TCP_EV_WRITE}" do
    it "#{TCP_EV_WRITE} should be tracked with SOCK_STREAM" do
      assert run_pkt_script(<<-EOT)
        #{connected_sock_stream} 
        +0 write(3, ..., 100) = 100
      EOT
      assert_event_present(TCP_EV_WRITE)
    end

    it "#{TCP_EV_WRITE} should not crash with SOCK_DGRAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_DGRAM, IPPROTO_UDP) = 3 
        +0 connect(3, ..., ...) = 0
        +0 write(3, ..., 100) = 100
      EOT
    end

    it "#{TCP_EV_WRITE} should be tracked when failing" do
      skip
    end
  end

  describe "when calling #{TCP_EV_READ}" do
    it "#{TCP_EV_READ} should be tracked with SOCK_STREAM" do
      assert run_pkt_script(<<-EOT)
        #{connected_sock_stream} 
        +0 < P. 1:1001(1000) ack 1 win 1000
        +0 read(3, ..., 1000) = 1000
      EOT
      assert_event_present(TCP_EV_READ)
    end

    it "#{TCP_EV_READ} should not crash with SOCK_DGRAM" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_DGRAM, IPPROTO_UDP) = 3 
        +0 fcntl(3, F_SETFL, O_RDWR|O_NONBLOCK) = 0
        +0 read(3, ..., 1000) = -1
      EOT
    end

    it "#{TCP_EV_READ} should be tracked when failing" do
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

  describe "when calling #{TCP_EV_WRITEV}" do
    it "#{TCP_EV_WRITEV} should be tracked with SOCK_STREAM" do
      skip
    end

    it "#{TCP_EV_WRITEV} should not crash with SOCK_DGRAM" do
      skip
    end

    it "#{TCP_EV_WRITEV} should be tracked when failing" do
      skip
    end
  end

  describe "when calling #{TCP_EV_READV}" do
    it "#{TCP_EV_READV} should be tracked with SOCK_STREAM" do
      skip
    end

    it "#{TCP_EV_READV} should not crash with SOCK_DGRAM" do
      skip
    end

    it "#{TCP_EV_READV} should be tracked when failing" do
      skip
    end
  end

=begin
  ____  _____ _   _ ____  _____ ___ _     _____      _    ____ ___
 / ___|| ____| \ | |  _ \|  ___|_ _| |   | ____|    / \  |  _ \_ _|
 \___ \|  _| |  \| | | | | |_   | || |   |  _|     / _ \ | |_) | |
  ___) | |___| |\  | |_| |  _|  | || |___| |___   / ___ \|  __/| |
 |____/|_____|_| \_|____/|_|   |___|_____|_____| /_/   \_\_|  |___|

 sendfile.h - transfer data between file descriptors

 functions: sendfile()

=end

  describe "when calling #{TCP_EV_SENDFILE}" do
    it "#{TCP_EV_SENDFILE} should be tracked with SOCK_STREAM" do
      skip
    end

    it "#{TCP_EV_SENDFILE} should not crash with SOCK_DGRAM" do
      skip
    end

    it "#{TCP_EV_SENDFILE} should be tracked when failing" do
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

  describe "when calling #{TCP_EV_POLL}" do
    it "#{TCP_EV_POLL} should be tracked with SOCK_STREAM" do
      skip
    end

    it "#{TCP_EV_POLL} should not crash with SOCK_DGRAM" do
      skip
    end

    it "#{TCP_EV_POLL} should be tracked when failing" do
      skip
    end
  end

end
