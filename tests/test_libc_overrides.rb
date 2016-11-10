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

end
