# Purpose: test the JSON output file of a given TCP connection

require 'minitest/autorun'
require 'minitest/reporters'
require 'minitest/spec'
require './common.rb'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

describe "tcp_spy" do
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
      skip
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
end

