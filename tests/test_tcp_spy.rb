# Purpose: test the JSON output file of a given TCP connection
require 'minitest/autorun'
require 'minitest/spec'
require 'minitest/reporters'

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

  before do
    reset_dir(DEFAULT_PATH) 
  end

  describe "a TcpConnection" do
    it "should have correct top level JSON fields" do
      run_pkt_script(<<-EOT)
        0 socket(..., SOCK_STREAM, 0) = 3 
      EOT
      pattern = {
        app_name: String,
        bytes_received: Fixnum,
        bytes_sent: Fixnum,
        cmdline: String,
        directory: String,
        events: Array,
        events_count: Fixnum,
        id: Fixnum,
        kernel: String,
        successful_pcap: Boolean,
        timestamp: Fixnum,
      }
      assert_json_match(pattern, json_dump)
    end
  end
 
  describe "an event" do
    it "should have the correct shared fields" do
      run_pkt_script(<<-EOT)
        0 socket(..., SOCK_STREAM, 0) = 3 
      EOT
      pattern = {
        events: [
          {
            details: Hash,
            return_value: Fixnum,
            success: Boolean,
            timestamp: {
              sec: Fixnum,
              usec: Fixnum
            },
            type: String
          }.ignore_extra_keys!
        ].ignore_extra_values!
      }.ignore_extra_keys!
      assert_json_match(pattern, json_dump)
    end
  end
 
  describe "a #{TCP_EV_SOCKET} event" do
    it "#{TCP_EV_SOCKET}should have the correct JSON fields" do
      run_pkt_script(<<-EOT)
        0 socket(..., SOCK_STREAM, 0) = 3 
      EOT
      pattern = {
        events: [
          {
            type: TCP_EV_SOCKET,
            details: {
              domain: String,
              protocol: Fixnum,
              sock_cloexec: Boolean,
              sock_nonblock: Boolean,
              type: String
            }
          }.ignore_extra_keys!
        ].ignore_extra_values!
      }.ignore_extra_keys!
      assert_json_match(pattern, json_dump)
    end
  end

  describe "a #{TCP_EV_BIND} event" do
    it "#{TCP_EV_BIND} should have the correct JSON fields" do
      run_pkt_script(<<-EOT)
        0 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3 
        +0 bind(3, ..., ...) = 0
      EOT
      pattern = {
        events: [
          {
            type: TCP_EV_BIND,
            details: {
              addr: String,
              force_bind: Boolean,
              port: String
            }
          }.ignore_extra_keys!
        ].ignore_extra_values!
      }.ignore_extra_keys!
      assert_json_match(pattern, json_dump)
    end
  end

  describe "a #{TCP_EV_CONNECT} event" do
    it "#{TCP_EV_CONNECT} should have the correct JSON fields" do
      run_pkt_script(connected_sock_stream)
      pattern = {
        events: [
          {
            type: TCP_EV_CONNECT,
            details: {
              addr: String,
              port: String
            }
          }.ignore_extra_keys!
        ].ignore_extra_values!
      }.ignore_extra_keys!
      assert_json_match(pattern, json_dump)
    end
  end

  describe "a #{TCP_EV_SHUTDOWN} event" do
    it "#{TCP_EV_SHUTDOWN} should have the correct JSON fields" do
      run_pkt_script(<<-EOT)
        #{connected_sock_stream}
        +0 shutdown(3, SHUT_RD) = 0
      EOT
      pattern = {
        events: [
          {
            type: TCP_EV_SHUTDOWN,
            details: {
              shut_rd: Boolean,
              shut_wr: Boolean
            }
          }.ignore_extra_keys!
        ].ignore_extra_values!
      }.ignore_extra_keys!
      assert_json_match(pattern, json_dump)
    end
  end

  describe "a #{TCP_EV_LISTEN} event" do
    it "#{TCP_EV_LISTEN} should have the correct JSON fields" do
      run_pkt_script(<<-EOT)
        0 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3 
        +0 listen(3, 1) = 0
      EOT
      pattern = {
        events: [
          {
            type: TCP_EV_LISTEN,
            details: {
              backlog: Fixnum
            }
          }.ignore_extra_keys!
        ].ignore_extra_values!
      }.ignore_extra_keys!
      assert_json_match(pattern, json_dump)
    end
  end

  describe "a #{TCP_EV_SETSOCKOPT} event" do
    it "#{TCP_EV_SETSOCKOPT} should have the correct JSON fields" do
      run_pkt_script(<<-EOT)
        0 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3 
        +0 setsockopt(3, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0
      EOT
      pattern = {
        events: [
          {
            type: TCP_EV_SETSOCKOPT,
            details: {
              level: String,
              optname: String
            }
          }.ignore_extra_keys!
        ].ignore_extra_values!
      }.ignore_extra_keys!
      assert_json_match(pattern, json_dump)
    end
  end

  describe "a #{TCP_EV_SEND} event" do
    it "#{TCP_EV_SEND} should have the correct JSON fields" do
      run_pkt_script(<<-EOT)
        #{connected_sock_stream} 
        +0 send(3, ..., 100, 0) = 100
      EOT
      pattern = {
        events: [
          {
            type: TCP_EV_SEND,
            details: {
              bytes: Fixnum,
              flags: {
                msg_confirm: Boolean,
                msg_dontroute: Boolean,
                msg_dontwait: Boolean,
                msg_eor: Boolean,
                msg_more: Boolean,
                msg_nosignal: Boolean,
                msg_oob: Boolean
              }
            }
          }.ignore_extra_keys!
        ].ignore_extra_values!
      }.ignore_extra_keys!
      assert_json_match(pattern, json_dump)
    end
  end

  describe "a #{TCP_EV_RECV} event" do
    it "#{TCP_EV_RECV} should have the correct JSON fields" do
      run_pkt_script(<<-EOT)
         #{connected_sock_stream} 
        +0 < P. 1:1001(1000) ack 1 win 1000
        +0 recv(3, ..., 1000, 0) = 1000
      EOT
      pattern = {
        events: [
          {
            type: TCP_EV_RECV,
            details: {
              bytes: Fixnum,
              flags: {
                msg_cmsg_cloexec: Boolean,
                msg_dontwait: Boolean,
                msg_errqueue: Boolean,
                msg_oob: Boolean,
                msg_peek: Boolean,
                msg_trunc: Boolean,
                msg_waitall: Boolean
              }
            }
          }.ignore_extra_keys!
        ].ignore_extra_values!
      }.ignore_extra_keys!
      assert_json_match(pattern, json_dump)
    end
  end

  describe "a #{TCP_EV_SENDTO} event" do
    it "#{TCP_EV_SENDTO} should have the correct JSON fields" do
      run_pkt_script(<<-EOT)
        #{connected_sock_stream} 
        +0 sendto(3, ..., 100, 0, ..., ...) = 100
      EOT
      pattern = {
        events: [
          {
            type: TCP_EV_SENDTO,
            details: {
              addr: String,
              bytes: Fixnum,
              port: String,
              flags: {
                msg_confirm: Boolean,
                msg_dontroute: Boolean,
                msg_dontwait: Boolean,
                msg_eor: Boolean,
                msg_more: Boolean,
                msg_nosignal: Boolean,
                msg_oob: Boolean
              }
            }
          }.ignore_extra_keys!
        ].ignore_extra_values!
      }.ignore_extra_keys!
      assert_json_match(pattern, json_dump)
 
    end
  end

  describe "a #{TCP_EV_RECVFROM} event" do
    it "#{TCP_EV_RECVFROM} should have the correct JSON fields" do
      run_pkt_script(<<-EOT)
        #{connected_sock_stream} 
        +0 < P. 1:1001(1000) ack 1 win 1000
        +0 recvfrom(3, ..., 1000, 0, ..., ...) = 1000
      EOT
      pattern = {
        events: [
          {
            type: TCP_EV_RECVFROM,
            details: {
              bytes: Fixnum,
              flags: {
                msg_cmsg_cloexec: Boolean,
                msg_dontwait: Boolean,
                msg_errqueue: Boolean,
                msg_oob: Boolean,
                msg_peek: Boolean,
                msg_trunc: Boolean,
                msg_waitall: Boolean
              }
            }
          }.ignore_extra_keys!
        ].ignore_extra_values!
      }.ignore_extra_keys!
      assert_json_match(pattern, json_dump)
 
    end
  end

  describe "a #{TCP_EV_WRITE} event" do
    it "#{TCP_EV_WRITE} should have the correct JSON fields" do
      run_pkt_script(<<-EOT)
        #{connected_sock_stream} 
        +0 write(3, ..., 100) = 100
      EOT
      pattern = {
        events: [
          {
            type: TCP_EV_WRITE,
            details: {
              bytes: Fixnum
            }
          }.ignore_extra_keys!
        ].ignore_extra_values!
      }.ignore_extra_keys!
      assert_json_match(pattern, json_dump)
 
    end
  end

  describe "a #{TCP_EV_READ} event" do
    it "#{TCP_EV_READ} should have the correct JSON fields" do
      run_pkt_script(<<-EOT)
        #{connected_sock_stream} 
        +0 < P. 1:1001(1000) ack 1 win 1000
        +0 read(3, ..., 1000) = 1000
      EOT
      pattern = {
        events: [
          {
            type: TCP_EV_READ,
            details: {
              bytes: Fixnum
            }
          }.ignore_extra_keys!
        ].ignore_extra_values!
      }.ignore_extra_keys!
      assert_json_match(pattern, json_dump)
    end
  end

  describe "a #{TCP_EV_CLOSE} event" do
    it "#{TCP_EV_CLOSE} should have the correct JSON fields" do
      run_pkt_script(<<-EOT)
        0 socket(..., SOCK_STREAM, 0) = 3 
        +0 close(3) = 0
      EOT
      pattern = {
        events: [
          {
            type: TCP_EV_CLOSE,
            details: {
              detected: Boolean
            }
          }.ignore_extra_keys!
        ].ignore_extra_values!
      }.ignore_extra_keys!
      assert_json_match(pattern, json_dump)
    end
  end

  describe "a #{TCP_EV_TCP_INFO} event" do
    it "#{TCP_EV_TCP_INFO} should have the correct JSON fields" do
      skip
    end
  end
end
