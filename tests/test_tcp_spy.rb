# Purpose: test the JSON output file of a given TCP connection
require 'minitest/autorun'
require 'minitest/spec'
require 'minitest/reporters'

require './common.rb'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

def json(con_id=1)
  read_json("packetdrill", con_id)
end

describe "tcp_spy" do
  before do
    reset_dir(DEFAULT_PATH) 
  end

  describe "a TcpConnection" do
    it "should have correct top level JSON fields" do
      run_pkt_script(PKT_SOCKET_STREAM)
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
      assert_json_match(pattern, json)
    end

    it "should have the proper bytes count" do
      run_pkt_script(<<-EOT)
        #{PKT_CONNECTED_SOCK_STREAM}
        +0 send(3, ..., 80, 0) = 80
        +0 send(3, ..., 110, 0) = 110
        +0 < P. 1:101(100) ack 1 win 1000
        +0 recv(3, ..., 100, 0) = 100
        +0 < P. 101:211(110) ack 1 win 110
        +0 recv(3, ..., 110, 0) = 110
      EOT
      pattern = {
        bytes_received: 210,
        bytes_sent: 190,
      }.ignore_extra_keys!
      assert_json_match(pattern, json)
    end
  end

  describe "2 TCP connections" do
    it "should properly handle 2 subsequent connections" do
      run_pkt_script(<<-EOT)
        0 socket(..., SOCK_STREAM, 0) = 3 
        +0 listen(3, 1) = 0
        +0 close(3) = 0
        +0 socket(..., SOCK_STREAM, 0) = 3 
        +0 setsockopt(3, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0
        +0 close(3) = 0
      EOT
      pattern1 = {
        id: 1, # id 0 is taken by a Packetdrill connection.
        events: [
          {type: TCP_EV_SOCKET}.ignore_extra_keys!,
          {type: TCP_EV_LISTEN}.ignore_extra_keys!,
          {type: TCP_EV_CLOSE}.ignore_extra_keys!
        ].ignore_extra_values!
      }.ignore_extra_keys!
      pattern2 = {
        id: 2,
        events: [
          {type: TCP_EV_SOCKET}.ignore_extra_keys!,
          {type: TCP_EV_SETSOCKOPT}.ignore_extra_keys!,
          {type: TCP_EV_CLOSE}.ignore_extra_keys!
        ].ignore_extra_values!
      }.ignore_extra_keys!
      assert_json_match(pattern1, json(1))
      assert_json_match(pattern2, json(2))
    end

    it "should properly handle 2 interleaved connections" do
      run_pkt_script(<<-EOT)
        0 socket(..., SOCK_STREAM, 0) = 3 
        +0 socket(..., SOCK_STREAM, 0) = 4 
        +0 listen(3, 1) = 0
        +0 setsockopt(4, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0
        +0 close(3) = 0
        +0 close(4) = 0
     EOT
      pattern1 = {
        id: 1, # id 0 is taken by a Packetdrill connection.
        events: [
          {type: TCP_EV_SOCKET}.ignore_extra_keys!,
          {type: TCP_EV_LISTEN}.ignore_extra_keys!,
          {type: TCP_EV_CLOSE}.ignore_extra_keys!
        ].ignore_extra_values!
      }.ignore_extra_keys!
      pattern2 = {
        id: 2,
        events: [
          {type: TCP_EV_SOCKET}.ignore_extra_keys!,
          {type: TCP_EV_SETSOCKOPT}.ignore_extra_keys!,
          {type: TCP_EV_CLOSE}.ignore_extra_keys!
        ].ignore_extra_values!
      }.ignore_extra_keys!
      assert_json_match(pattern1, json(1))
      assert_json_match(pattern2, json(2))
    end
  end

  describe "an event" do
    it "should have the correct shared fields" do
      run_pkt_script(PKT_SOCKET_STREAM)
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
      assert_json_match(pattern, json)
    end
  end
 
  describe "a #{TCP_EV_SOCKET} event" do
    it "#{TCP_EV_SOCKET}should have the correct JSON fields" do
      run_pkt_script(PKT_SOCKET_STREAM)
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
      assert_json_match(pattern, json)
    end
  end

  describe "a #{TCP_EV_BIND} event" do
    it "#{TCP_EV_BIND} should have the correct JSON fields" do
      run_pkt_script(PKT_BIND_STREAM)
      pattern = {
        events: [
          {
            type: TCP_EV_BIND,
            details: {
              addr: {
                ip: String,
                port: String,
                name: String,
                serv: String
              },
              force_bind: Boolean,
            }
          }.ignore_extra_keys!
        ].ignore_extra_values!
      }.ignore_extra_keys!
      assert_json_match(pattern, json)
    end
  end

  describe "a #{TCP_EV_CONNECT} event" do
    it "#{TCP_EV_CONNECT} should have the correct JSON fields" do
      run_pkt_script(PKT_CONNECT_STREAM)
      pattern = {
        events: [
          {
            type: TCP_EV_CONNECT,
            details: {
              addr: {
                ip: String,
                port: String,
                name: String,
                serv: String
              }
            }
          }.ignore_extra_keys!
        ].ignore_extra_values!
      }.ignore_extra_keys!
      assert_json_match(pattern, json)
    end
  end

  describe "a #{TCP_EV_SHUTDOWN} event" do
    it "#{TCP_EV_SHUTDOWN} should have the correct JSON fields" do
      run_pkt_script(PKT_SHUTDOWN_STREAM)
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
      assert_json_match(pattern, json)
    end
  end

  describe "a #{TCP_EV_LISTEN} event" do
    it "#{TCP_EV_LISTEN} should have the correct JSON fields" do
      run_pkt_script(PKT_LISTEN_STREAM)
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
      assert_json_match(pattern, json)
    end
  end

  describe "a #{TCP_EV_SETSOCKOPT} event" do
    it "#{TCP_EV_SETSOCKOPT} should have the correct JSON fields" do
      run_pkt_script(PKT_SETSOCKOPT_STREAM)
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
      assert_json_match(pattern, json)
    end
  end

  describe "a #{TCP_EV_SEND} event" do
    it "#{TCP_EV_SEND} should have the correct JSON fields" do
      run_pkt_script(PKT_SEND_STREAM)
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
      assert_json_match(pattern, json)
    end
  end

  describe "a #{TCP_EV_RECV} event" do
    it "#{TCP_EV_RECV} should have the correct JSON fields" do
      run_pkt_script(PKT_RECV_STREAM)
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
      assert_json_match(pattern, json)
    end
  end

  describe "a #{TCP_EV_SENDTO} event" do
    it "#{TCP_EV_SENDTO} should have the correct JSON fields" do
      run_pkt_script(PKT_SENDTO_STREAM)
      pattern = {
        events: [
          {
            type: TCP_EV_SENDTO,
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
      assert_json_match(pattern, json)
 
    end
  end

  describe "a #{TCP_EV_RECVFROM} event" do
    it "#{TCP_EV_RECVFROM} should have the correct JSON fields" do
      run_pkt_script(PKT_RECVFROM_STREAM)
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
      assert_json_match(pattern, json)
 
    end
  end

  describe "a #{TCP_EV_WRITE} event" do
    it "#{TCP_EV_WRITE} should have the correct JSON fields" do
      run_pkt_script(PKT_WRITE_STREAM)
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
      assert_json_match(pattern, json)
 
    end
  end

  describe "a #{TCP_EV_READ} event" do
    it "#{TCP_EV_READ} should have the correct JSON fields" do
      run_pkt_script(PKT_READ_STREAM)
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
      assert_json_match(pattern, json)
    end
  end

  describe "a #{TCP_EV_CLOSE} event" do
    it "#{TCP_EV_CLOSE} should have the correct JSON fields" do
      run_pkt_script(PKT_CLOSE_STREAM)
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
      assert_json_match(pattern, json)
    end
  end

  describe "a #{TCP_EV_TCP_INFO} event" do
    it "#{TCP_EV_TCP_INFO} should have the correct JSON fields" do
      skip
    end
  end
end
