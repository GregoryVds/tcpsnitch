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
      assert_json_match(pattern, json_str)
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
      assert_json_match(pattern, json_str)
    end
  end
 
  describe "a socket() event" do
    it "should have the correct fields" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_STREAM, 0) = 3 
      EOT
      pattern = {
        events: [
          {
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
      assert_json_match(pattern, json_str)
    end
  end

end

