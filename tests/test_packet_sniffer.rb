# Purpose: test that we properly capture all packets in the PCAP trace.
require 'minitest/autorun'
require 'minitest/spec'
require 'minitest/reporters'
require 'packetfu'
require './lib/lib.rb'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

def get_pcap
  PacketFu::PcapFile.file_to_array(pcap_file_str)
end

def get_packet(pcap, pkt_id)
  PacketFu::Packet.parse(pcap[pkt_id])
end

describe "packet_sniffer.c" do
  before do WebServer.start end
  MiniTest::Unit.after_tests { WebServer.stop }

  it "should create a PCAP file on CONNECT" do
    run_c_program(SOCK_EV_CONNECT, "-c")
    assert contains?(dir_str, "0.pcap")
  end

  # Need to capture on a single interface to use packetfu
  # Otherwises issues with layer 2 header.
  it "should capture the 3-way handshake on CONNECT" do
    skip
    run_c_program(SOCK_EV_CONNECT, "-c")
    cap = get_pcap
    assert cap.size >= 3
  end
end
