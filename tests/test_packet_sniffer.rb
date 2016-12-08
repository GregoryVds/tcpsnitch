# Purpose: test that we properly capture all packets in the PCAP trace. 
require 'minitest/autorun'
require 'minitest/spec'
require 'minitest/reporters'
require 'packetfu'
require './common.rb'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

def get_pcap
  PacketFu::PcapFile.file_to_array(pcap_file_str)
end

def get_packet(pcap, pkt_id)
  PacketFu::Packet.parse(pcap[pkt_id])
end

describe "packet_sniffer.c" do
  it "should create a PCAP file on CONNECT" do
    run_c_program(TCP_EV_CONNECT)
    assert contains?(con_dir_str, PCAP_FILE) 
  end
  
  # Need to capture on a single interface to use packetfu
  # Otherwises issues with layer 2 header.
  it "should capture the 3-way handshake on CONNECT" do
    skip
    run_c_program(TCP_EV_CONNECT)
    cap = get_pcap
    assert cap.size >= 3
  end
end
