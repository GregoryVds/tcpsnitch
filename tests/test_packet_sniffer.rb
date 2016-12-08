# Purpose: test that we properly capture all packets in the PCAP trace. 
require 'minitest/autorun'
require 'minitest/spec'
require 'minitest/reporters'
require 'packetfu'
require './common.rb'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

def pcap_present?
  contains?(con_dir_str("curl", 0), PCAP_FILE)
end

def get_pcap
  PacketFu::PcapFile.file_to_array(pcap_file_str("curl", 0))
end

def get_packet(pcap, pkt_id)
  PacketFu::Packet.parse(pcap[pkt_id])
end

describe "packet_sniffer.c" do
  
  before do
    reset_dir(DEFAULT_PATH) 
  end

  it "should create a PCAP file on CONNECT" do
    run_curl
    assert pcap_present?
  end
  
  # Cannot capture trace on a single interface with Packetdrill?
  # In the meantime, use Curl instead.
  it "should capture the 3-way handshake on CONNECT" do
    run_curl
    cap = get_pcap
    assert cap.size >= 3
  end

end

