# Purpose: test the PCAP file of a given TCP connection.

require 'minitest/autorun'
require 'minitest/reporters'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

class TestPacketSniffer < Minitest::Test

	def test_truthness
		assert true
	end

end
