# Purpose: test the JSON output file of a given TCP connection

require 'minitest/autorun'
require 'minitest/reporters'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

class TestTcpSpy < Minitest::Test

	def test_truthness
		assert true
	end

end
