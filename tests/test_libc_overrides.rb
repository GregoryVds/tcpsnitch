# Purpose: test that all libc overrides do not crash the main process.

require 'minitest/autorun'
require 'minitest/reporters'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

class TestLibcOverrides < Minitest::Test

	def test_truthness
		assert true
	end

end
