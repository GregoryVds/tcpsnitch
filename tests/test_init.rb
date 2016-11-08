# Purpose: test initialization (init.c) of Netspy.

require 'minitest/autorun'
require 'minitest/reporters'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

class TestInit < Minitest::Test

	def test_truthness
		assert true
	end

end
