# Purpose: test initialization (init.c) of Netspy.

require 'minitest/autorun'
require 'minitest/reporters'
require './common.rb'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

class TestInit < Minitest::Test

	def test_no_env
		assert system(PACKET_DRILL+' ./pkt_scripts/init/no_env.pkt')
	end

	def test_with_netspy_path
		assert system(LD_PRELOAD+' '+PACKET_DRILL+' ./pkt_scripts/init/no_env.pkt')
 	end


end
