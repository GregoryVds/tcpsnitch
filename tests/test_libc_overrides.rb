# Purpose: test that all libc overrides do not crash the main process.

require 'minitest/autorun'
require 'minitest/reporters'
require 'minitest/spec'
require './common.rb'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

describe "libc overrides" do

  describe "when calling socket()" do
    it "should not crash with TCP socket" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_STREAM, 0) = 3 
      EOT
    end

    it "should not crash with UDP socket" do
      assert run_pkt_script(<<-EOT)
        0 socket(..., SOCK_DGRAM, 0) = 3 
      EOT
    end

    it "should not crash with failing() socket" do
      skip
      assert run_pkt_script(<<-EOT)
        0 socket(..., -42, 0) = -1 
      EOT
    end
  end

end
