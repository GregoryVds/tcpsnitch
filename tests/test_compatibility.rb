# Purpose: test compatibility with some applications 
require 'minitest/autorun'
require 'minitest/spec'
require 'minitest/reporters'
require './lib/lib.rb'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

def stderr(cmd, log_lvl) 
  `#{EXECUTABLE} -l #{log_lvl} #{cmd} 2>&1 >/dev/null`
end

describe "compatibility tests" do
	before do WebServer.start end
  MiniTest::Unit.after_tests { WebServer.stop }
	
  describe "curl" do
    curl = "curl localhost:8000"

    it "should not crash" do
      assert tcpsnitch(curl) 
    end

    it "should report some INFO" do
      assert stderr(curl, LOG_LVL_INFO)
    end

    it "should report no WARN" do
      skip
      assert_empty stderr(curl, LOG_LVL_WARN)
    end

    it "should report no ERROR" do
      skip
      assert_empty stderr(curl, LOG_LVL_ERROR) 
    end
  end
end
