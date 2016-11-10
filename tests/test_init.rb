# Purpose: test initialization (init.c) of Netspy.
require 'minitest/autorun'
require 'minitest/spec'
require 'minitest/reporters'

require './common.rb'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

describe "Init" do
		
  let(:script) { "0 socket(..., SOCK_DGRAM, 0) = 3" }
  let(:dir) { "/tmp/dummy" }

  describe "when no ENV variable is set" do
    it "should simply not crash" do
      assert run_pkt_script(script)
    end

    it "should create #{DEFAULT_PATH} if does not exits" do
      rmdir(DEFAULT_PATH)
      run_pkt_script(script)
      assert dir_exists?(DEFAULT_PATH) 
    end
    
    it "should not crash when #{DEFAULT_PATH} already exists" do
      mkdir(DEFAULT_PATH)
      assert run_pkt_script(script)
    end
  end

  describe "when #{ENV_PATH} is set" do
    it "should not crash when #{ENV_PATH} exists" do
      mkdir(dir)
      assert run_pkt_script(script, "#{ENV_PATH}=#{dir}")
    end

    it "should not crash when #{ENV_PATH} does not exists" do
      rmdir(dir)
      assert run_pkt_script(script, "#{ENV_PATH}=#{dir}")
    end

    it "should not crash when #{ENV_PATH} is invalid" do
      assert run_pkt_script(script, "#{ENV_PATH}=$*?")
    end
  end

  describe "when the PATH is resolved" do
    it "should create the system config dump in PATH" do
      skip
    end
		
    it "should not override a system config dump in PATH" do
      skip
    end

    it "should create a log dir in PATH" do 
      reset_dir(dir)
      assert run_pkt_script(script, "#{ENV_PATH}=#{dir}")
      assert !dir_empty?(dir)
    end
		
    it "should create a log file in PATH" do
      reset_dir(dir)
      assert run_pkt_script(script, "#{ENV_PATH}=#{dir}")
      assert contains?(dir, "*/#{LOG_FILE}")
    end
  end

  describe "when #{ENV_BYTES_IVAL} is set" do
    it "should not crash when #{ENV_BYTES_IVAL} is valid" do
      assert run_pkt_script(script, "#{ENV_BYTES_IVAL}=1024")
    end

    it "should not crash when #{ENV_BYTES_IVAL} is invalid" do
      assert run_pkt_script(script, "#{ENV_BYTES_IVAL}=-1")
      assert run_pkt_script(script, "#{ENV_BYTES_IVAL}=$")
    end
  end

  describe "when #{ENV_MICROS_IVAL} is set" do
    it "should not crash when #{ENV_MICROS_IVAL} is valid" do
      assert run_pkt_script(script, "#{ENV_MICROS_IVAL}=1024")
    end

    it "should not crash when #{ENV_MICROS_IVAL} is invalid" do
      assert run_pkt_script(script, "#{ENV_MICROS_IVAL}=-1")
      assert run_pkt_script(script, "#{ENV_MICROS_IVAL}=$")
    end
  end

end
