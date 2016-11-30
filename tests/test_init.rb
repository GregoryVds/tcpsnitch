# Purpose: test initialization (init.c) of Netspy.
require 'minitest/autorun'
require 'minitest/spec'
require 'minitest/reporters'

require './common.rb'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

describe "Init" do
		
  let(:script) { "./c_programs/00_socket_stream.out" } 
  let(:dir) { "/tmp/dummy" }

  def run_lib(env='')
    system("#{env} #{LD_PRELOAD} #{script}") 
  end

  describe "when no ENV variable is set" do
    it "should simply not crash" do
      assert run_lib
    end
  end

  describe "when #{ENV_PATH} is set" do
    it "should not crash when #{ENV_PATH} exists" do
      mkdir(dir)
      assert(run_lib, "#{ENV_PATH}=#{dir}")
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
      assert contains?(log_dir_str("packetdrill"), "#{LOG_FILE}")
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

  describe "when running an executable" do
    it "should not crash with absolute path" do
      assert run_exec("/usr/bin/curl -s google.com")
    end

    it "a should give no ERROR log with absolute path" do
      reset_dir(DEFAULT_PATH)
      run_exec("/usr/bin/curl -s google.com")
      puts log_file_str("curl")
      assert !errors_in_log?(log_file_str("curl"))
    end

    it "should not crash with executable name" do
      assert run_exec("curl -s google.com")
    end

    it "should give no ERROR log with executable name" do
      reset_dir(DEFAULT_PATH)
      run_exec("curl -s google.com")
      assert !errors_in_log?(log_file_str("curl"))
    end
  end

end
