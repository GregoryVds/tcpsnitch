# Purpose: test initialization (init.c) of Netspy.
require 'minitest/autorun'
require 'minitest/spec'
require 'minitest/reporters'

require './common.rb'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

describe "tcpsnitch" do
		
  let(:cmd) { "./c_programs/00_socket_stream.out" } 

  describe "when no option is set" do
    it "should not crash" do
      assert tcpsnitch('', cmd)
    end
  end

  describe "when no command is passed" do
    it "should report 'too few arguments'" do
      assert_match(/too few arguments/, tcpsnitch_output('', '')) 
      assert_match(/too few arguments/, tcpsnitch_output('-b 42', ''))
    end
  end
  
  ["-b", "-f", "-l", "-u"].each do |opt|
    describe "when #{opt} is set" do
      it "should report 'invalid #{opt} argument'" do
        assert_match(/invalid #{opt} argument/, tcpsnitch_output("#{opt} -42", cmd)) 
        assert_match(/invalid #{opt} argument/, tcpsnitch_output("#{opt} foo", cmd))
      end
   
      it "should not crash with a valid arg" do
        assert tcpsnitch("#{opt} 5", cmd)
      end
    end
  end

  describe "when -d is set" do
    it "should report 'invalid argument' with invalid dir" do
      assert_match(/invalid -d argument/, tcpsnitch_output("-d 1234", cmd))
      assert_match(/invalid -d argument/, tcpsnitch_output("-d /crazy/path", cmd))
    end

    it "should not crash with a valid arg" do
      assert tcpsnitch("-d #{TEST_DIR}", cmd)
    end

    it "should write to a valid dir" do
      reset_dir(TEST_DIR)
      tcpsnitch("-d #{TEST_DIR}", cmd)
      assert !dir_empty?(TEST_DIR)
    end
  end
 
  describe "when -l is set" do
    it "should show logs at 3" do
      assert_match(/[INFO]/, tcpsnitch_output("-l 3", cmd))
    end
  end
 
  describe "when -h is set" do
    it "should not crash" do
      assert tcpsnitch("-h", '')
    end

    it "should print usage dialog" do
      assert_match(/Usage/, tcpsnitch_output('-h', ''))
    end
  end

  describe "when -v is set" do
    it "should show verbose output" do
      assert_match(/[pid \d*] [a-z]*()/, tcpsnitch_output("-v", cmd))
    end
  end

  describe "when --version is set" do
    it "should not crash" do
      assert tcpsnitch("--version", '')
    end

    it "should print version" do
      assert_match(/version/, tcpsnitch_output('--version', ''))
    end
  end



=begin


  describe "lo" do
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
=end
end
