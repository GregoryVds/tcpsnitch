# Purpose: test bash interface & initialization (init.c) of Netspy lib.
require 'minitest/autorun'
require 'minitest/spec'
require 'minitest/reporters'
require './lib/lib.rb'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

describe "tcpsnitch" do
	before do WebServer.start end
  MiniTest::Unit.after_tests { WebServer.stop }
	
  let(:cmd) { "./c_programs/00_socket.out" } 

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
  
  ["-b", "-e", "-f", "-l", "-u"].each do |opt|
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
  
  describe "option -c" do
    it "should not crash with -c" do
      assert tcpsnitch("-c", cmd)
    end

    it "should capture with -c" do
      run_c_program(TCP_EV_SEND, "-c")
      assert contains?(con_dir_str, PCAP_FILE)
    end

    it "should not capture without -c" do
      assert run_c_program(TCP_EV_SEND)
      assert !contains?(con_dir_str, PCAP_FILE)
    end
    # Rest is tested in test_packet_sniffer.rb
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

  describe "option -e" do
    cmd = "./c_programs/09_shutdown.out" # script has 4 syscalls
    
    it "should dump json 3 times with -e 1" do
      out = tcpsnitch_output("-e 1 -l 5", cmd)
      assert_equal(4, out.scan(/tcp_dump_json/).count) 
    end
  
    it "should dump json 2 times with -e 2" do
      out = tcpsnitch_output("-e 2 -l 5", cmd)
      assert_equal(2, out.scan(/tcp_dump_json/).count) 
    end

    it "should dump json 1 time without -e" do # defaults to 1000
      out = tcpsnitch_output("-l 5", cmd)
      assert_equal(1, out.scan(/tcp_dump_json/).count) 
    end
  end

  describe "option -i" do
    it "should not crash with valid iface" do
      assert tcpsnitch("-i lo", cmd)
    end

    it "should report 'invalid argument' with invalid iface" do
      assert_match(/invalid -i argument/, tcpsnitch_output("-i abc", cmd))
      assert_match(/invalid -i argument/, tcpsnitch_output("-i 123", cmd))
    end
  end

  describe "when -l is set" do
    it "should show logs at 3" do
      assert_match(/#{LOG_LABEL_INFO}/, tcpsnitch_output("-l 3", cmd))
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

  describe "option -p" do
    it "should not crash with -p" do
      assert tcpsnitch("-p", cmd)
    end

    it "should pretty print the JSON with -p" do
      skip
      reset_dir(TEST_DIR)
      tcpsnitch("-d #{TEST_DIR} -p", cmd)
      assert system("test $(wc -l < #{json_file_str}) -gt 0") 
    end

    it "should not pretty print the JSON without -p" do
      skip
      reset_dir(TEST_DIR)
      tcpsnitch("-d #{TEST_DIR}", cmd)
      assert system("test $(wc -l < #{json_file_str}) -eq 0") 
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

  describe "for any run" do
    it "should save the os version" do
      reset_dir(TEST_DIR)
      tcpsnitch("-d #{TEST_DIR}", cmd)
      assert contains?(TEST_DIR, "uname.txt")  
    end

    it "should save the network config" do
      reset_dir(TEST_DIR)
      tcpsnitch("-d #{TEST_DIR}", cmd)
      assert contains?(TEST_DIR, "sysctl_net.txt") 
    end
  end
end
