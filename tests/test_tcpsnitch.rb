# Purpose: test bash interface & initialization (init.c) of Netspy lib.
require 'minitest/autorun'
require 'minitest/spec'
require 'minitest/reporters'
require './lib/lib.rb'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

describe "tcpsnitch" do
  before do WebServer.start end
  MiniTest::Unit.after_tests { WebServer.stop }

  let(:cmd) { "./c_programs/socket.out" } 

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

  ["-b", "-f", "-l", "-t", "-u"].each do |opt|
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
      run_c_program(SOCK_EV_SEND, "-c")
      assert contains?(TEST_DIR, "0.pcap")
    end

    it "should not capture without -c" do
      assert run_c_program(SOCK_EV_SEND)
      assert !contains?(TEST_DIR, "0.pcap")
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
end
