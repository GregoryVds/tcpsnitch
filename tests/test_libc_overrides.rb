# Purpose: test that all libc overrides do not crash the main process.
require 'minitest/autorun'
require 'minitest/spec'
require 'minitest/reporters'
require './common.rb'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

def no_error_log
  !errors_in_log?
end

def assert_event_present(type, success=true)
  pattern = {
    events: [
      {
        type: type,
        success: success
      }.ignore_extra_keys!
    ].ignore_extra_values!
  }.ignore_extra_keys!
  assert_json_match(pattern, read_json)
end

describe "libc overrides" do
  SOCKET_SYSCALLS.each do |syscall|
    describe "when calling #{syscall}()" do
      stream  = "#{syscall}_stream.out"
      dgram   = "#{syscall}_dgram.out"
      failing = "#{syscall}_fail.out"

      it "#{stream} should not crash" do
        assert run_c_program(stream)
      end

      it "#{stream} should log no ERROR" do
        run_c_program(stream)
        assert no_error_log
      end

      it "should be in JSON with #{stream}" do
        run_c_program(stream)
        assert_event_present("#{syscall}()")
      end

      # LISTEN: Cannot listen() on DGRAM socket
      unless [TCP_EV_LISTEN].include?(syscall)
        it "#{dgram} should not crash" do
          assert run_c_program(dgram)
        end
      end

      it "#{failing} should not crash" do
        assert run_c_program(failing)
      end

      # SOCKET: No log file if no TCP connection
      unless [TCP_EV_SOCKET].include?(syscall)
        it "#{failing} should log no ERROR" do
          run_c_program(failing)
          assert no_error_log
        end
      end

      # SOCKET: No JSON if no TCP connection.
      # LISTEN: How to fail listen() on valid TCP socket? 
      # CLOSE: How to fail close() on valid TCP socket?
      unless [TCP_EV_SOCKET, TCP_EV_LISTEN, TCP_EV_CLOSE].include?(syscall)
        it "should be in JSON with #{failing}" do
          run_c_program(failing)
          assert_event_present("#{syscall}()", false)
        end
      end
    end
  end

=begin
  _   _ _   _ ___ ____ _____ ____       _    ____ ___
 | | | | \ | |_ _/ ___|_   _|  _ \     / \  |  _ \_ _|
 | | | |  \| || |\___ \ | | | | | |   / _ \ | |_) | |
 | |_| | |\  || | ___) || | | |_| |  / ___ \|  __/| |
  \___/|_| \_|___|____/ |_| |____/  /_/   \_\_|  |___|

 unistd.h - standard symbolic constants and types

 functions: write(), read(), close().


  describe "when calling #{TCP_EV_WRITE}" do
    it "#{TCP_EV_WRITE} should not crash" do
      assert run_c_program(PKT_WRITE_STREAM)
    end
    
    it "#{TCP_EV_WRITE} should give no ERROR log" do
      run_c_program(PKT_WRITE_STREAM)
      assert no_error_log
    end

    it "#{TCP_EV_WRITE} should be tracked" do
      run_c_program(PKT_WRITE_STREAM)
      assert_event_present(TCP_EV_WRITE)
    end

    it "#{TCP_EV_WRITE} should not crash" do
      assert run_c_program(PKT_WRITE_DGRAM)
    end

    it "#{TCP_EV_WRITE} should give no ERROR log" do
      run_c_program(PKT_WRITE_DGRAM)
      assert no_error_log
    end

    it "#{TCP_EV_WRITE} should not crash" do
      skip
    end
  end

  describe "when calling #{TCP_EV_READ}" do
    it "#{TCP_EV_READ} should not crash" do
      assert run_c_program(PKT_READ_STREAM)
    end
    
    it "#{TCP_EV_READ} should give no ERROR log" do
      run_c_program(PKT_READ_STREAM)
      assert no_error_log
    end

    it "#{TCP_EV_READ} should be tracked" do
      run_c_program(PKT_READ_STREAM)
      assert_event_present(TCP_EV_READ)
    end

    it "#{TCP_EV_READ} should not crash" do
      assert run_c_program(PKT_READ_DGRAM)
    end

    it "#{TCP_EV_READ} should give no ERROR log" do
      run_c_program(PKT_READ_DGRAM)
      assert no_error_log
    end

    it "#{TCP_EV_READ} should not crash" do
      skip
    end
  end

  describe "when calling #{TCP_EV_CLOSE}" do
    it "#{TCP_EV_CLOSE} should not crash" do
      assert run_c_program(PKT_CLOSE_STREAM)
    end
    
    it "#{TCP_EV_CLOSE} should give no ERROR log" do
      run_c_program(PKT_CLOSE_STREAM)
      assert no_error_log
    end

    it "#{TCP_EV_CLOSE} should be tracked" do
      run_c_program(PKT_CLOSE_STREAM)
      assert_event_present(TCP_EV_CLOSE)
    end

    it "#{TCP_EV_CLOSE} should not crash" do
      assert run_c_program(PKT_CLOSE_DGRAM)
    end

    it "#{TCP_EV_CLOSE} should give no ERROR log" do
      run_c_program(PKT_CLOSE_DGRAM)
      assert no_error_log
    end

    it "#{TCP_EV_CLOSE} should not crash" do
      skip
    end
  end

=begin
  _   _ ___ ___       _    ____ ___
 | | | |_ _/ _ \     / \  |  _ \_ _|
 | | | || | | | |   / _ \ | |_) | |
 | |_| || | |_| |  / ___ \|  __/| |
  \___/|___\___/  /_/   \_\_|  |___|

 sys/uio.h - definitions for vector I/O operations

 functions: writev(), readv()

=end

=begin
  ____  _____ _   _ ____  _____ ___ _     _____      _    ____ ___
 / ___|| ____| \ | |  _ \|  ___|_ _| |   | ____|    / \  |  _ \_ _|
 \___ \|  _| |  \| | | | | |_   | || |   |  _|     / _ \ | |_) | |
  ___) | |___| |\  | |_| |  _|  | || |___| |___   / ___ \|  __/| |
 |____/|_____|_| \_|____/|_|   |___|_____|_____| /_/   \_\_|  |___|

 sendfile.h - transfer data between file descriptors

 functions: sendfile()

=end

=begin
  ____   ___  _     _          _    ____ ___
 |  _ \ / _ \| |   | |        / \  |  _ \_ _|
 | |_) | | | | |   | |       / _ \ | |_) | |
 |  __/| |_| | |___| |___   / ___ \|  __/| |
 |_|    \___/|_____|_____| /_/   \_\_|  |___|

 poll.h - definitions for the poll() function

 functions: poll()

=end

end
