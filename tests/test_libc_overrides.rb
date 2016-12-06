# Purpose: test that all libc overrides do not crash the main process.
require 'minitest/autorun'
require 'minitest/spec'
require 'minitest/reporters'
require './common.rb'
require './lib/webserver.rb'

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
  before do 
    WebServer.start  # Memoization done in WebServer
  end

  MiniTest::Unit.after_tests { WebServer.stop }

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

      # SOCKET: No log file if no TCP connection.
      # CLOSE: No log file if no TCP connection. How to fail close() with con?
      unless [TCP_EV_SOCKET, TCP_EV_CLOSE].include?(syscall)
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
