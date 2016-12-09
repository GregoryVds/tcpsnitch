# Purpose: test that all libc overrides do not crash the main process, do not
# generate any error log and are present in the JSON trace.
require 'minitest/autorun'
require 'minitest/spec'
require 'minitest/reporters'
require './lib/lib.rb'
require './lib/webserver.rb'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

def no_error_log(log_file=log_file_str)
  !errors_in_log?(log_file)
end

def assert_event_present(type, success=true, json=read_json)
  pattern = {
    events: [
      {
        type: type,
        success: success
      }.ignore_extra_keys!
    ].ignore_extra_values!
  }.ignore_extra_keys!
  assert_json_match(pattern, json)
end

describe "libc overrides" do
  before do 
    WebServer.start  # Memoization done in WebServer
  end

  MiniTest::Unit.after_tests { WebServer.stop }

  SOCKET_SYSCALLS.each do |syscall|
    describe "when calling #{syscall}()" do
      stream  = "#{syscall}"
      dgram   = "#{syscall}_dgram"
      failing = "#{syscall}_fail"

      it "#{stream} should not crash" do
        assert run_c_program(stream)
      end

      it "#{stream} should log no ERROR" do
        run_c_program(stream)
        assert no_error_log
      end

      it "should be in JSON with #{stream}" do
        run_c_program(stream)
        assert_event_present(syscall)
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
          assert_event_present(syscall, false)
        end
      end
    end
  end

  describe "when calling fork()" do
    prog = "fork"

    it "#{prog} should not crash" do
      assert run_c_program(prog)
    end

    it "#{prog} should create a log dir for both processes" do
      run_c_program(prog)
      assert_equal(process_dirs.size, 2)
    end

    it "#{prog} should create a con 0 for both processes" do
      run_c_program(prog)
      dir0 = process_dirs[0]
      dir1 = process_dirs[1]
      assert dir_exists?(dir0+"/0")
      assert dir_exists?(dir1+"/0")
    end

    it "#{prog} should log no ERROR for both processes" do
      run_c_program(prog)
      dir0 = process_dirs[0]
      dir1 = process_dirs[1]
      assert no_error_log(dir0+"/"+LOG_FILE)
      assert no_error_log(dir1+"/"+LOG_FILE)
    end

    it "socket() should be in JSON for both processes" do 
      run_c_program(prog)
      dir0 = process_dirs[0]
      dir1 = process_dirs[1]
      assert_event_present("socket", true, File.read(dir0+"/0/"+JSON_FILE))
      assert_event_present("socket", true, File.read(dir1+"/0/"+JSON_FILE))
    end
  end
end
