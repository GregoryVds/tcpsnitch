# Purpose: test that all libc overrides do not crash the main process, do not
# generate any error log and are present in the JSON trace.
require 'minitest/autorun'
require 'minitest/spec'
require 'minitest/reporters'
require './lib/lib.rb'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

def no_error_log(log_file=log_file_str)
  !errors_in_log?(log_file)
end

def assert_event_present(type, success=true,json= read_json_as_array)
  pattern =  [
    {
      type: type,
      success: success
    }.ignore_extra_keys!
  ].ignore_extra_values!
  assert_json_match(pattern, json)
end

describe "libc overrides" do
  before do WebServer.start end
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
      unless [SOCK_EV_LISTEN, SOCK_EV_SOCKATMARK].include?(syscall)
        it "#{dgram} should not crash" do
          assert run_c_program(dgram)
        end

        it "should be in JSON with #{dgram}" do
          run_c_program(stream)
          assert_event_present(syscall)
        end
      end

      unless [SOCK_EV_POLL, SOCK_EV_PPOLL, SOCK_EV_SOCKATMARK].include?(syscall) 
        it "#{failing} should not crash" do
          assert run_c_program(failing)
        end
      end

      # SOCKET: No log file if no TCP connection.
      # CLOSE: No log file if no TCP connection. How to fail close() with con?
      unless [SOCK_EV_SOCKET, SOCK_EV_CLOSE, SOCK_EV_POLL, 
              SOCK_EV_PPOLL, SOCK_EV_SOCKATMARK].include?(syscall)
        it "#{failing} should log no ERROR" do
          run_c_program(failing)
          assert no_error_log
        end
      end

      # SOCKET: No JSON if no TCP connection.
      # LISTEN: How to fail listen() on valid TCP socket? 
      # CLOSE: How to fail close() on valid TCP socket?
      unless [SOCK_EV_SOCKET, SOCK_EV_LISTEN, SOCK_EV_CLOSE, SOCK_EV_DUP, 
              SOCK_EV_POLL, SOCK_EV_PPOLL, SOCK_EV_FCNTL, SOCK_EV_EPOLL_WAIT,
              SOCK_EV_EPOLL_PWAIT, SOCK_EV_SOCKATMARK, 
              SOCK_EV_ISFDTYPE].include?(syscall)
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
      assert file_exists?(dir0+"/1.json")
      assert file_exists?(dir1+"/1.json")
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
      trace1 = File.read(process_dirs[0]+"/1.json")
      trace2 = File.read(process_dirs[1]+"/1.json")
      assert_event_present("socket", true, wrap_as_array(trace1))
      assert_event_present("socket", true, wrap_as_array(trace2))
    end
  end

  [SOCK_EV_DUP, SOCK_EV_DUP2, SOCK_EV_DUP3, SOCK_EV_ACCEPT, SOCK_EV_ACCEPT4].each do |syscall|
    describe "a #{syscall} event which creates a new socket" do
      it "#{syscall} should have the correct JSON fields" do
        run_c_program(syscall)
        pattern = [{ type: syscall }.ignore_extra_keys!].ignore_extra_values!
        assert_json_match(pattern, read_json_as_array(1))
        assert_json_match(pattern, read_json_as_array(2))
      end
    end
  end
end
