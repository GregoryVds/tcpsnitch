# Purpose: test that all libc overrides do not crash the main process.
require 'minitest/autorun'
require 'minitest/spec'
require 'minitest/reporters'

require './common.rb'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

def no_error_log
  !errors_in_log?
end

# Not very robust but it seems that packetdrill always open another TCP connection
# before the script. So the first connection we are interested in is at /1/
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
=begin
  ____   ___   ____ _  _______ _____      _    ____ ___
 / ___| / _ \ / ___| |/ / ____|_   _|    / \  |  _ \_ _|
 \___ \| | | | |   | ' /|  _|   | |     / _ \ | |_) | |
  ___) | |_| | |___| . \| |___  | |    / ___ \|  __/| |
 |____/ \___/ \____|_|\_\_____| |_|   /_/   \_\_|  |___|

 sys/socket.h - Internet Protocol family

 functions: socket(), bind(), connect(), shutdown(), listen(), setsockopt(), 
 send(), recv(), sendto(), recvfrom(), sendmsg(),  recvmsg(),

=end

  describe "when calling #{TCP_EV_SOCKET}" do
    socket_stream = "socket_stream.out"
    socket_dgram = "socket_dgram.out"
    socket_fail = "socket_fail.out"

    it "#{socket_stream} should not crash" do
      assert run_c_program(socket_stream)
    end
    
    it "#{socket_stream} should give no ERROR log" do
      run_c_program(socket_stream)
      assert no_error_log
    end

    it "#{TCP_EV_SOCKET} should be tracked with #{socket_stream}" do
      run_c_program(socket_stream)
      assert_event_present(TCP_EV_SOCKET)
    end

    it "#{socket_dgram} should not crash" do
      assert run_c_program(socket_dgram)
    end

    it "#{socket_fail} should not crash" do
      assert run_c_program(socket_fail)
    end
  end

  describe "when calling #{TCP_EV_BIND}" do
    bind_stream = "bind_stream.out"
    bind_dgram = "bind_dgram.out"
    bind_fail = "bind_fail.out"
  
    it "#{bind_stream} should not crash" do
      assert run_c_program(bind_stream)
    end
    
    it "#{bind_stream} should give no ERROR log" do
      run_c_program(bind_stream)
      assert no_error_log
    end

    it "#{TCP_EV_BIND} should be tracked with #{bind_stream}" do
      run_c_program(bind_stream)
      assert_event_present(TCP_EV_BIND)
    end

    it "#{bind_dgram} should not crash" do
      assert run_c_program(bind_dgram)
    end

    it "#{bind_fail} should not crash" do
      assert run_c_program(bind_fail)
    end

    it "#{bind_fail} should give no ERROR log" do
      run_c_program(bind_fail)
      assert no_error_log
    end
  end

  describe "when calling #{TCP_EV_CONNECT}" do
    connect_stream = "connect_stream.out"
    connect_dgram = "connect_dgram.out"
    connect_fail = "connect_fail.out"
  
    it "#{connect_stream} should not crash" do
      assert run_c_program(connect_stream)
    end
    
    it "#{connect_stream} should give no ERROR log" do
      run_c_program(connect_stream)
      assert no_error_log
    end

    it "#{TCP_EV_CONNECT} should be tracked with #{connect_stream}" do
      run_c_program(connect_stream)
      assert_event_present(TCP_EV_CONNECT)
    end

    it "#{connect_dgram} should not crash" do
      assert run_c_program(connect_dgram)
    end

    it "#{connect_fail} should not crash" do
      assert run_c_program(connect_fail)
    end

    it "#{connect_fail} should give no ERROR log" do
      run_c_program(connect_fail)
      assert no_error_log
    end
  end
=begin
  describe "when calling #{TCP_EV_SHUTDOWN}" do
    it "#{TCP_EV_SHUTDOWN} should not crash" do
      assert run_c_program(PKT_SHUTDOWN_STREAM)
    end
    
    it "#{TCP_EV_SHUTDOWN} should give no ERROR log" do
      run_c_program(PKT_SHUTDOWN_STREAM)
      assert no_error_log
    end

    it "#{TCP_EV_SHUTDOWN} should be tracked" do
      run_c_program(PKT_SHUTDOWN_STREAM)
      assert_event_present(TCP_EV_SHUTDOWN)
    end

    it "#{TCP_EV_SHUTDOWN} should not crash" do
      assert run_c_program(PKT_SHUTDOWN_DGRAM)
    end

    it "#{TCP_EV_SHUTDOWN} should give no ERROR log" do
      run_c_program(PKT_SHUTDOWN_DGRAM)
      assert no_error_log
    end

    it "#{TCP_EV_SHUTDOWN} should not crash" do
      skip
    end
  end
  
  describe "when calling #{TCP_EV_LISTEN}" do
    it "#{TCP_EV_LISTEN} should not crash" do
      assert run_c_program(PKT_LISTEN_STREAM)
    end
    
    it "#{TCP_EV_LISTEN} should give no ERROR log" do
      run_c_program(PKT_LISTEN_STREAM)
      assert no_error_log
    end

    it "#{TCP_EV_LISTEN} should be tracked" do
      run_c_program(PKT_LISTEN_STREAM)
      assert_event_present(TCP_EV_LISTEN)
    end

    it "#{TCP_EV_LISTEN} should not crash" do
      skip
    end
  end

  describe "when calling #{TCP_EV_SETSOCKOPT}" do
    it "#{TCP_EV_SETSOCKOPT} should not crash" do
      assert run_c_program(PKT_SETSOCKOPT_STREAM)
    end
    
    it "#{TCP_EV_SETSOCKOPT} should give no ERROR log" do
      run_c_program(PKT_SETSOCKOPT_STREAM)
      assert no_error_log
    end

    it "#{TCP_EV_SETSOCKOPT} should be tracked" do
      run_c_program(PKT_SETSOCKOPT_STREAM)
      assert_event_present(TCP_EV_SETSOCKOPT)
    end

    it "#{TCP_EV_SETSOCKOPT} should not crash" do
      assert run_c_program(PKT_SETSOCKOPT_DGRAM)
    end

    it "#{TCP_EV_SETSOCKOPT} should give no ERROR log" do
      run_c_program(PKT_SETSOCKOPT_DGRAM)
      assert no_error_log
    end

    it "#{TCP_EV_SETSOCKOPT} should not crash" do
      skip
    end
  end

  describe "when calling #{TCP_EV_SEND}" do
    it "#{TCP_EV_SEND} should not crash" do
      assert run_c_program(PKT_SEND_STREAM)
    end
    
    it "#{TCP_EV_SEND} should give no ERROR log" do
      run_c_program(PKT_SEND_STREAM)
      assert no_error_log
    end

    it "#{TCP_EV_SEND} should be tracked" do
      run_c_program(PKT_SEND_STREAM)
      assert_event_present(TCP_EV_SEND)
    end

    it "#{TCP_EV_SEND} should not crash" do
      assert run_c_program(PKT_SEND_DGRAM)
    end

    it "#{TCP_EV_SEND} should give no ERROR log" do
      run_c_program(PKT_SEND_DGRAM)
      assert no_error_log
    end

    it "#{TCP_EV_SEND} should not crash" do
      skip
    end
  end

  describe "when calling #{TCP_EV_RECV}" do
    it "#{TCP_EV_RECV} should not crash" do
      assert run_c_program(PKT_RECV_STREAM)
    end
    
    it "#{TCP_EV_RECV} should give no ERROR log" do
      run_c_program(PKT_RECV_STREAM)
      assert no_error_log
    end

    it "#{TCP_EV_RECV} should be tracked" do
      run_c_program(PKT_RECV_STREAM)
      assert_event_present(TCP_EV_RECV)
    end

    it "#{TCP_EV_RECV} should not crash" do
      assert run_c_program(PKT_RECV_DGRAM)
    end

    it "#{TCP_EV_RECV} should give no ERROR log" do
      run_c_program(PKT_RECV_DGRAM)
      assert no_error_log
    end

    it "#{TCP_EV_RECV} should not crash" do
      skip
    end
  end

  describe "when calling #{TCP_EV_SENDTO}" do
    it "#{TCP_EV_SENDTO} should not crash" do
      assert run_c_program(PKT_SENDTO_STREAM)
    end
    
    it "#{TCP_EV_SENDTO} should give no ERROR log" do
      run_c_program(PKT_SENDTO_STREAM)
      assert no_error_log
    end

    it "#{TCP_EV_SENDTO} should be tracked" do
      run_c_program(PKT_SENDTO_STREAM)
      assert_event_present(TCP_EV_SENDTO)
    end

    it "#{TCP_EV_SENDTO} should not crash" do
      assert run_c_program(PKT_SENDTO_DGRAM)
    end

    it "#{TCP_EV_SENDTO} should give no ERROR log" do
      run_c_program(PKT_SENDTO_DGRAM)
      assert no_error_log
    end

    it "#{TCP_EV_SENDTO} should not crash" do
      skip
    end
  end

  describe "when calling #{TCP_EV_RECVFROM}" do
    it "#{TCP_EV_RECVFROM} should not crash" do
      assert run_c_program(PKT_RECVFROM_STREAM)
    end
    
    it "#{TCP_EV_RECVFROM} should give no ERROR log" do
      run_c_program(PKT_RECVFROM_STREAM)
      assert no_error_log
    end

    it "#{TCP_EV_RECVFROM} should be tracked" do
      run_c_program(PKT_RECVFROM_STREAM)
      assert_event_present(TCP_EV_RECVFROM)
    end

    it "#{TCP_EV_RECVFROM} should not crash" do
      assert run_c_program(PKT_RECVFROM_DGRAM)
    end

    it "#{TCP_EV_RECVFROM} should give no ERROR log" do
      run_c_program(PKT_RECVFROM_DGRAM)
      assert no_error_log
    end

    it "#{TCP_EV_RECVFROM} should not crash" do
      skip
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
