# Purpose: test that all libc overrides do not crash the main process.
require 'minitest/autorun'
require 'minitest/spec'
require 'minitest/reporters'

require './common.rb'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

def no_error_log
  !errors_in_log?(log_file_str("packetdrill"))
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
  assert_json_match(pattern, read_json("packetdrill", 1))
end


describe "libc overrides" do
  before do
    reset_dir(DEFAULT_PATH) 
  end

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
    it "#{TCP_EV_SOCKET} should not crash with SOCK_STREAM" do
      assert run_pkt_script(PKT_SOCKET_STREAM)
    end
    
    it "#{TCP_EV_SOCKET} should give no ERROR log with SOCK_STREAM" do
      run_pkt_script(PKT_SOCKET_STREAM)
      assert no_error_log
    end

    it "#{TCP_EV_SOCKET} should be tracked with SOCK_STREAM" do
      run_pkt_script(PKT_SOCKET_STREAM)
      assert_event_present(TCP_EV_SOCKET)
    end

    it "#{TCP_EV_SOCKET} should not crash with SOCK_DGRAM" do
      assert run_pkt_script(PKT_SOCKET_DGRAM)
    end

    it "#{TCP_EV_SOCKET} should give no ERROR log with SOCK_DGRAM" do
      run_pkt_script(PKT_SOCKET_DGRAM)
      assert no_error_log
    end

    it "#{TCP_EV_SOCKET} should not crash when failing" do
      skip
    end
  end

  describe "when calling #{TCP_EV_BIND}" do
    it "#{TCP_EV_BIND} should not crash with SOCK_STREAM" do
      assert run_pkt_script(PKT_BIND_STREAM)
    end
    
    it "#{TCP_EV_BIND} should give no ERROR log with SOCK_STREAM" do
      run_pkt_script(PKT_BIND_STREAM)
      assert no_error_log
    end

    it "#{TCP_EV_BIND} should be tracked with SOCK_STREAM" do
      run_pkt_script(PKT_BIND_STREAM)
      assert_event_present(TCP_EV_BIND)
    end

    it "#{TCP_EV_BIND} should not crash with SOCK_DGRAM" do
      assert run_pkt_script(PKT_BIND_DGRAM)
    end

    it "#{TCP_EV_BIND} should give no ERROR log with SOCK_DGRAM" do
      run_pkt_script(PKT_BIND_DGRAM)
      assert no_error_log
    end

    it "#{TCP_EV_BIND} should not crash when failing" do
      skip
    end
  end

  describe "when calling #{TCP_EV_CONNECT}" do
    it "#{TCP_EV_CONNECT} should not crash with SOCK_STREAM" do
      assert run_pkt_script(PKT_CONNECT_STREAM)
    end
    
    it "#{TCP_EV_CONNECT} should give no ERROR log with SOCK_STREAM" do
      run_pkt_script(PKT_CONNECT_STREAM)
      assert no_error_log
    end

    it "#{TCP_EV_CONNECT} should be tracked with SOCK_STREAM" do
      run_pkt_script(PKT_CONNECT_STREAM)
      assert_event_present(TCP_EV_CONNECT)
    end

    it "#{TCP_EV_CONNECT} should not crash with SOCK_DGRAM" do
      assert run_pkt_script(PKT_CONNECT_DGRAM)
    end

    it "#{TCP_EV_CONNECT} should give no ERROR log with SOCK_DGRAM" do
      run_pkt_script(PKT_CONNECT_DGRAM)
      assert no_error_log
    end

    it "#{TCP_EV_CONNECT} should not crash when failing" do
      skip
    end
  end

  describe "when calling #{TCP_EV_SHUTDOWN}" do
    it "#{TCP_EV_SHUTDOWN} should not crash with SOCK_STREAM" do
      assert run_pkt_script(PKT_SHUTDOWN_STREAM)
    end
    
    it "#{TCP_EV_SHUTDOWN} should give no ERROR log with SOCK_STREAM" do
      run_pkt_script(PKT_SHUTDOWN_STREAM)
      assert no_error_log
    end

    it "#{TCP_EV_SHUTDOWN} should be tracked with SOCK_STREAM" do
      run_pkt_script(PKT_SHUTDOWN_STREAM)
      assert_event_present(TCP_EV_SHUTDOWN)
    end

    it "#{TCP_EV_SHUTDOWN} should not crash with SOCK_DGRAM" do
      assert run_pkt_script(PKT_SHUTDOWN_DGRAM)
    end

    it "#{TCP_EV_SHUTDOWN} should give no ERROR log with SOCK_DGRAM" do
      run_pkt_script(PKT_SHUTDOWN_DGRAM)
      assert no_error_log
    end

    it "#{TCP_EV_SHUTDOWN} should not crash when failing" do
      skip
    end
  end
  
  describe "when calling #{TCP_EV_LISTEN}" do
    it "#{TCP_EV_LISTEN} should not crash with SOCK_STREAM" do
      assert run_pkt_script(PKT_LISTEN_STREAM)
    end
    
    it "#{TCP_EV_LISTEN} should give no ERROR log with SOCK_STREAM" do
      run_pkt_script(PKT_LISTEN_STREAM)
      assert no_error_log
    end

    it "#{TCP_EV_LISTEN} should be tracked with SOCK_STREAM" do
      run_pkt_script(PKT_LISTEN_STREAM)
      assert_event_present(TCP_EV_LISTEN)
    end

    it "#{TCP_EV_LISTEN} should not crash when failing" do
      skip
    end
  end

  describe "when calling #{TCP_EV_SETSOCKOPT}" do
    it "#{TCP_EV_SETSOCKOPT} should not crash with SOCK_STREAM" do
      assert run_pkt_script(PKT_SETSOCKOPT_STREAM)
    end
    
    it "#{TCP_EV_SETSOCKOPT} should give no ERROR log with SOCK_STREAM" do
      run_pkt_script(PKT_SETSOCKOPT_STREAM)
      assert no_error_log
    end

    it "#{TCP_EV_SETSOCKOPT} should be tracked with SOCK_STREAM" do
      run_pkt_script(PKT_SETSOCKOPT_STREAM)
      assert_event_present(TCP_EV_SETSOCKOPT)
    end

    it "#{TCP_EV_SETSOCKOPT} should not crash with SOCK_DGRAM" do
      assert run_pkt_script(PKT_SETSOCKOPT_DGRAM)
    end

    it "#{TCP_EV_SETSOCKOPT} should give no ERROR log with SOCK_DGRAM" do
      run_pkt_script(PKT_SETSOCKOPT_DGRAM)
      assert no_error_log
    end

    it "#{TCP_EV_SETSOCKOPT} should not crash when failing" do
      skip
    end
  end

  describe "when calling #{TCP_EV_SEND}" do
    it "#{TCP_EV_SEND} should not crash with SOCK_STREAM" do
      assert run_pkt_script(PKT_SEND_STREAM)
    end
    
    it "#{TCP_EV_SEND} should give no ERROR log with SOCK_STREAM" do
      run_pkt_script(PKT_SEND_STREAM)
      assert no_error_log
    end

    it "#{TCP_EV_SEND} should be tracked with SOCK_STREAM" do
      run_pkt_script(PKT_SEND_STREAM)
      assert_event_present(TCP_EV_SEND)
    end

    it "#{TCP_EV_SEND} should not crash with SOCK_DGRAM" do
      assert run_pkt_script(PKT_SEND_DGRAM)
    end

    it "#{TCP_EV_SEND} should give no ERROR log with SOCK_DGRAM" do
      run_pkt_script(PKT_SEND_DGRAM)
      assert no_error_log
    end

    it "#{TCP_EV_SEND} should not crash when failing" do
      skip
    end
  end

  describe "when calling #{TCP_EV_RECV}" do
    it "#{TCP_EV_RECV} should not crash with SOCK_STREAM" do
      assert run_pkt_script(PKT_RECV_STREAM)
    end
    
    it "#{TCP_EV_RECV} should give no ERROR log with SOCK_STREAM" do
      run_pkt_script(PKT_RECV_STREAM)
      assert no_error_log
    end

    it "#{TCP_EV_RECV} should be tracked with SOCK_STREAM" do
      run_pkt_script(PKT_RECV_STREAM)
      assert_event_present(TCP_EV_RECV)
    end

    it "#{TCP_EV_RECV} should not crash with SOCK_DGRAM" do
      assert run_pkt_script(PKT_RECV_DGRAM)
    end

    it "#{TCP_EV_RECV} should give no ERROR log with SOCK_DGRAM" do
      run_pkt_script(PKT_RECV_DGRAM)
      assert no_error_log
    end

    it "#{TCP_EV_RECV} should not crash when failing" do
      skip
    end
  end

  describe "when calling #{TCP_EV_SENDTO}" do
    it "#{TCP_EV_SENDTO} should not crash with SOCK_STREAM" do
      assert run_pkt_script(PKT_SENDTO_STREAM)
    end
    
    it "#{TCP_EV_SENDTO} should give no ERROR log with SOCK_STREAM" do
      run_pkt_script(PKT_SENDTO_STREAM)
      assert no_error_log
    end

    it "#{TCP_EV_SENDTO} should be tracked with SOCK_STREAM" do
      run_pkt_script(PKT_SENDTO_STREAM)
      assert_event_present(TCP_EV_SENDTO)
    end

    it "#{TCP_EV_SENDTO} should not crash with SOCK_DGRAM" do
      assert run_pkt_script(PKT_SENDTO_DGRAM)
    end

    it "#{TCP_EV_SENDTO} should give no ERROR log with SOCK_DGRAM" do
      run_pkt_script(PKT_SENDTO_DGRAM)
      assert no_error_log
    end

    it "#{TCP_EV_SENDTO} should not crash when failing" do
      skip
    end
  end

  describe "when calling #{TCP_EV_RECVFROM}" do
    it "#{TCP_EV_RECVFROM} should not crash with SOCK_STREAM" do
      assert run_pkt_script(PKT_RECVFROM_STREAM)
    end
    
    it "#{TCP_EV_RECVFROM} should give no ERROR log with SOCK_STREAM" do
      run_pkt_script(PKT_RECVFROM_STREAM)
      assert no_error_log
    end

    it "#{TCP_EV_RECVFROM} should be tracked with SOCK_STREAM" do
      run_pkt_script(PKT_RECVFROM_STREAM)
      assert_event_present(TCP_EV_RECVFROM)
    end

    it "#{TCP_EV_RECVFROM} should not crash with SOCK_DGRAM" do
      assert run_pkt_script(PKT_RECVFROM_DGRAM)
    end

    it "#{TCP_EV_RECVFROM} should give no ERROR log with SOCK_DGRAM" do
      run_pkt_script(PKT_RECVFROM_DGRAM)
      assert no_error_log
    end

    it "#{TCP_EV_RECVFROM} should not crash when failing" do
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

=end

  describe "when calling #{TCP_EV_WRITE}" do
    it "#{TCP_EV_WRITE} should not crash with SOCK_STREAM" do
      assert run_pkt_script(PKT_WRITE_STREAM)
    end
    
    it "#{TCP_EV_WRITE} should give no ERROR log with SOCK_STREAM" do
      run_pkt_script(PKT_WRITE_STREAM)
      assert no_error_log
    end

    it "#{TCP_EV_WRITE} should be tracked with SOCK_STREAM" do
      run_pkt_script(PKT_WRITE_STREAM)
      assert_event_present(TCP_EV_WRITE)
    end

    it "#{TCP_EV_WRITE} should not crash with SOCK_DGRAM" do
      assert run_pkt_script(PKT_WRITE_DGRAM)
    end

    it "#{TCP_EV_WRITE} should give no ERROR log with SOCK_DGRAM" do
      run_pkt_script(PKT_WRITE_DGRAM)
      assert no_error_log
    end

    it "#{TCP_EV_WRITE} should not crash when failing" do
      skip
    end
  end

  describe "when calling #{TCP_EV_READ}" do
    it "#{TCP_EV_READ} should not crash with SOCK_STREAM" do
      assert run_pkt_script(PKT_READ_STREAM)
    end
    
    it "#{TCP_EV_READ} should give no ERROR log with SOCK_STREAM" do
      run_pkt_script(PKT_READ_STREAM)
      assert no_error_log
    end

    it "#{TCP_EV_READ} should be tracked with SOCK_STREAM" do
      run_pkt_script(PKT_READ_STREAM)
      assert_event_present(TCP_EV_READ)
    end

    it "#{TCP_EV_READ} should not crash with SOCK_DGRAM" do
      assert run_pkt_script(PKT_READ_DGRAM)
    end

    it "#{TCP_EV_READ} should give no ERROR log with SOCK_DGRAM" do
      run_pkt_script(PKT_READ_DGRAM)
      assert no_error_log
    end

    it "#{TCP_EV_READ} should not crash when failing" do
      skip
    end
  end

  describe "when calling #{TCP_EV_CLOSE}" do
    it "#{TCP_EV_CLOSE} should not crash with SOCK_STREAM" do
      assert run_pkt_script(PKT_CLOSE_STREAM)
    end
    
    it "#{TCP_EV_CLOSE} should give no ERROR log with SOCK_STREAM" do
      run_pkt_script(PKT_CLOSE_STREAM)
      assert no_error_log
    end

    it "#{TCP_EV_CLOSE} should be tracked with SOCK_STREAM" do
      run_pkt_script(PKT_CLOSE_STREAM)
      assert_event_present(TCP_EV_CLOSE)
    end

    it "#{TCP_EV_CLOSE} should not crash with SOCK_DGRAM" do
      assert run_pkt_script(PKT_CLOSE_DGRAM)
    end

    it "#{TCP_EV_CLOSE} should give no ERROR log with SOCK_DGRAM" do
      run_pkt_script(PKT_CLOSE_DGRAM)
      assert no_error_log
    end

    it "#{TCP_EV_CLOSE} should not crash when failing" do
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

