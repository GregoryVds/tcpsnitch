# Purpose: test the JSON output file of a given TCP connection
require 'minitest/autorun'
require 'minitest/spec'
require 'minitest/reporters'
require './lib/lib.rb'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

describe 'tcp_spy' do
  MiniTest::Unit.after_tests { WebServer.stop }

  before do
    WebServer.start
    reset_dir(DEFAULT_PATH)
  end

  describe '2 TCP connections' do
    it 'should properly handle 2 consecutive connections' do
      run_c_program('consecutive_connections')
      pattern0 = [
        { type: TCP_EV_SOCKET }.ignore_extra_keys!,
        { type: TCP_EV_CLOSE }.ignore_extra_keys!
      ].ignore_extra_values!
      pattern1 = [
        { type: TCP_EV_SOCKET }.ignore_extra_keys!,
        { type: TCP_EV_CLOSE }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern0, read_json_as_array(0))
      assert_json_match(pattern1, read_json_as_array(1))
    end

    it 'should properly handle 2 concurrent connections' do
      run_c_program('concurrent_connections')
      pattern0 = [
        { type: TCP_EV_SOCKET }.ignore_extra_keys!,
        { type: TCP_EV_CLOSE }.ignore_extra_keys!
      ].ignore_extra_values!
      pattern1 = [
        { type: TCP_EV_SOCKET }.ignore_extra_keys!,
        { type: TCP_EV_CLOSE }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern0, read_json_as_array(0))
      assert_json_match(pattern1, read_json_as_array(1))
    end
  end

  describe 'an event' do
    it 'should have the correct shared fields' do
      run_c_program('socket')
      pattern = [
        {
          details: Hash,
          return_value: Integer,
          success: Boolean,
          timestamp: {
            sec: Integer,
            usec: Integer
          },
          type: String
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

  describe "a #{TCP_EV_SOCKET} event" do
    it "#{TCP_EV_SOCKET}should have the correct JSON fields" do
      run_c_program(TCP_EV_SOCKET)
      pattern = [
        {
          type: TCP_EV_SOCKET,
          details: {
            domain: String,
            protocol: Integer,
            sock_cloexec: Boolean,
            sock_nonblock: Boolean,
            type: String
          }
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

  addr = {
    sa_family: String,
    ip: String,
    port: String,
    hostname: String,
    service: String
  }

  describe "a #{TCP_EV_BIND} event" do
    it "#{TCP_EV_BIND} should have the correct JSON fields" do
      run_c_program(TCP_EV_BIND)
      pattern = [
        {
          type: TCP_EV_BIND,
          details: {
           	addr: addr
          }
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

  describe "a #{TCP_EV_CONNECT} event" do
    it "#{TCP_EV_CONNECT} should have the correct JSON fields" do
      run_c_program(TCP_EV_CONNECT)
      pattern = [
        {
          type: TCP_EV_CONNECT,
          details: {
            addr: addr,
          }
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

  describe "a #{TCP_EV_SHUTDOWN} event" do
    it "#{TCP_EV_SHUTDOWN} should have the correct JSON fields" do
      run_c_program(TCP_EV_SHUTDOWN)
      pattern = [
        {
          type: TCP_EV_SHUTDOWN,
          details: {
            shut_rd: Boolean,
            shut_wr: Boolean
          }
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

  describe "a #{TCP_EV_LISTEN} event" do
    it "#{TCP_EV_LISTEN} should have the correct JSON fields" do
      run_c_program(TCP_EV_LISTEN)
      pattern = [
        {
          type: TCP_EV_LISTEN,
          details: {
            backlog: Integer
          }
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

	sock_opt = {
		level: String,
   	optname: String,
		optlen: Integer
	}

  describe "a #{TCP_EV_GETSOCKOPT} event" do
    it "#{TCP_EV_GETSOCKOPT} should have the correct JSON fields" do
      run_c_program(TCP_EV_GETSOCKOPT)
      pattern = [
        {
          type: TCP_EV_GETSOCKOPT,
          details: sock_opt
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

  describe "a #{TCP_EV_SETSOCKOPT} event" do
    it "#{TCP_EV_SETSOCKOPT} should have the correct JSON fields" do
      run_c_program(TCP_EV_SETSOCKOPT)
      pattern = [
        {
          type: TCP_EV_SETSOCKOPT,
          details: sock_opt
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

	send_flags = {
		MSG_CONFIRM: Boolean,
		MSG_DONTROUTE: Boolean,
		MSG_DONTWAIT: Boolean,
		MSG_EOR: Boolean,
		MSG_MORE: Boolean,
		MSG_NOSIGNAL: Boolean,
		MSG_OOB: Boolean
	}
	
	recv_flags = {
		MSG_CMSG_CLOEXEC: Boolean,
		MSG_DONTWAIT: Boolean,
		MSG_ERRQUEUE: Boolean,
		MSG_OOB: Boolean,
		MSG_PEEK: Boolean,
		MSG_TRUNC: Boolean,
		MSG_WAITALL: Boolean	
	}

  describe "a #{TCP_EV_SEND} event" do
    it "#{TCP_EV_SEND} should have the correct JSON fields" do
      run_c_program(TCP_EV_SEND)
      pattern = [
        {
          type: TCP_EV_SEND,
          details: {
            bytes: Integer,
            flags: send_flags
          }
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

  describe "a #{TCP_EV_RECV} event" do
    it "#{TCP_EV_RECV} should have the correct JSON fields" do
      run_c_program(TCP_EV_RECV)
      pattern = [
        {
          type: TCP_EV_RECV,
          details: {
            bytes: Integer,
            flags: recv_flags
					}
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

  describe "a #{TCP_EV_SENDTO} event" do
    it "#{TCP_EV_SENDTO} should have the correct JSON fields" do
      run_c_program(TCP_EV_SENDTO)
      pattern = [
        {
          type: TCP_EV_SENDTO,
          details: {
            bytes: Integer,
            flags: send_flags
          }
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

  describe "a #{TCP_EV_RECVFROM} event" do
    it "#{TCP_EV_RECVFROM} should have the correct JSON fields" do
      run_c_program(TCP_EV_RECVFROM)
      pattern = [
        {
          type: TCP_EV_RECVFROM,
          details: {
            bytes: Integer,
            flags: recv_flags
          }
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

	msghdr = {
		control_data_len: Integer,
		control_data: Array,
		iovec: {
			iovec_count: Integer,
			iovec_sizes: Array
		}
	}
 
  describe "a #{TCP_EV_SENDMSG} event" do
    it "#{TCP_EV_SENDMSG} should have the correct JSON fields" do
      run_c_program(TCP_EV_SENDMSG)
      pattern = [
        {
          type: TCP_EV_SENDMSG,
          details: {
            bytes: Integer,
            flags: send_flags,
            msghdr: msghdr
          }
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

  describe "a #{TCP_EV_RECVMSG} event" do
    it "#{TCP_EV_RECVMSG} should have the correct JSON fields" do
      run_c_program(TCP_EV_RECVMSG)
      pattern = [
        {
          type: TCP_EV_RECVMSG,
          details: {
            bytes: Integer,
            flags: recv_flags,
            msghdr: msghdr
					}
				}.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

  describe "a #{TCP_EV_WRITE} event" do
    it "#{TCP_EV_WRITE} should have the correct JSON fields" do
      run_c_program(TCP_EV_WRITE)
      pattern = [
        {
          type: TCP_EV_WRITE,
          details: {
            bytes: Integer
          }
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

  describe "a #{TCP_EV_GETSOCKNAME} event" do
    it "#{TCP_EV_GETSOCKNAME} should have the correct JSON fields" do
      run_c_program(TCP_EV_GETSOCKNAME)
      pattern = [
        {
          type: TCP_EV_GETSOCKNAME,
          details: {
            addr: addr
          }
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

  describe "a #{TCP_EV_READ} event" do
    it "#{TCP_EV_READ} should have the correct JSON fields" do
      run_c_program(TCP_EV_READ)
      pattern = [
        {
          type: TCP_EV_READ,
          details: {
            bytes: Integer
          }
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

  describe "a #{TCP_EV_CLOSE} event" do
    it "#{TCP_EV_CLOSE} should have the correct JSON fields" do
      run_c_program(TCP_EV_CLOSE)
      pattern = [
        {
          type: TCP_EV_CLOSE,
          details: {
            detected: Boolean
          }
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

  describe "a #{TCP_EV_DUP} event" do
    it "#{TCP_EV_DUP} should have the correct JSON fields" do
      run_c_program(TCP_EV_DUP)
      pattern = [
        {type: TCP_EV_DUP}.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

  describe "a #{TCP_EV_DUP2} event" do
    it "#{TCP_EV_DUP2} should have the correct JSON fields" do
      run_c_program(TCP_EV_DUP2)
      pattern = [
        {
          type: TCP_EV_DUP2,
          details: {
            newfd: Integer
          }
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

  describe "a #{TCP_EV_DUP3} event" do
    it "#{TCP_EV_DUP3} should have the correct JSON fields" do
      run_c_program(TCP_EV_DUP3)
      pattern = [
        {
          type: TCP_EV_DUP3,
          details: {
            newfd: Integer,
            o_cloexec: Boolean
          }
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

  describe "a #{TCP_EV_WRITEV} event" do
    it "#{TCP_EV_WRITEV} should have the correct JSON fields" do
      run_c_program(TCP_EV_WRITEV)
      pattern = [
        {
          type: TCP_EV_WRITEV,
          details: {
            bytes: Integer,
            iovec: {
              iovec_count: Integer,
              iovec_sizes: Array
            }
          }
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

  describe "a #{TCP_EV_READV} event" do
    it "#{TCP_EV_READV} should have the correct JSON fields" do
      run_c_program(TCP_EV_READV)
      pattern = [
        {
          type: TCP_EV_READV,
          details: {
            bytes: Integer,
            iovec: {
              iovec_count: Integer,
              iovec_sizes: Array
            }
          }
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

  describe "a #{TCP_EV_IOCTL} event" do
    it "#{TCP_EV_IOCTL} should have the correct JSON fields" do
      run_c_program(TCP_EV_IOCTL)
      pattern = [
        {
          type: TCP_EV_IOCTL,
          details: {
            request: String
          }
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

  describe "a #{TCP_EV_SENDFILE} event" do
    it "#{TCP_EV_SENDFILE} should have the correct JSON fields" do
      run_c_program(TCP_EV_SENDFILE)
      pattern = [
        {
          type: TCP_EV_SENDFILE,
          details: {
            bytes: Integer
          }
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end
	
	poll_events = {
		POLLIN: Boolean,
		POLLPRI: Boolean,
		POLLOUT: Boolean,
		POLLRDHUP: Boolean,
		POLLERR: Boolean,
		POLLHUP: Boolean,
		POLLNVAL: Boolean
	}

  describe "a #{TCP_EV_POLL} event" do
    it "#{TCP_EV_POLL} should have the correct JSON fields" do
      run_c_program(TCP_EV_POLL)
      pattern = [
        {
          type: TCP_EV_POLL,
          details: {
            timeout: {
              seconds: Integer,
              nanoseconds: Integer
            },
            requested_events: poll_events,
            returned_events: poll_events
					}
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

  describe "a #{TCP_EV_PPOLL} event" do
    it "#{TCP_EV_PPOLL} should have the correct JSON fields" do
      run_c_program(TCP_EV_PPOLL)
      pattern = [
        {
          type: TCP_EV_PPOLL,
          details: {
            timeout: {
              seconds: Integer,
              nanoseconds: Integer
            },
            requested_events: poll_events,
            returned_events: poll_events
					}
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

	select_events = {
		READ: Boolean,
		WRITE: Boolean,
		EXCEPT: Boolean
	}

  describe "a #{TCP_EV_SELECT} event" do
    it "#{TCP_EV_SELECT} should have the correct JSON fields" do
      run_c_program(TCP_EV_SELECT)
      pattern = [
        {
          type: TCP_EV_SELECT,
          details: {
            timeout: {
              seconds: Integer,
              nanoseconds: Integer
            },
          	requested_events: select_events,
          	returned_events: select_events
					}
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

  describe "a #{TCP_EV_PSELECT} event" do
    it "#{TCP_EV_PSELECT} should have the correct JSON fields" do
      run_c_program(TCP_EV_PSELECT)
      pattern = [
        {
          type: TCP_EV_PSELECT,
          details: {
            timeout: {
              seconds: Integer,
              nanoseconds: Integer
            },
			    	requested_events: select_events,
          	returned_events: select_events
					}
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end

  describe "a #{TCP_EV_TCP_INFO} event" do
    it "#{TCP_EV_TCP_INFO} should have the correct JSON fields" do
      tcpsnitch("-u 1 -d #{TEST_DIR}", './c_programs/*socket.out')
      pattern = [
        {
          type: TCP_EV_TCP_INFO,
          details: {
            state: Integer,
            ca_state: Integer,
            retransmits: Integer,
            probes: Integer,
            backoff: Integer,
            options: Integer,
            snd_wscale: Integer,
            rcv_wscale: Integer,
            rto: Integer,
            ato: Integer,
            snd_mss: Integer,
            rcv_mss: Integer,
            unacked: Integer,
            sacked: Integer,
            lost: Integer,
            retrans: Integer,
            fackets: Integer,
            last_data_sent: Integer,
            last_ack_sent: Integer,
            last_data_recv: Integer,
            last_ack_recv: Integer,
            pmtu: Integer,
            rcv_ssthresh: Integer,
            rtt: Integer,
            rttvar: Integer,
            snd_ssthresh: Integer,
            snd_cwnd: Integer,
            advmss: Integer,
            reordering: Integer,
            rcv_rtt: Integer,
            rcv_space: Integer,
            total_retrans: Integer
          }
        }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern, read_json_as_array)
    end
  end
end
