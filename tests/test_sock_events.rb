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
    reset_dir(TEST_DIR)
  end

  describe '2 TCP connections' do
    it 'should properly handle 2 consecutive connections' do
      run_c_program('consecutive_connections')
      pattern0 = [
        { type: SOCK_EV_SOCKET }.ignore_extra_keys!,
        { type: SOCK_EV_CLOSE }.ignore_extra_keys!
      ].ignore_extra_values!
      pattern1 = [
        { type: SOCK_EV_SOCKET }.ignore_extra_keys!,
        { type: SOCK_EV_CLOSE }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern0, read_json_as_array(1))
      assert_json_match(pattern1, read_json_as_array(2))
    end

    it 'should properly handle 2 concurrent connections' do
      run_c_program('concurrent_connections')
      pattern0 = [
        { type: SOCK_EV_SOCKET }.ignore_extra_keys!,
        { type: SOCK_EV_CLOSE }.ignore_extra_keys!
      ].ignore_extra_values!
      pattern1 = [
        { type: SOCK_EV_SOCKET }.ignore_extra_keys!,
        { type: SOCK_EV_CLOSE }.ignore_extra_keys!
      ].ignore_extra_values!
      assert_json_match(pattern0, read_json_as_array(1))
      assert_json_match(pattern1, read_json_as_array(2))
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
          thread_id: Integer,
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

  addr = {
    sa_family: String,
    ip: String,
    port: String
  #  hostname: String,
  #  service: String
  }

  sock_opt = {
    level: String,
    optname: String,
    optlen: Integer,
    optval: Object
  }

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

  msghdr = {
    control_data_len: Integer,
    control_data: Array,
    iovec: {
      iovec_count: Integer,
      iovec_sizes: [Integer].ignore_extra_values!
    }
  }

  poll_events = {
    POLLIN: Boolean,
    POLLPRI: Boolean,
    POLLOUT: Boolean,
    POLLRDHUP: Boolean,
    POLLERR: Boolean,
    POLLHUP: Boolean,
    POLLNVAL: Boolean
  }

  timeout = {
    seconds: Integer,
    nanoseconds: Integer
  }

  select_events = {
    READ: Boolean,
    WRITE: Boolean,
    EXCEPT: Boolean
  }

  epoll_events = {
    EPOLLIN: Boolean,
    EPOLLOUT: Boolean,
    EPOLLRDHUP: Boolean,
    EPOLLPRI: Boolean,
    EPOLLERR: Boolean,
    EPOLLHUP: Boolean,
    EPOLLET: Boolean,
    EPOLLONESHOT: Boolean,
    EPOLLWAKEUP: Boolean
  }

  DETAILS = {
    SOCK_EV_SOCKET => {
      domain: String,
      protocol: Integer,
      SOCK_CLOEXEC: Boolean,
      SOCK_NONBLOCK: Boolean,
      type: String
    },
    SOCK_EV_BIND => {
      addr: addr
    },
    SOCK_EV_CONNECT => {
      addr: addr
    },
    SOCK_EV_SHUTDOWN => {
      SHUT_RD: Boolean,
      SHUT_WR: Boolean
    },
    SOCK_EV_LISTEN => {
      backlog: Integer
    },
    SOCK_EV_GETSOCKOPT => sock_opt,
    SOCK_EV_SETSOCKOPT => sock_opt,
    SOCK_EV_SEND => {
      bytes: Integer,
      flags: send_flags
    },
    SOCK_EV_RECV => {
      bytes: Integer,
      flags: recv_flags
    },
    SOCK_EV_SENDTO => {
      bytes: Integer,
      flags: send_flags,
      addr: addr
    },
    SOCK_EV_RECVFROM => {
      bytes: Integer,
      flags: recv_flags,
      addr: addr
    },
    SOCK_EV_SENDMSG => {
      bytes: Integer,
      flags: send_flags,
      msghdr: msghdr
    },
    SOCK_EV_RECVMSG => {
      bytes: Integer,
      flags: recv_flags,
      msghdr: msghdr
    },
    SOCK_EV_SENDMMSG => {
      bytes: Integer,
      flags: send_flags,
      mmsghdr_count: Integer,
      mmsghdr_vec: [
        {
          transmitted_bytes: Integer,
          msghdr: msghdr
        }
      ].ignore_extra_values!
    },
    SOCK_EV_RECVMMSG => {
      bytes: Integer,
      flags: recv_flags,
      mmsghdr_count: Integer,
      mmsghdr_vec: [
        {
          transmitted_bytes: Integer,
          msghdr: msghdr
        }
      ].ignore_extra_values!,
      timeout: timeout
    },
    SOCK_EV_WRITE => {
      bytes: Integer
    },
    SOCK_EV_READ => {
      bytes: Integer
    },
    SOCK_EV_GETSOCKNAME => {
      addr: addr
    },
    SOCK_EV_GETPEERNAME => {
      addr: addr
    },
    SOCK_EV_SOCKATMARK => {
    },
    SOCK_EV_ISFDTYPE => {
      fdtype: Integer
    },
    SOCK_EV_CLOSE => {},
    SOCK_EV_DUP => {},
    SOCK_EV_DUP2 => {
      newfd: Integer
    },
    SOCK_EV_DUP3 => {
      newfd: Integer,
      O_CLOEXEC: Boolean
    },
    SOCK_EV_WRITEV => {
      bytes: Integer,
      iovec: {
        iovec_count: Integer,
        iovec_sizes: [Integer].ignore_extra_values!
      }
    },
    SOCK_EV_READV => {
      bytes: Integer,
      iovec: {
        iovec_count: Integer,
        iovec_sizes: [Integer].ignore_extra_values!
      }
    },
    SOCK_EV_IOCTL => {
      request: String
    },
    SOCK_EV_SENDFILE => {
      bytes: Integer
    },
    SOCK_EV_POLL => {
      timeout: timeout,
      requested_events: poll_events,
      returned_events: poll_events
    },
    SOCK_EV_PPOLL => {
      timeout: timeout,
      requested_events: poll_events,
      returned_events: poll_events
    },
    SOCK_EV_SELECT => {
      timeout: timeout,
      requested_events: select_events,
      returned_events: select_events
    },
    SOCK_EV_PSELECT => {
      timeout: timeout,
      requested_events: select_events,
      returned_events: select_events
    },
    SOCK_EV_FCNTL => {
      cmd: String
    }.ignore_extra_keys!,
    SOCK_EV_EPOLL_CTL => {
      op: String,
      requested_events: epoll_events
    },
    SOCK_EV_EPOLL_WAIT => {
      timeout: Integer,
      returned_events: epoll_events
    },
    SOCK_EV_EPOLL_PWAIT => {
      timeout: Integer,
      returned_events: epoll_events
    },
    SOCK_EV_FDOPEN => {
      mode: String,
    },
    SOCK_EV_TCP_INFO => {
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
  }

  SOCKET_SYSCALLS.each do |syscall|
    describe "a #{syscall} event" do
      it "#{syscall} should have the correct JSON fields" do
        run_c_program(syscall)
        pattern = [
          {
            type: syscall,
            return_value: Integer,
            success: Boolean,
            thread_id: Integer,
            timestamp: {
              sec: Integer,
              usec: Integer
            },
            details: DETAILS[syscall]
          }.ignore_extra_keys!
        ].ignore_extra_values!
        assert_json_match(pattern, read_json_as_array)
      end
    end
  end
end
