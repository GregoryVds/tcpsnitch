require 'tempfile'
require 'json_expressions/minitest'

NETSPY_PATH=`pwd`.chomp("\n")+"/../libnetspy.so"
puts NETSPY_PATH

LD_PRELOAD="LD_PRELOAD=../libnetspy.so"
PACKET_DRILL="packetdrill --tolerance_usecs=10000000"

# packetdrill scripts
PKT_SCRIPTS_PATH="./pkt_scripts"

DEFAULT_PATH="/tmp/netspy"
JSON_FILE="dump.json"
PCAP_FILE="dump.pcap"
LOG_FILE="log.txt"

# Env variables
ENV_PATH="NETSPY_PATH"
ENV_BYTES_IVAL="NETSPY_BYTES_IVAL"
ENV_MICROS_IVAL="NETSPY_MICROS_IVAL"

# Events

# sys/socket.h
TCP_EV_SOCKET="socket()"
TCP_EV_BIND="bind()"
TCP_EV_CONNECT="connect()"
TCP_EV_SHUTDOWN="shutdown()"
TCP_EV_LISTEN="listen()"
TCP_EV_SETSOCKOPT="setsockopt()"
TCP_EV_SEND="send()"
TCP_EV_RECV="recv()"
TCP_EV_SENDTO="sendto()"
TCP_EV_RECVFROM="recvfrom()"
TCP_EV_SENDMSG="sendmsg()"
TCP_EV_RECVMSG="recvmsg()"

# unistd.h
TCP_EV_CLOSE="close()"
TCP_EV_WRITE="write()"
TCP_EV_READ="read()"

# sys/uio.h
TCP_EV_WRITEV="writev()"
TCP_EV_READV="readv()"

# sys/sendfile.h
TCP_EV_SENDFILE="sendfile()"

# pool.h
TCP_EV_POLL="poll()"

TCP_EV_TCP_INFO="tcp_info"

# As suggested by Jansson library.
# http://stackoverflow.com/questions/3028243/check-if-ruby-object-is-a-boolean#answer-3028378
module Boolean; end
class TrueClass; include Boolean; end
class FalseClass; include Boolean; end

def mkdir(path)
  system("test -d #{path} || mkdir #{path}")
end

def rmdir(path)
  system("rm -rf #{path}")
end

def dir_exists?(path)
  system("test -d #{path}")
end

def contains?(dir, el)
  system("ls #{dir}/#{el} >/dev/null 2>&1")
end

def dir_empty?(path)
  !system("ls #{path}/* >/dev/null 2>&1")
end

def reset_dir(path)
  rmdir(path)
  mkdir(path)
end

def run_pkt_cmd_str(path, env='')
  cmd = "#{LD_PRELOAD} #{PACKET_DRILL} #{path} 2>/dev/null" 
  if env then env+' '+cmd else cmd end
end

def run_pkt_script(script, env='')
  file = Tempfile.new("foo")
  file.write(script)
  file.close
  rc = system(run_pkt_cmd_str(file.path, env)) 
  file.unlink
  rc
end

# Packetdrill forks a bunch of programs such as ip, sh, etc. Assuming the 
# DEFAULT_PATH was emptied before executing the test, then our log should be
# in the ONLY directory starting with packetdrill_*. In case it was not emptied, we should NOT expect last to be the last created directory.
def log_dir_str
  Dir[DEFAULT_PATH+"/packetdrill_*"].last
end

# Not very robust but it seems that packetdrill always open another TCP connection
# before the script. So the first connection we are interested in is at /1/
def json_str
  File.read(log_dir_str+"/1/"+JSON_FILE)
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
  assert_json_match(pattern, json_str)
end

