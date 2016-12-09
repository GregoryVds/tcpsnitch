
NETSPY_PATH=`pwd`.chomp("\n")+"/../libnetspy.so"

EXECUTABLE="../tcpsnitch"
LD_PRELOAD="LD_PRELOAD=../libtcpsnitch.so.1.0"
TEST_DIR="/tmp/netspy"

PACKET_DRILL="packetdrill --tolerance_usecs=10000000"

# packetdrill scripts
PKT_SCRIPTS_PATH="./pkt_scripts"

DEFAULT_PATH="/tmp/netspy"
JSON_FILE="dump.json"
PCAP_FILE="dump.pcap"

# LOGS
PROCESS_DIR_REGEX="*.out*"
LOG_FILE="*.log"
LOG_LABEL_ERROR="[ERROR]"
LOG_LABEL_WARN="[WARN]"
LOG_LABEL_INFO="[INFO]"

# LOGS LVL
LOG_LVL_ALWAYS  = 0
LOG_LVL_ERROR   = 1
LOG_LVL_WARN    = 2
LOG_LVL_INFO    = 3
LOG_LVL_DEBUG   = 4

# EVENTS

# sys/socket.h
TCP_EV_SOCKET="socket"
TCP_EV_BIND="bind"
TCP_EV_CONNECT="connect"
TCP_EV_SHUTDOWN="shutdown"
TCP_EV_LISTEN="listen"
TCP_EV_SETSOCKOPT="setsockopt"
TCP_EV_SEND="send"
TCP_EV_RECV="recv"
TCP_EV_SENDTO="sendto"
TCP_EV_RECVFROM="recvfrom"
TCP_EV_SENDMSG="sendmsg"
TCP_EV_RECVMSG="recvmsg"

# unistd.h
TCP_EV_CLOSE="close"
TCP_EV_WRITE="write"
TCP_EV_READ="read"

# sys/uio.h
TCP_EV_WRITEV="writev"
TCP_EV_READV="readv"

SOCKET_SYSCALLS = [
  TCP_EV_SOCKET,
  TCP_EV_BIND,
  TCP_EV_CONNECT,
  TCP_EV_SHUTDOWN,
  TCP_EV_LISTEN,
  TCP_EV_SETSOCKOPT,
  TCP_EV_SEND,
  TCP_EV_RECV,
  TCP_EV_SENDTO,
  TCP_EV_RECVFROM,
  TCP_EV_SENDMSG,
  TCP_EV_RECVMSG,
  TCP_EV_WRITE,
  TCP_EV_READ,
  TCP_EV_CLOSE,
  TCP_EV_WRITEV,
  TCP_EV_READV
]

# sys/sendfile.h
TCP_EV_SENDFILE="sendfile"

# pool.h
TCP_EV_POLL="poll"

TCP_EV_TCP_INFO="tcp_info"
