NETSPY_PATH=`pwd`.chomp("\n")+"/../libnetspy.so"

LD_PRELOAD="LD_PRELOAD=../libnetspy.so"
PACKET_DRILL="packetdrill --tolerance_usecs=10000000"

# packetdrill scripts
PKT_SCRIPTS_PATH="./pkt_scripts"

DEFAULT_PATH="/tmp/netspy"
JSON_FILE="dump.json"
PCAP_FILE="dump.pcap"

# LOGS
LOG_FILE="*.log"
LOG_LVL_ERROR="ERROR"
LOG_LVL_WARN="WARN"
LOG_LVL_INFO="INFO"

# Env variables
ENV_PATH="NETSPY_PATH"
ENV_BYTES_IVAL="NETSPY_BYTES_IVAL"
ENV_MICROS_IVAL="NETSPY_MICROS_IVAL"
ENV_DEV="NETSPY_DEV"

# EVENTS

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
