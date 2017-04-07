#define _GNU_SOURCE

#ifndef STRING_BUILDERS_H
#define STRING_BUILDERS_H

#include <arpa/inet.h>
#include <asm-generic/ioctls.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/ax25.h>
#include <linux/if_eql.h>
#include <linux/if_plip.h>
#include <linux/if_ppp.h>
#include <linux/ipx.h>
#include <linux/mroute.h>
#include <linux/sockios.h>
#include <linux/wireless.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include "sock_events.h"
#ifdef __ANDROID__
#include <linux/udp.h>
#else
#include <netinet/udp.h>
#endif
#include <sys/socket.h>
#include <unistd.h>

#define MEMBER_SIZE(type, member) sizeof(((type *)0)->member)

typedef struct {
        int cons;
        const char str[40];
} IntStrPair;

char *alloc_ip_str(const struct sockaddr *addr);
char *alloc_port_str(const struct sockaddr *addr);
char *alloc_addr_str(const struct sockaddr *addr);
bool alloc_name_str(const struct sockaddr *addr, socklen_t len, char **name,
                    char **serv);

char *alloc_concat_path(const char *path1, const char *path2);
char *alloc_append_int_to_path(const char *path1, int i);

char *alloc_android_opt_d(void);
char *alloc_pcap_path_str(Socket *con);
char *alloc_json_path_str(Socket *con);

char *alloc_cmdline_str(void);
char *alloc_app_name(void);

char *alloc_error_str(int err);

#ifdef __ANDROID__
char *alloc_property(const char *property);
#endif

char *alloc_str_opt(const char *opt);

char *alloc_sock_domain_str(int domain);
char *alloc_sock_type_str(int type);

char *alloc_sockopt_level(int level);
char *alloc_sockoptname(int level, int optname);

char *alloc_fcntl_cmd_str(int cmd);
char *alloc_ioctl_request_str(int request);
char *alloc_errno_str(int err);

#define ADD(constant) \
        { constant, #constant }

/* We use #ifdef directives to produce code that is easily portable on multiple
 * libc versions which may define different set of constants. */

static const IntStrPair SOCKET_DOMAINS[] = {
#ifdef AF_UNIX
    ADD(AF_UNIX),
#endif
#ifdef AF_INET
    ADD(AF_INET),
#endif
#ifdef AF_INET6
    ADD(AF_INET6),
#endif
#ifdef AF_IPX
    ADD(AF_IPX),
#endif
#ifdef AF_NETLINK
    ADD(AF_NETLINK),
#endif
#ifdef AF_PACKET
    ADD(AF_PACKET)
#endif
};

static const IntStrPair SOCKET_TYPES[] = {
#ifdef SOCK_STREAM
    ADD(SOCK_STREAM),
#endif
#ifdef SOCK_DGRAM
    ADD(SOCK_DGRAM),
#endif
#ifdef SOCK_SEQPACKET
    ADD(SOCK_SEQPACKET),
#endif
#ifdef SOCK_RAW
    ADD(SOCK_RAW),
#endif
#ifdef SOCK_RDM
    ADD(SOCK_RDM),
#endif
#ifdef SOCK_PACKET
    ADD(SOCK_PACKET)
#endif
};

static const IntStrPair SOCKOPT_LEVELS[] = {
#ifdef IPPROTO_IP
    ADD(IPPROTO_IP),
#endif
#ifdef SOL_SOCKET
    ADD(SOL_SOCKET),
#endif
#ifdef IPPROTO_TCP
    ADD(IPPROTO_TCP),
#endif
#ifdef IPPROTO_UDP
    ADD(IPPROTO_UDP),
#endif
#ifdef IPPROTO_IPV6
    ADD(IPPROTO_IPV6),
#endif
#ifdef SOL_PACKET
    ADD(SOL_PACKET)
#endif
};

static const IntStrPair SOL_SOCKET_OPTIONS[] = {
#ifdef SO_DEBUG
    ADD(SO_DEBUG),
#endif
#ifdef SO_REUSEADDR
    ADD(SO_REUSEADDR),
#endif
#ifdef SO_TYPE
    ADD(SO_TYPE),
#endif
#ifdef SO_ERROR
    ADD(SO_ERROR),
#endif
#ifdef SO_DONTROUTE
    ADD(SO_DONTROUTE),
#endif
#ifdef SO_BROADCAST
    ADD(SO_BROADCAST),
#endif
#ifdef SO_SNDBUF
    ADD(SO_SNDBUF),
#endif
#ifdef SO_RCVBUF
    ADD(SO_RCVBUF),
#endif
#ifdef SO_SNDBUFFORCE
    ADD(SO_SNDBUFFORCE),
#endif
#ifdef SO_RCVBUFFORCE
    ADD(SO_RCVBUFFORCE),
#endif
#ifdef SO_KEEPALIVE
    ADD(SO_KEEPALIVE),
#endif
#ifdef SO_OOBINLINE
    ADD(SO_OOBINLINE),
#endif
#ifdef SO_NO_CHECK
    ADD(SO_NO_CHECK),
#endif
#ifdef SO_PRIORITY
    ADD(SO_PRIORITY),
#endif
#ifdef SO_LINGER
    ADD(SO_LINGER),
#endif
#ifdef SO_BSDCOMPAT
    ADD(SO_BSDCOMPAT),
#endif
#ifdef SO_REUSEPORT
    ADD(SO_REUSEPORT),
#endif
#ifdef SO_PASSCRED
    ADD(SO_PASSCRED),
#endif
#ifdef SO_PASSCRED
    ADD(SO_PASSCRED),
#endif
#ifdef SO_PEERCRED
    ADD(SO_PEERCRED),
#endif
#ifdef SO_RCVLOWAT
    ADD(SO_RCVLOWAT),
#endif
#ifdef SO_SNDLOWAT
    ADD(SO_SNDLOWAT),
#endif
#ifdef SO_RCVTIMEO
    ADD(SO_RCVTIMEO),
#endif
#ifdef SO_SNDTIMEO
    ADD(SO_SNDTIMEO),
#endif
#ifdef SO_SECURITY_AUTHENTICATION
    ADD(SO_SECURITY_AUTHENTICATION),
#endif
#ifdef SO_SECURITY_ENCRYPTION_TRANSPORT
    ADD(SO_SECURITY_ENCRYPTION_TRANSPORT),
#endif
#ifdef SO_SECURITY_ENCRYPTION_NETWORK
    ADD(SO_SECURITY_ENCRYPTION_NETWORK),
#endif
#ifdef SO_BINDTODEVICE
    ADD(SO_BINDTODEVICE),
#endif
#ifdef SO_ATTACH_FILTER
    ADD(SO_ATTACH_FILTER),
#endif
#ifdef SO_DETACH_FILTER
    ADD(SO_DETACH_FILTER),
#endif
#ifdef SO_GET_FILTER
    ADD(SO_GET_FILTER),
#endif
#ifdef SO_PEERNAME
    ADD(SO_PEERNAME),
#endif
#ifdef SO_TIMESTAMP
    ADD(SO_TIMESTAMP),
#endif
#ifdef SO_TIMESTAMP
    ADD(SO_TIMESTAMP),
#endif
#ifdef SO_ACCEPTCONN
    ADD(SO_ACCEPTCONN),
#endif
#ifdef SO_PEERSEC
    ADD(SO_PEERSEC),
#endif
#ifdef SO_PASSSEC
    ADD(SO_PASSSEC),
#endif
#ifdef SO_TIMESTAMPNS
    ADD(SO_TIMESTAMPNS),
#endif
#ifdef SO_MARK
    ADD(SO_MARK),
#endif
#ifdef SO_TIMESTAMPING
    ADD(SO_TIMESTAMPING),
#endif
#ifdef SO_PROTOCOL
    ADD(SO_PROTOCOL),
#endif
#ifdef SO_DOMAIN
    ADD(SO_DOMAIN),
#endif
#ifdef SO_RXQ_OVFL
    ADD(SO_RXQ_OVFL),
#endif
#ifdef SO_WIFI_STATUS
    ADD(SO_WIFI_STATUS),
#endif
#ifdef SO_PEEK_OFF
    ADD(SO_PEEK_OFF),
#endif
#ifdef SO_NOFCS
    ADD(SO_NOFCS),
#endif
#ifdef SO_LOCK_FILTER
    ADD(SO_LOCK_FILTER),
#endif
#ifdef SO_SELECT_ERR_QUEUE
    ADD(SO_SELECT_ERR_QUEUE),
#endif
#ifdef SO_BUSY_POLL
    ADD(SO_BUSY_POLL),
#endif
#ifdef SO_MAX_PACING_RATE
    ADD(SO_MAX_PACING_RATE),
#endif
#ifdef SO_BPF_EXTENSIONS
    ADD(SO_BPF_EXTENSIONS)
#endif
};

static const IntStrPair IPPROTO_IP_OPTIONS[] = {
#ifdef IP_TOS
    ADD(IP_TOS),
#endif
#ifdef IP_TTL
    ADD(IP_TTL),
#endif
#ifdef IP_HDRINCL
    ADD(IP_HDRINCL),
#endif
#ifdef IP_OPTIONS
    ADD(IP_OPTIONS),
#endif
#ifdef IP_ROUTER_ALERT
    ADD(IP_ROUTER_ALERT),
#endif
#ifdef IP_RECVOPTS
    ADD(IP_RECVOPTS),
#endif
#ifdef IP_RETOPTS
    ADD(IP_RETOPTS),
#endif
#ifdef IP_PKTINFO
    ADD(IP_PKTINFO),
#endif
#ifdef IP_PKTOPTIONS
    ADD(IP_PKTOPTIONS),
#endif
#ifdef IP_MTU_DISCOVER
    ADD(IP_MTU_DISCOVER),
#endif
#ifdef IP_RECVERR
    ADD(IP_RECVERR),
#endif
#ifdef IP_RECVTTL
    ADD(IP_RECVTTL),
#endif
#ifdef IP_RECVTOS
    ADD(IP_RECVTOS),
#endif
#ifdef IP_MTU
    ADD(IP_MTU),
#endif
#ifdef IP_FREEBIND
    ADD(IP_FREEBIND),
#endif
#ifdef IP_IPSEC_POLICY
    ADD(IP_IPSEC_POLICY),
#endif
#ifdef IP_XFRM_POLICY
    ADD(IP_XFRM_POLICY),
#endif
#ifdef IP_PASSSEC
    ADD(IP_PASSSEC),
#endif
#ifdef IP_TRANSPARENT
    ADD(IP_TRANSPARENT),
#endif
#ifdef IP_RECVRETOPTS
    ADD(IP_RECVRETOPTS),
#endif
#ifdef IP_ORIGDSTADDR
    ADD(IP_ORIGDSTADDR),
#endif
#ifdef IP_RECVORIGDSTADDR
    ADD(IP_RECVORIGDSTADDR),
#endif
#ifdef IP_MINTTL
    ADD(IP_MINTTL),
#endif
#ifdef IP_NODEFRAG
    ADD(IP_NODEFRAG),
#endif
#ifdef IP_MULTICAST_IF
    ADD(IP_MULTICAST_IF),
#endif
#ifdef IP_MULTICAST_TTL
    ADD(IP_MULTICAST_TTL),
#endif
#ifdef IP_MULTICAST_LOOP
    ADD(IP_MULTICAST_LOOP),
#endif
#ifdef IP_ADD_MEMBERSHIP
    ADD(IP_ADD_MEMBERSHIP),
#endif
#ifdef IP_DROP_MEMBERSHIP
    ADD(IP_DROP_MEMBERSHIP),
#endif
#ifdef IP_UNBLOCK_SOURCE
    ADD(IP_UNBLOCK_SOURCE),
#endif
#ifdef IP_BLOCK_SOURCE
    ADD(IP_BLOCK_SOURCE),
#endif
#ifdef IP_ADD_SOURCE_MEMBERSHIP
    ADD(IP_ADD_SOURCE_MEMBERSHIP),
#endif
#ifdef IP_DROP_SOURCE_MEMBERSHIP
    ADD(IP_DROP_SOURCE_MEMBERSHIP),
#endif
#ifdef IP_MSFILTER
    ADD(IP_MSFILTER),
#endif
#ifdef MCAST_JOIN_GROUP
    ADD(MCAST_JOIN_GROUP),
#endif
#ifdef MCAST_BLOCK_SOURCE
    ADD(MCAST_BLOCK_SOURCE),
#endif
#ifdef MCAST_UNBLOCK_SOURCE
    ADD(MCAST_UNBLOCK_SOURCE),
#endif
#ifdef MCAST_LEAVE_GROUP
    ADD(MCAST_LEAVE_GROUP),
#endif
#ifdef MCAST_JOIN_SOURCE_GROUP
    ADD(MCAST_JOIN_SOURCE_GROUP),
#endif
#ifdef MCAST_LEAVE_SOURCE_GROUP
    ADD(MCAST_LEAVE_SOURCE_GROUP),
#endif
#ifdef MCAST_MSFILTER
    ADD(MCAST_MSFILTER),
#endif
#ifdef IP_MULTICAST_ALL
    ADD(IP_MULTICAST_ALL),
#endif
#ifdef IP_UNICAST_IF
    ADD(IP_UNICAST_IF)
#endif
};

static const IntStrPair IPPROTO_IPV6_OPTIONS[] = {
#ifdef IPV6_ADDRFORM
    ADD(IPV6_ADDRFORM),
#endif
#ifdef IPV6_2292PKTINFO
    ADD(IPV6_2292PKTINFO),
#endif
#ifdef IPV6_2292HOPOPTS
    ADD(IPV6_2292HOPOPTS),
#endif
#ifdef IPV6_2292DSTOPTS
    ADD(IPV6_2292DSTOPTS),
#endif
#ifdef IPV6_2292RTHDR
    ADD(IPV6_2292RTHDR),
#endif
#ifdef IPV6_2292PKTOPTIONS
    ADD(IPV6_2292PKTOPTIONS),
#endif
#ifdef IPV6_CHECKSUM
    ADD(IPV6_CHECKSUM),
#endif
#ifdef IPV6_HOPLIMIT
    ADD(IPV6_HOPLIMIT),
#endif
#ifdef IPV6_NEXTHOP
    ADD(IPV6_NEXTHOP),
#endif
#ifdef IPV6_AUTHHDR
    ADD(IPV6_AUTHHDR),
#endif
#ifdef IPV6_FLOWINFO
    ADD(IPV6_FLOWINFO),
#endif
#ifdef IPV6_UNICAST_HOPS
    ADD(IPV6_UNICAST_HOPS),
#endif
#ifdef IPV6_MULTICAST_IF
    ADD(IPV6_MULTICAST_IF),
#endif
#ifdef IPV6_MULTICAST_HOPS
    ADD(IPV6_MULTICAST_HOPS),
#endif
#ifdef IPV6_MULTICAST_LOOP
    ADD(IPV6_MULTICAST_LOOP),
#endif
#ifdef IPV6_ADD_MEMBERSHIP
    ADD(IPV6_ADD_MEMBERSHIP),
#endif
#ifdef IPV6_DROP_MEMBERSHIP
    ADD(IPV6_DROP_MEMBERSHIP),
#endif
#ifdef IPV6_ROUTER_ALERT
    ADD(IPV6_ROUTER_ALERT),
#endif
#ifdef IPV6_MTU_DISCOVER
    ADD(IPV6_MTU_DISCOVER),
#endif
#ifdef IPV6_MTU
    ADD(IPV6_MTU),
#endif
#ifdef IPV6_RECVERR
    ADD(IPV6_RECVERR),
#endif
#ifdef IPV6_V6ONLY
    ADD(IPV6_V6ONLY),
#endif
#ifdef IPV6_JOIN_ANYCAST
    ADD(IPV6_JOIN_ANYCAST),
#endif
#ifdef IPV6_LEAVE_ANYCAST
    ADD(IPV6_LEAVE_ANYCAST),
#endif
#ifdef IPV6_FLOWLABEL_MGR
    ADD(IPV6_FLOWLABEL_MGR),
#endif
#ifdef IPV6_FLOWINFO_SEND
    ADD(IPV6_FLOWINFO_SEND),
#endif
#ifdef IPV6_IPSEC_POLICY
    ADD(IPV6_IPSEC_POLICY),
#endif
#ifdef IPV6_XFRM_POLICY
    ADD(IPV6_XFRM_POLICY),
#endif
#ifdef IPV6_RECVPKTINFO
    ADD(IPV6_RECVPKTINFO),
#endif
#ifdef IPV6_PKTINFO
    ADD(IPV6_PKTINFO),
#endif
#ifdef IPV6_RECVHOPLIMIT
    ADD(IPV6_RECVHOPLIMIT),
#endif
#ifdef IPV6_HOPLIMIT
    ADD(IPV6_HOPLIMIT),
#endif
#ifdef IPV6_RECVHOPOPTS
    ADD(IPV6_RECVHOPOPTS),
#endif
#ifdef IPV6_HOPOPTS
    ADD(IPV6_HOPOPTS),
#endif
#ifdef IPV6_RTHDRDSTOPTS
    ADD(IPV6_RTHDRDSTOPTS),
#endif
#ifdef IPV6_RECVRTHDR
    ADD(IPV6_RECVRTHDR),
#endif
#ifdef IPV6_RTHDR
    ADD(IPV6_RTHDR),
#endif
#ifdef IPV6_RECVDSTOPTS
    ADD(IPV6_RECVDSTOPTS),
#endif
#ifdef IPV6_DSTOPTS
    ADD(IPV6_DSTOPTS),
#endif
#ifdef IPV6_RECVPATHMTU
    ADD(IPV6_RECVPATHMTU),
#endif
#ifdef IPV6_PATHMTU
    ADD(IPV6_PATHMTU),
#endif
#ifdef IPV6_DONTFRAG
    ADD(IPV6_DONTFRAG),
#endif
#ifdef IPV6_RECVTCLASS
    ADD(IPV6_RECVTCLASS),
#endif
#ifdef IPV6_TCLASS
    ADD(IPV6_TCLASS),
#endif
#ifdef IPV6_ADDR_PREFERENCES
    ADD(IPV6_ADDR_PREFERENCES),
#endif
#ifdef IPV6_MINHOPCOUNT
    ADD(IPV6_MINHOPCOUNT),
#endif
#ifdef IPV6_ORIGDSTADDR
    ADD(IPV6_ORIGDSTADDR),
#endif
#ifdef IPV6_TRANSPARENT
    ADD(IPV6_TRANSPARENT),
#endif
#ifdef IPV6_UNICAST_IF
    ADD(IPV6_UNICAST_IF)
#endif
};

static const IntStrPair IPPROTO_TCP_OPTIONS[] = {
#ifdef TCP_NODELAY
    ADD(TCP_NODELAY),
#endif
#ifdef TCP_MAXSEG
    ADD(TCP_MAXSEG),
#endif
#ifdef TCP_CORK
    ADD(TCP_CORK),
#endif
#ifdef TCP_KEEPIDLE
    ADD(TCP_KEEPIDLE),
#endif
#ifdef TCP_KEEPINTVL
    ADD(TCP_KEEPINTVL),
#endif
#ifdef TCP_KEEPCNT
    ADD(TCP_KEEPCNT),
#endif
#ifdef TCP_SYNCNT
    ADD(TCP_SYNCNT),
#endif
#ifdef TCP_LINGER2
    ADD(TCP_LINGER2),
#endif
#ifdef TCP_DEFER_ACCEPT
    ADD(TCP_DEFER_ACCEPT),
#endif
#ifdef TCP_WINDOW_CLAMP
    ADD(TCP_WINDOW_CLAMP),
#endif
#ifdef TCP_INFO
    ADD(TCP_INFO),
#endif
#ifdef TCP_QUICKACK
    ADD(TCP_QUICKACK),
#endif
#ifdef TCP_CONGESTION
    ADD(TCP_CONGESTION),
#endif
#ifdef TCP_MD5SIG
    ADD(TCP_MD5SIG),
#endif
#ifdef TCP_THIN_LINEAR_TIMEOUTS
    ADD(TCP_THIN_LINEAR_TIMEOUTS),
#endif
#ifdef TCP_THIN_DUPACK
    ADD(TCP_THIN_DUPACK),
#endif
#ifdef TCP_USER_TIMEOUT
    ADD(TCP_USER_TIMEOUT),
#endif
#ifdef TCP_REPAIR
    ADD(TCP_REPAIR),
#endif
#ifdef TCP_REPAIR_QUEUE
    ADD(TCP_REPAIR_QUEUE),
#endif
#ifdef TCP_QUEUE_SEQ
    ADD(TCP_QUEUE_SEQ),
#endif
#ifdef TCP_REPAIR_OPTIONS
    ADD(TCP_REPAIR_OPTIONS),
#endif
#ifdef TCP_FASTOPEN
    ADD(TCP_FASTOPEN),
#endif
#ifdef TCP_TIMESTAMP
    ADD(TCP_TIMESTAMP),
#endif
#ifdef TCP_NOTSENT_LOWAT
    ADD(TCP_NOTSENT_LOWAT)
#endif
};

static const IntStrPair SOL_PACKET_OPTIONS[] = {
#ifdef PACKET_ADD_MEMBERSHIP
    ADD(PACKET_ADD_MEMBERSHIP),
#endif
#ifdef PACKET_DROP_MEMBERSHIP
    ADD(PACKET_DROP_MEMBERSHIP),
#endif
#ifdef PACKET_RECV_OUTPUT
    ADD(PACKET_RECV_OUTPUT),
#endif
#ifdef PACKET_RX_RING
    ADD(PACKET_RX_RING),
#endif
#ifdef PACKET_STATISTICS
    ADD(PACKET_STATISTICS),
#endif
#ifdef PACKET_COPY_THRESH
    ADD(PACKET_COPY_THRESH),
#endif
#ifdef PACKET_AUXDATA
    ADD(PACKET_AUXDATA),
#endif
#ifdef PACKET_ORIGDEV
    ADD(PACKET_ORIGDEV),
#endif
#ifdef PACKET_VERSION
    ADD(PACKET_VERSION),
#endif
#ifdef PACKET_HDRLEN
    ADD(PACKET_HDRLEN),
#endif
#ifdef PACKET_RESERVE
    ADD(PACKET_RESERVE),
#endif
#ifdef PACKET_TX_RING
    ADD(PACKET_TX_RING),
#endif
#ifdef PACKET_LOSS
    ADD(PACKET_LOSS),
#endif
#ifdef PACKET_VNET_HDR
    ADD(PACKET_VNET_HDR),
#endif
#ifdef PACKET_TX_TIMESTAMP
    ADD(PACKET_TX_TIMESTAMP),
#endif
#ifdef PACKET_TIMESTAMP
    ADD(PACKET_TIMESTAMP),
#endif
#ifdef PACKET_FANOUT
    ADD(PACKET_FANOUT),
#endif
#ifdef PACKET_TX_HAS_OFF
    ADD(PACKET_TX_HAS_OFF),
#endif
#ifdef PACKET_QDISC_BYPASS
    ADD(PACKET_QDISC_BYPASS),
#endif
#ifdef PACKET_ROLLOVER_STATS
    ADD(PACKET_ROLLOVER_STATS),
#endif
#ifdef PACKET_FANOUT_DATA
    ADD(PACKET_FANOUT_DATA)
#endif
};

static const IntStrPair IPPROTO_UDP_OPTIONS[] = {
#ifdef UDP_CORK
    ADD(UDP_CORK)
#endif
};

static const IntStrPair FCNTL_CMDS[] = {
#ifdef F_GETFD
    ADD(F_GETFD),
#endif
#ifdef F_GETFL
    ADD(F_GETFL),
#endif
#ifdef F_GETOWN
    ADD(F_GETOWN),
#endif
#ifdef F_GETSIG
    ADD(F_GETSIG),
#endif
#ifdef F_GETLEASE
    ADD(F_GETLEASE),
#endif
#ifdef F_GETPIPE_SZ
    ADD(F_GETPIPE_SZ),
#endif
#ifdef F_DUPFD
    ADD(F_DUPFD),
#endif
#ifdef F_DUPFD_CLOEXEC
    ADD(F_DUPFD_CLOEXEC),
#endif
#ifdef F_SETFD
    ADD(F_SETFD),
#endif
#ifdef F_SETFL
    ADD(F_SETFL),
#endif
#ifdef F_SETOWN
    ADD(F_SETOWN),
#endif
#ifdef F_SETSIG
    ADD(F_SETSIG),
#endif
#ifdef F_SETLEASE
    ADD(F_SETLEASE),
#endif
#ifdef F_NOTIFY
    ADD(F_NOTIFY),
#endif
#ifdef F_SETPIPE_SZ
    ADD(F_SETPIPE_SZ),
#endif
#ifdef F_SETLK
    ADD(F_SETLK),
#endif
#ifdef F_SETLKW
    ADD(F_SETLKW),
#endif
#ifdef F_GETLK
    ADD(F_GETLK),
#endif
#ifdef F_GETLK64
    ADD(F_GETLK64),
#endif
#ifdef F_SETLK64
    ADD(F_SETLK64),
#endif
#ifdef F_SETLKW64
    ADD(F_SETLKW64),
#endif
#ifdef F_OFD_SETLK
    ADD(F_OFD_SETLK),
#endif
#ifdef F_OFD_SETLKW
    ADD(F_OFD_SETLKW),
#endif
#ifdef F_OFD_GETLK
    ADD(F_OFD_GETLK),
#endif
#ifdef F_GETOWN_EX
    ADD(F_GETOWN_EX),
#endif
#ifdef F_SETOWN_EX
    ADD(F_SETOWN_EX)
#endif
};

static const IntStrPair IOCTL_REQUESTS[] = {
#ifdef FIONREAD
    ADD(FIONREAD),
#endif
// <include/asm-i386/socket.h>
#ifdef FIOSETOWN
    ADD(FIOSETOWN),
#endif
#ifdef SIOCSPGRP
    ADD(SIOCSPGRP),
#endif
#ifdef FIOGETOWN
    ADD(FIOGETOWN),
#endif
#ifdef SIOCGPGRP
    ADD(SIOCGPGRP),
#endif
#ifdef SIOCATMAR
    ADD(SIOCATMAR),
#endif
#ifdef SIOCGSTAMP
    ADD(SIOCGSTAMP),
#endif
// <include/asm-i386/termios.h>
#ifdef TCGETS
    ADD(TCGETS),
#endif
#ifdef TCSETS
    ADD(TCSETS),
#endif
#ifdef TCSETSW
    ADD(TCSETSW),
#endif
#ifdef TCSETSF
    ADD(TCSETSF),
#endif
#ifdef TCGETA
    ADD(TCGETA),
#endif
#ifdef TCSETA
    ADD(TCSETA),
#endif
#ifdef TCSETAW
    ADD(TCSETAW),
#endif
#ifdef TCSETAF
    ADD(TCSETAF),
#endif
#ifdef TCSBRK
    ADD(TCSBRK),
#endif
#ifdef TCXONC
    ADD(TCXONC),
#endif
#ifdef TCFLSH
    ADD(TCFLSH),
#endif
#ifdef TIOCEXCL
    ADD(TIOCEXCL),
#endif
#ifdef TIOCNXCL
    ADD(TIOCNXCL),
#endif
#ifdef TIOCSCTTY
    ADD(TIOCSCTTY),
#endif
#ifdef TIOCGPGRP
    ADD(TIOCGPGRP),
#endif
#ifdef TIOCSPGRP
    ADD(TIOCSPGRP),
#endif
#ifdef TIOCOUTQ
    ADD(TIOCOUTQ),
#endif
#ifdef TIOCSTI
    ADD(TIOCSTI),
#endif
#ifdef TIOCGWINSZ
    ADD(TIOCGWINSZ),
#endif
#ifdef TIOCSWINSZ
    ADD(TIOCSWINSZ),
#endif
#ifdef TIOCMGET
    ADD(TIOCMGET),
#endif
#ifdef TIOCMBIS
    ADD(TIOCMBIS),
#endif
#ifdef TIOCMBIC
    ADD(TIOCMBIC),
#endif
#ifdef TIOCMSET
    ADD(TIOCMSET),
#endif
#ifdef TIOCGSOFTCAR
    ADD(TIOCGSOFTCAR),
#endif
#ifdef TIOCSSOFTCAR
    ADD(TIOCSSOFTCAR),
#endif
#ifdef FIONREAD
    ADD(FIONREAD),
#endif
#ifdef TIOCINQ
    ADD(TIOCINQ),
#endif
#ifdef TIOCLINUX
    ADD(TIOCLINUX),
#endif
#ifdef TIOCCONS
    ADD(TIOCCONS),
#endif
#ifdef TIOCGSERIAL
    ADD(TIOCGSERIAL),
#endif
#ifdef TIOCSSERIAL
    ADD(TIOCSSERIAL),
#endif
#ifdef TIOCPKT
    ADD(TIOCPKT),
#endif
#ifdef FIONBIO
    ADD(FIONBIO),
#endif
#ifdef TIOCNOTTY
    ADD(TIOCNOTTY),
#endif
#ifdef TIOCSETD
    ADD(TIOCSETD),
#endif
#ifdef TIOCGETD
    ADD(TIOCGETD),
#endif
#ifdef TCSBRKP
    ADD(TCSBRKP),
#endif
#ifdef TIOCTTYGSTRUCT
    ADD(TIOCTTYGSTRUCT),
#endif
#ifdef FIONCLEX
    ADD(FIONCLEX),
#endif
#ifdef FIOCLEX
    ADD(FIOCLEX),
#endif
#ifdef FIOASYNC
    ADD(FIOASYNC),
#endif
#ifdef TIOCSERCONFIG
    ADD(TIOCSERCONFIG),
#endif
#ifdef TIOCSERGWILD
    ADD(TIOCSERGWILD),
#endif
#ifdef TIOCSERSWILD
    ADD(TIOCSERSWILD),
#endif
#ifdef TIOCGLCKTRMIOS
    ADD(TIOCGLCKTRMIOS),
#endif
#ifdef TIOCSLCKTRMIOS
    ADD(TIOCSLCKTRMIOS),
#endif
#ifdef TIOCSERGSTRUCT
    ADD(TIOCSERGSTRUCT),
#endif
#ifdef TIOCSERGETLSR
    ADD(TIOCSERGETLSR),
#endif
#ifdef TIOCSERGETMULTI
    ADD(TIOCSERGETMULTI),
#endif
#ifdef TIOCSERSETMULTI
    ADD(TIOCSERSETMULTI),
#endif
// <include/linux/ax25.h>
#ifdef SIOCAX25GETUID
    ADD(SIOCAX25GETUID),
#endif
#ifdef SIOCAX25ADDUID
    ADD(SIOCAX25ADDUID),
#endif
#ifdef SIOCAX25DELUID
    ADD(SIOCAX25DELUID),
#endif
#ifdef SIOCAX25NOUID
    ADD(SIOCAX25NOUID),
#endif
#ifdef SIOCAX25DIGCTL
    ADD(SIOCAX25DIGCTL),
#endif
#ifdef SIOCAX25GETPARMS
    ADD(SIOCAX25GETPARMS),
#endif
#ifdef SIOCAX25SETPARMS
    ADD(SIOCAX25SETPARMS),
#endif
// <include/linux/,if_eql.h>
#ifdef EQL_ENSLAVE
    ADD(EQL_ENSLAVE),
#endif
#ifdef EQL_EMANCIPATE
    ADD(EQL_EMANCIPATE),
#endif
#ifdef EQL_GETSLAVECFG
    ADD(EQL_GETSLAVECFG),
#endif
#ifdef EQL_SETSLAVECFG
    ADD(EQL_SETSLAVECFG),
#endif
#ifdef EQL_GETMASTRCFG
    ADD(EQL_GETMASTRCFG),
#endif
#ifdef EQL_SETMASTRCFG
    ADD(EQL_SETMASTRCFG),
#endif
// <include/linux/if_plip.h>
#ifdef SIOCDEVPLIP
    ADD(SIOCDEVPLIP),
#endif
// <include/linux/if_ppp.h>
#ifdef PPPIOCGFLAGS
    ADD(PPPIOCGFLAGS),
#endif
#ifdef PPPIOCSFLAGS
    ADD(PPPIOCSFLAGS),
#endif
#ifdef PPPIOCGASYNCMAP
    ADD(PPPIOCGASYNCMAP),
#endif
#ifdef PPPIOCSASYNCMAP
    ADD(PPPIOCSASYNCMAP),
#endif
#ifdef PPPIOCGUNIT
    ADD(PPPIOCGUNIT),
#endif
#ifdef PPPIOCSINPSIG
    ADD(PPPIOCSINPSIG),
#endif
#ifdef PPPIOCSDEBUG
    ADD(PPPIOCSDEBUG),
#endif
#ifdef PPPIOCGDEBUG
    ADD(PPPIOCGDEBUG),
#endif
#ifdef PPPIOCGSTAT
    ADD(PPPIOCGSTAT),
#endif
#ifdef PPPIOCGTIME
    ADD(PPPIOCGTIME),
#endif
#ifdef PPPIOCGXASYNCMAP
    ADD(PPPIOCGXASYNCMAP),
#endif
#ifdef PPPIOCSXASYNCMAP
    ADD(PPPIOCSXASYNCMAP),
#endif
#ifdef PPPIOCSMRU
    ADD(PPPIOCSMRU),
#endif
#ifdef PPPIOCRASYNCMAP
    ADD(PPPIOCRASYNCMAP),
#endif
#ifdef PPPIOCSMAXCID
    ADD(PPPIOCSMAXCID),
#endif
// <include/linux/ipx.h>
#ifdef SIOCAIPXITFCRT
    ADD(SIOCAIPXITFCRT),
#endif
#ifdef SIOCAIPXPRISLT
    ADD(SIOCAIPXPRISLT),
#endif
#ifdef SIOCIPXCFGDATA
    ADD(SIOCIPXCFGDATA),
#endif
// <include/linux/mroute.h>
#ifdef SIOCGETVIFCNT
    ADD(SIOCGETVIFCNT),
#endif
#ifdef SIOCGETSGCNT
    ADD(SIOCGETSGCNT),
#endif
// <include/uapi/linux/wireless.h>
#ifdef SIOCSIWCOMMIT
    ADD(SIOCSIWCOMMIT),
#endif
#ifdef SIOCGIWNAME
    ADD(SIOCGIWNAME),
#endif
#ifdef SIOCSIWNWID
    ADD(SIOCSIWNWID),
#endif
#ifdef SIOCGIWNWID
    ADD(SIOCGIWNWID),
#endif
#ifdef SIOCSIWFREQ
    ADD(SIOCSIWFREQ),
#endif
#ifdef SIOCGIWFREQ
    ADD(SIOCGIWFREQ),
#endif
#ifdef SIOCSIWMODE
    ADD(SIOCSIWMODE),
#endif
#ifdef SIOCGIWMODE
    ADD(SIOCGIWMODE),
#endif
#ifdef SIOCSIWSENS
    ADD(SIOCSIWSENS),
#endif
#ifdef SIOCGIWSENS
    ADD(SIOCGIWSENS),
#endif
#ifdef SIOCSIWRANGE
    ADD(SIOCSIWRANGE),
#endif
#ifdef SIOCGIWRANGE
    ADD(SIOCGIWRANGE),
#endif
#ifdef SIOCSIWPRIV
    ADD(SIOCSIWPRIV),
#endif
#ifdef SIOCGIWPRIV
    ADD(SIOCGIWPRIV),
#endif
#ifdef SIOCSIWSTATS
    ADD(SIOCSIWSTATS),
#endif
#ifdef SIOCGIWSTATS
    ADD(SIOCGIWSTATS),
#endif
#ifdef SIOCSIWSPY
    ADD(SIOCSIWSPY),
#endif
#ifdef SIOCGIWSPY
    ADD(SIOCGIWSPY),
#endif
#ifdef SIOCSIWTHRSPY
    ADD(SIOCSIWTHRSPY),
#endif
#ifdef SIOCGIWTHRSPY
    ADD(SIOCGIWTHRSPY),
#endif
#ifdef SIOCSIWAP
    ADD(SIOCSIWAP),
#endif
#ifdef SIOCGIWAP
    ADD(SIOCGIWAP),
#endif
#ifdef SIOCGIWAPLIST
    ADD(SIOCGIWAPLIST),
#endif
#ifdef SIOCSIWSCAN
    ADD(SIOCSIWSCAN),
#endif
#ifdef SIOCGIWSCAN
    ADD(SIOCGIWSCAN),
#endif
#ifdef SIOCSIWESSID
    ADD(SIOCSIWESSID),
#endif
#ifdef SIOCGIWESSID
    ADD(SIOCGIWESSID),
#endif
#ifdef SIOCSIWNICKN
    ADD(SIOCSIWNICKN),
#endif
#ifdef SIOCGIWNICKN
    ADD(SIOCGIWNICKN),
#endif
#ifdef SIOCSIWRATE
    ADD(SIOCSIWRATE),
#endif
#ifdef SIOCGIWRATE
    ADD(SIOCGIWRATE),
#endif
#ifdef SIOCSIWRTS
    ADD(SIOCSIWRTS),
#endif
#ifdef SIOCGIWRTS
    ADD(SIOCGIWRTS),
#endif
#ifdef SIOCSIWFRAG
    ADD(SIOCSIWFRAG),
#endif
#ifdef SIOCGIWFRAG
    ADD(SIOCGIWFRAG),
#endif
#ifdef SIOCSIWTXPOW
    ADD(SIOCSIWTXPOW),
#endif
#ifdef SIOCGIWTXPOW
    ADD(SIOCGIWTXPOW),
#endif
#ifdef SIOCSIWRETRY
    ADD(SIOCSIWRETRY),
#endif
#ifdef SIOCGIWRETRY
    ADD(SIOCGIWRETRY),
#endif
#ifdef SIOCSIWENCODE
    ADD(SIOCSIWENCODE),
#endif
#ifdef SIOCGIWENCODE
    ADD(SIOCGIWENCODE),
#endif
#ifdef SIOCSIWPOWER
    ADD(SIOCSIWPOWER),
#endif
#ifdef SIOCGIWPOWER
    ADD(SIOCGIWPOWER),
#endif
#ifdef SIOCSIWGENIE
    ADD(SIOCSIWGENIE),
#endif
#ifdef SIOCGIWGENIE
    ADD(SIOCGIWGENIE),
#endif
#ifdef SIOCSIWMLME
    ADD(SIOCSIWMLME),
#endif
#ifdef SIOCSIWAUTH
    ADD(SIOCSIWAUTH),
#endif
#ifdef SIOCGIWAUTH
    ADD(SIOCGIWAUTH),
#endif
#ifdef SIOCSIWENCODEEXT
    ADD(SIOCSIWENCODEEXT),
#endif
#ifdef SIOCGIWENCODEEXT
    ADD(SIOCGIWENCODEEXT),
#endif
#ifdef SIOCSIWPMKSA
    ADD(SIOCSIWPMKSA),
#endif
// <include/uapi/linux/sockios.h> see netdevice(7)
#ifdef SIOCADDRT
    ADD(SIOCADDRT),
#endif
#ifdef SIOCDELRT
    ADD(SIOCDELRT),
#endif
#ifdef SIOCGIFNAME
    ADD(SIOCGIFNAME),
#endif
#ifdef SIOCSIFLINK
    ADD(SIOCSIFLINK),
#endif
#ifdef SIOCGIFCONF
    ADD(SIOCGIFCONF),
#endif
#ifdef SIOCGIFFLAGS
    ADD(SIOCGIFFLAGS),
#endif
#ifdef SIOCSIFFLAGS
    ADD(SIOCSIFFLAGS),
#endif
#ifdef SIOCGIFADDR
    ADD(SIOCGIFADDR),
#endif
#ifdef SIOCSIFADDR
    ADD(SIOCSIFADDR),
#endif
#ifdef SIOCGIFDSTADDR
    ADD(SIOCGIFDSTADDR),
#endif
#ifdef SIOCSIFDSTADDR
    ADD(SIOCSIFDSTADDR),
#endif
#ifdef SIOCGIFBRDADDR
    ADD(SIOCGIFBRDADDR),
#endif
#ifdef SIOCSIFBRDADDR
    ADD(SIOCSIFBRDADDR),
#endif
#ifdef SIOCGIFNETMASK
    ADD(SIOCGIFNETMASK),
#endif
#ifdef SIOCSIFNETMASK
    ADD(SIOCSIFNETMASK),
#endif
#ifdef SIOCGIFMETRIC
    ADD(SIOCGIFMETRIC),
#endif
#ifdef SIOCSIFMETRIC
    ADD(SIOCSIFMETRIC),
#endif
#ifdef SIOCGIFMEM
    ADD(SIOCGIFMEM),
#endif
#ifdef SIOCSIFMEM
    ADD(SIOCSIFMEM),
#endif
#ifdef SIOCGIFMTU
    ADD(SIOCGIFMTU),
#endif
#ifdef SIOCSIFMTU
    ADD(SIOCSIFMTU),
#endif
#ifdef OLD_SIOCGIFHWADDR
    ADD(OLD_SIOCGIFHWADDR),
#endif
#ifdef SIOCSIFHWADDR
    ADD(SIOCSIFHWADDR),
#endif
#ifdef SIOCGIFENCAP
    ADD(SIOCGIFENCAP),
#endif
#ifdef SIOCSIFENCAP
    ADD(SIOCSIFENCAP),
#endif
#ifdef SIOCGIFHWADDR
    ADD(SIOCGIFHWADDR),
#endif
#ifdef SIOCGIFSLAVE
    ADD(SIOCGIFSLAVE),
#endif
#ifdef SIOCSIFSLAVE
    ADD(SIOCSIFSLAVE),
#endif
#ifdef SIOCADDMULTI
    ADD(SIOCADDMULTI),
#endif
#ifdef SIOCDELMULTI
    ADD(SIOCDELMULTI),
#endif
#ifdef SIOCADDRTOLD
    ADD(SIOCADDRTOLD),
#endif
#ifdef SIOCDELRTOLD
    ADD(SIOCDELRTOLD),
#endif
#ifdef SIOCDARP
    ADD(SIOCDARP),
#endif
#ifdef SIOCGARP
    ADD(SIOCGARP),
#endif
#ifdef SIOCSARP
    ADD(SIOCSARP),
#endif
#ifdef SIOCDRARP
    ADD(SIOCDRARP),
#endif
#ifdef SIOCGRARP
    ADD(SIOCGRARP),
#endif
#ifdef SIOCSRARP
    ADD(SIOCSRARP),
#endif
#ifdef SIOCGIFMAP
    ADD(SIOCGIFMAP),
#endif
#ifdef SIOCSIFMAP
    ADD(SIOCSIFMAP)
#endif
};

static const IntStrPair ERRNOS[] = {
#ifdef EPERM
    ADD(EPERM),
#endif
#ifdef ENOENT
    ADD(ENOENT),
#endif
#ifdef ESRCH
    ADD(ESRCH),
#endif
#ifdef EINTR
    ADD(EINTR),
#endif
#ifdef EIO
    ADD(EIO),
#endif
#ifdef ENXIO
    ADD(ENXIO),
#endif
#ifdef E2BIG
    ADD(E2BIG),
#endif
#ifdef ENOEXEC
    ADD(ENOEXEC),
#endif
#ifdef EBADF
    ADD(EBADF),
#endif
#ifdef ECHILD
    ADD(ECHILD),
#endif
#ifdef EAGAIN
    ADD(EAGAIN),
#endif
#ifdef ENOMEM
    ADD(ENOMEM),
#endif
#ifdef EACCES
    ADD(EACCES),
#endif
#ifdef EFAULT
    ADD(EFAULT),
#endif
#ifdef ENOTBLK
    ADD(ENOTBLK),
#endif
#ifdef EBUSY
    ADD(EBUSY),
#endif
#ifdef EEXIST
    ADD(EEXIST),
#endif
#ifdef EXDEV
    ADD(EXDEV),
#endif
#ifdef ENODEV
    ADD(ENODEV),
#endif
#ifdef ENOTDIR
    ADD(ENOTDIR),
#endif
#ifdef EISDIR
    ADD(EISDIR),
#endif
#ifdef EINVAL
    ADD(EINVAL),
#endif
#ifdef ENFILE
    ADD(ENFILE),
#endif
#ifdef EMFILE
    ADD(EMFILE),
#endif
#ifdef ENOTTY
    ADD(ENOTTY),
#endif
#ifdef ETXTBSY
    ADD(ETXTBSY),
#endif
#ifdef EFBIG
    ADD(EFBIG),
#endif
#ifdef ENOSPC
    ADD(ENOSPC),
#endif
#ifdef ESPIPE
    ADD(ESPIPE),
#endif
#ifdef EROFS
    ADD(EROFS),
#endif
#ifdef EMLINK
    ADD(EMLINK),
#endif
#ifdef EPIPE
    ADD(EPIPE),
#endif
#ifdef EDOM
    ADD(EDOM),
#endif
#ifdef ERANGE
    ADD(ERANGE),
#endif
#ifdef EDEADLK
    ADD(EDEADLK),
#endif
#ifdef ENAMETOOLONG
    ADD(ENAMETOOLONG),
#endif
#ifdef ENOLCK
    ADD(ENOLCK),
#endif
#ifdef ENOSYS
    ADD(ENOSYS),
#endif
#ifdef ENOTEMPTY
    ADD(ENOTEMPTY),
#endif
#ifdef ELOOP
    ADD(ELOOP),
#endif
#ifdef EWOULDBLOCK
    ADD(EWOULDBLOCK),
#endif
#ifdef ENOMSG
    ADD(ENOMSG),
#endif
#ifdef EIDRM
    ADD(EIDRM),
#endif
#ifdef ECHRNG
    ADD(ECHRNG),
#endif
#ifdef EL2NSYNC
    ADD(EL2NSYNC),
#endif
#ifdef EL3HLT
    ADD(EL3HLT),
#endif
#ifdef EL3RST
    ADD(EL3RST),
#endif
#ifdef ELNRNG
    ADD(ELNRNG),
#endif
#ifdef EUNATCH
    ADD(EUNATCH),
#endif
#ifdef ENOCSI
    ADD(ENOCSI),
#endif
#ifdef EL2HLT
    ADD(EL2HLT),
#endif
#ifdef EBADE
    ADD(EBADE),
#endif
#ifdef EBADR
    ADD(EBADR),
#endif
#ifdef EXFULL
    ADD(EXFULL),
#endif
#ifdef ENOANO
    ADD(ENOANO),
#endif
#ifdef EBADRQC
    ADD(EBADRQC),
#endif
#ifdef EBADSLT
    ADD(EBADSLT),
#endif
#ifdef EDEADLOCK
    ADD(EDEADLOCK),
#endif
#ifdef EBFONT
    ADD(EBFONT),
#endif
#ifdef ENOSTR
    ADD(ENOSTR),
#endif
#ifdef ENODATA
    ADD(ENODATA),
#endif
#ifdef ETIME
    ADD(ETIME),
#endif
#ifdef ENOSR
    ADD(ENOSR),
#endif
#ifdef ENONET
    ADD(ENONET),
#endif
#ifdef ENOPKG
    ADD(ENOPKG),
#endif
#ifdef EREMOTE
    ADD(EREMOTE),
#endif
#ifdef ENOLINK
    ADD(ENOLINK),
#endif
#ifdef EADV
    ADD(EADV),
#endif
#ifdef ESRMNT
    ADD(ESRMNT),
#endif
#ifdef ECOMM
    ADD(ECOMM),
#endif
#ifdef EPROTO
    ADD(EPROTO),
#endif
#ifdef EMULTIHOP
    ADD(EMULTIHOP),
#endif
#ifdef EDOTDOT
    ADD(EDOTDOT),
#endif
#ifdef EBADMSG
    ADD(EBADMSG),
#endif
#ifdef EOVERFLOW
    ADD(EOVERFLOW),
#endif
#ifdef ENOTUNIQ
    ADD(ENOTUNIQ),
#endif
#ifdef EBADFD
    ADD(EBADFD),
#endif
#ifdef EREMCHG
    ADD(EREMCHG),
#endif
#ifdef ELIBACC
    ADD(ELIBACC),
#endif
#ifdef ELIBBAD
    ADD(ELIBBAD),
#endif
#ifdef ELIBSCN
    ADD(ELIBSCN),
#endif
#ifdef ELIBMAX
    ADD(ELIBMAX),
#endif
#ifdef ELIBEXEC
    ADD(ELIBEXEC),
#endif
#ifdef EILSEQ
    ADD(EILSEQ),
#endif
#ifdef ERESTART
    ADD(ERESTART),
#endif
#ifdef ESTRPIPE
    ADD(ESTRPIPE),
#endif
#ifdef EUSERS
    ADD(EUSERS),
#endif
#ifdef ENOTSOCK
    ADD(ENOTSOCK),
#endif
#ifdef EDESTADDRREQ
    ADD(EDESTADDRREQ),
#endif
#ifdef EMSGSIZE
    ADD(EMSGSIZE),
#endif
#ifdef EPROTOTYPE
    ADD(EPROTOTYPE),
#endif
#ifdef ENOPROTOOPT
    ADD(ENOPROTOOPT),
#endif
#ifdef EPROTONOSUPPORT
    ADD(EPROTONOSUPPORT),
#endif
#ifdef ESOCKTNOSUPPORT
    ADD(ESOCKTNOSUPPORT),
#endif
#ifdef EOPNOTSUPP
    ADD(EOPNOTSUPP),
#endif
#ifdef EPFNOSUPPORT
    ADD(EPFNOSUPPORT),
#endif
#ifdef EAFNOSUPPORT
    ADD(EAFNOSUPPORT),
#endif
#ifdef EADDRINUSE
    ADD(EADDRINUSE),
#endif
#ifdef EADDRNOTAVAIL
    ADD(EADDRNOTAVAIL),
#endif
#ifdef ENETDOWN
    ADD(ENETDOWN),
#endif
#ifdef ENETUNREACH
    ADD(ENETUNREACH),
#endif
#ifdef ENETRESET
    ADD(ENETRESET),
#endif
#ifdef ECONNABORTED
    ADD(ECONNABORTED),
#endif
#ifdef ECONNRESET
    ADD(ECONNRESET),
#endif
#ifdef ENOBUFS
    ADD(ENOBUFS),
#endif
#ifdef EISCONN
    ADD(EISCONN),
#endif
#ifdef ENOTCONN
    ADD(ENOTCONN),
#endif
#ifdef ESHUTDOWN
    ADD(ESHUTDOWN),
#endif
#ifdef ETOOMANYREFS
    ADD(ETOOMANYREFS),
#endif
#ifdef ETIMEDOUT
    ADD(ETIMEDOUT),
#endif
#ifdef ECONNREFUSED
    ADD(ECONNREFUSED),
#endif
#ifdef EHOSTDOWN
    ADD(EHOSTDOWN),
#endif
#ifdef EHOSTUNREACH
    ADD(EHOSTUNREACH),
#endif
#ifdef EALREADY
    ADD(EALREADY),
#endif
#ifdef EINPROGRESS
    ADD(EINPROGRESS),
#endif
#ifdef ESTALE
    ADD(ESTALE),
#endif
#ifdef EUCLEAN
    ADD(EUCLEAN),
#endif
#ifdef ENOTNAM
    ADD(ENOTNAM),
#endif
#ifdef ENAVAIL
    ADD(ENAVAIL),
#endif
#ifdef EISNAM
    ADD(EISNAM),
#endif
#ifdef EREMOTEIO
    ADD(EREMOTEIO),
#endif
#ifdef EDQUOT
    ADD(EDQUOT),
#endif
#ifdef ENOMEDIUM
    ADD(ENOMEDIUM),
#endif
#ifdef EMEDIUMTYPE
    ADD(EMEDIUMTYPE),
#endif
#ifdef ECANCELED
    ADD(ECANCELED),
#endif
#ifdef ENOKEY
    ADD(ENOKEY),
#endif
#ifdef EKEYEXPIRED
    ADD(EKEYEXPIRED),
#endif
#ifdef EKEYREVOKED
    ADD(EKEYREVOKED),
#endif
#ifdef EKEYREJECTED
    ADD(EKEYREJECTED),
#endif
#ifdef EOWNERDEAD
    ADD(EOWNERDEAD),
#endif
#ifdef ENOTRECOVERABLE
    ADD(ENOTRECOVERABLE),
#endif
#ifdef PERM
    ADD(PERM),
#endif
#ifdef ENOENT
    ADD(ENOENT),
#endif
#ifdef ESRCH
    ADD(ESRCH),
#endif
#ifdef EINTR
    ADD(EINTR),
#endif
#ifdef EIO
    ADD(EIO),
#endif
#ifdef ENXIO
    ADD(ENXIO),
#endif
#ifdef E2BIG
    ADD(E2BIG),
#endif
#ifdef ENOEXEC
    ADD(ENOEXEC),
#endif
#ifdef EBADF
    ADD(EBADF),
#endif
#ifdef ECHILD
    ADD(ECHILD),
#endif
#ifdef EAGAIN
    ADD(EAGAIN),
#endif
#ifdef ENOMEM
    ADD(ENOMEM),
#endif
#ifdef EACCES
    ADD(EACCES),
#endif
#ifdef EFAULT
    ADD(EFAULT),
#endif
#ifdef ENOTBLK
    ADD(ENOTBLK),
#endif
#ifdef EBUSY
    ADD(EBUSY),
#endif
#ifdef EEXIST
    ADD(EEXIST),
#endif
#ifdef EXDEV
    ADD(EXDEV),
#endif
#ifdef ENODEV
    ADD(ENODEV),
#endif
#ifdef ENOTDIR
    ADD(ENOTDIR),
#endif
#ifdef EISDIR
    ADD(EISDIR),
#endif
#ifdef EINVAL
    ADD(EINVAL),
#endif
#ifdef ENFILE
    ADD(ENFILE),
#endif
#ifdef EMFILE
    ADD(EMFILE),
#endif
#ifdef ENOTTY
    ADD(ENOTTY),
#endif
#ifdef ETXTBSY
    ADD(ETXTBSY),
#endif
#ifdef EFBIG
    ADD(EFBIG),
#endif
#ifdef ENOSPC
    ADD(ENOSPC),
#endif
#ifdef ESPIPE
    ADD(ESPIPE),
#endif
#ifdef EROFS
    ADD(EROFS),
#endif
#ifdef EMLINK
    ADD(EMLINK),
#endif
#ifdef EPIPE
    ADD(EPIPE),
#endif
#ifdef EDOM
    ADD(EDOM),
#endif
#ifdef ERANGE
    ADD(ERANGE),
#endif
#ifdef EDEADLK
    ADD(EDEADLK),
#endif
#ifdef ENAMETOOLONG
    ADD(ENAMETOOLONG),
#endif
#ifdef ENOLCK
    ADD(ENOLCK),
#endif
#ifdef ENOSYS
    ADD(ENOSYS),
#endif
#ifdef ENOTEMPTY
    ADD(ENOTEMPTY),
#endif
#ifdef ELOOP
    ADD(ELOOP),
#endif
#ifdef EWOULDBLOCK
    ADD(EWOULDBLOCK),
#endif
#ifdef ENOMSG
    ADD(ENOMSG),
#endif
#ifdef EIDRM
    ADD(EIDRM),
#endif
#ifdef ECHRNG
    ADD(ECHRNG),
#endif
#ifdef EL2NSYNC
    ADD(EL2NSYNC),
#endif
#ifdef EL3HLT
    ADD(EL3HLT),
#endif
#ifdef EL3RST
    ADD(EL3RST),
#endif
#ifdef ELNRNG
    ADD(ELNRNG),
#endif
#ifdef EUNATCH
    ADD(EUNATCH),
#endif
#ifdef ENOCSI
    ADD(ENOCSI),
#endif
#ifdef EL2HLT
    ADD(EL2HLT),
#endif
#ifdef EBADE
    ADD(EBADE),
#endif
#ifdef EBADR
    ADD(EBADR),
#endif
#ifdef EXFULL
    ADD(EXFULL),
#endif
#ifdef ENOANO
    ADD(ENOANO),
#endif
#ifdef EBADRQC
    ADD(EBADRQC),
#endif
#ifdef EBADSLT
    ADD(EBADSLT),
#endif
#ifdef EDEADLOCK
    ADD(EDEADLOCK),
#endif
#ifdef EBFONT
    ADD(EBFONT),
#endif
#ifdef ENOSTR
    ADD(ENOSTR),
#endif
#ifdef ENODATA
    ADD(ENODATA),
#endif
#ifdef ETIME
    ADD(ETIME),
#endif
#ifdef ENOSR
    ADD(ENOSR),
#endif
#ifdef ENONET
    ADD(ENONET),
#endif
#ifdef ENOPKG
    ADD(ENOPKG),
#endif
#ifdef EREMOTE
    ADD(EREMOTE),
#endif
#ifdef ENOLINK
    ADD(ENOLINK),
#endif
#ifdef EADV
    ADD(EADV),
#endif
#ifdef ESRMNT
    ADD(ESRMNT),
#endif
#ifdef ECOMM
    ADD(ECOMM),
#endif
#ifdef EPROTO
    ADD(EPROTO),
#endif
#ifdef EMULTIHOP
    ADD(EMULTIHOP),
#endif
#ifdef EDOTDOT
    ADD(EDOTDOT),
#endif
#ifdef EBADMSG
    ADD(EBADMSG),
#endif
#ifdef EOVERFLOW
    ADD(EOVERFLOW),
#endif
#ifdef ENOTUNIQ
    ADD(ENOTUNIQ),
#endif
#ifdef EBADFD
    ADD(EBADFD),
#endif
#ifdef EREMCHG
    ADD(EREMCHG),
#endif
#ifdef ELIBACC
    ADD(ELIBACC),
#endif
#ifdef ELIBBAD
    ADD(ELIBBAD),
#endif
#ifdef ELIBSCN
    ADD(ELIBSCN),
#endif
#ifdef ELIBMAX
    ADD(ELIBMAX),
#endif
#ifdef ELIBEXEC
    ADD(ELIBEXEC),
#endif
#ifdef EILSEQ
    ADD(EILSEQ),
#endif
#ifdef ERESTART
    ADD(ERESTART),
#endif
#ifdef ESTRPIPE
    ADD(ESTRPIPE),
#endif
#ifdef EUSERS
    ADD(EUSERS),
#endif
#ifdef ENOTSOCK
    ADD(ENOTSOCK),
#endif
#ifdef EDESTADDRREQ
    ADD(EDESTADDRREQ),
#endif
#ifdef EMSGSIZE
    ADD(EMSGSIZE),
#endif
#ifdef EPROTOTYPE
    ADD(EPROTOTYPE),
#endif
#ifdef ENOPROTOOPT
    ADD(ENOPROTOOPT),
#endif
#ifdef EPROTONOSUPPORT
    ADD(EPROTONOSUPPORT),
#endif
#ifdef ESOCKTNOSUPPORT
    ADD(ESOCKTNOSUPPORT),
#endif
#ifdef EOPNOTSUPP
    ADD(EOPNOTSUPP),
#endif
#ifdef EPFNOSUPPORT
    ADD(EPFNOSUPPORT),
#endif
#ifdef EAFNOSUPPORT
    ADD(EAFNOSUPPORT),
#endif
#ifdef EADDRINUSE
    ADD(EADDRINUSE),
#endif
#ifdef EADDRNOTAVAIL
    ADD(EADDRNOTAVAIL),
#endif
#ifdef ENETDOWN
    ADD(ENETDOWN),
#endif
#ifdef ENETUNREACH
    ADD(ENETUNREACH),
#endif
#ifdef ENETRESET
    ADD(ENETRESET),
#endif
#ifdef ECONNABORTED
    ADD(ECONNABORTED),
#endif
#ifdef ECONNRESET
    ADD(ECONNRESET),
#endif
#ifdef ENOBUFS
    ADD(ENOBUFS),
#endif
#ifdef EISCONN
    ADD(EISCONN),
#endif
#ifdef ENOTCONN
    ADD(ENOTCONN),
#endif
#ifdef ESHUTDOWN
    ADD(ESHUTDOWN),
#endif
#ifdef ETOOMANYREFS
    ADD(ETOOMANYREFS),
#endif
#ifdef ETIMEDOUT
    ADD(ETIMEDOUT),
#endif
#ifdef ECONNREFUSED
    ADD(ECONNREFUSED),
#endif
#ifdef EHOSTDOWN
    ADD(EHOSTDOWN),
#endif
#ifdef EHOSTUNREACH
    ADD(EHOSTUNREACH),
#endif
#ifdef EALREADY
    ADD(EALREADY),
#endif
#ifdef EINPROGRESS
    ADD(EINPROGRESS),
#endif
#ifdef ESTALE
    ADD(ESTALE),
#endif
#ifdef EUCLEAN
    ADD(EUCLEAN),
#endif
#ifdef ENOTNAM
    ADD(ENOTNAM),
#endif
#ifdef ENAVAIL
    ADD(ENAVAIL),
#endif
#ifdef EISNAM
    ADD(EISNAM),
#endif
#ifdef EREMOTEIO
    ADD(EREMOTEIO),
#endif
#ifdef EDQUOT
    ADD(EDQUOT),
#endif
#ifdef ENOMEDIUM
    ADD(ENOMEDIUM),
#endif
#ifdef EMEDIUMTYPE
    ADD(EMEDIUMTYPE),
#endif
#ifdef ECANCELED
    ADD(ECANCELED),
#endif
#ifdef ENOKEY
    ADD(ENOKEY),
#endif
#ifdef EKEYEXPIRED
    ADD(EKEYEXPIRED),
#endif
#ifdef EKEYREVOKED
    ADD(EKEYREVOKED),
#endif
#ifdef EKEYREJECTED
    ADD(EKEYREJECTED),
#endif
#ifdef EOWNERDEAD
    ADD(EOWNERDEAD),
#endif
#ifdef ENOTRECOVERABLE
    ADD(ENOTRECOVERABLE)
#endif
};

#endif
