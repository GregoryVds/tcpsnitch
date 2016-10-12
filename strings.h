#ifndef STRINGS_H
#define STRINGS_H

#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/tcp.h>

typedef struct {
	int cons;
	const char str[30]; 
} IntStrPair;

/* Helper for building log messages */
int string_from_cons(int cons, char *buffer, int buffer_size, 
		const IntStrPair *map, int map_size);

/* Socket domains */
static const IntStrPair SOCKET_DOMAINS[] = {
	{ AF_INET, 	"AF_INET" },
	{ AF_INET6, 	"AF_INET6" },
	{ AF_UNIX, 	"AF_UNIX" }
};

/* Socket types */
static const IntStrPair SOCKET_TYPES[] = {
	{ SOCK_STREAM, 		"SOCK_STREAM" },
	{ SOCK_DGRAM, 		"SOCK_DGRAM"  },
	{ SOCK_RAW, 		"SOCK_RAW" },
	{ SOCK_RDM,		"SOCK_RDM" },
	{ SOCK_SEQPACKET, 	"SOCK_SEQPACKET" },
	{ SOCK_DCCP,		"SOCK_DCCP" },
	{ SOCK_PACKET,		"SOCK_PACKET" }
};

/* Socket options */
static const IntStrPair SOCKET_OPTIONS[] = {
	// Socket-level options
	{ SO_DEBUG,  	"SO_DEBUG" },
	{ SO_BROADCAST, "SO_BROADCAST" },
	{ SO_REUSEADDR,	"SO_REUSEADDR" },
	{ SO_KEEPALIVE, "SO_KEEPALIVE" },
	{ SO_LINGER,	"SO_KEEPALIVE" },
	{ SO_OOBINLINE, "SO_OOBINLINE" },
	{ SO_SNDBUF,	"SO_SNDBUF" },
	{ SO_RCVBUF,	"SO_RCVBUF" },
	{ SO_DONTROUTE,	"SO_DONTROUTE" },
	{ SO_RCVLOWAT,	"SO_RCVLOWAT" },
	{ SO_RCVTIMEO, 	"SO_RCVTIMEO" },
	{ SO_SNDLOWAT,	"SO_SNDLOWAT" },
	{ SO_SNDTIMEO,	"SO_SNDTIMEO" },
	// IP-level options		
	{ IP_TOS,		"IP_TOS" },		
	{ IP_TTL,		"IP_TTL" },
	{ IP_HDRINCL,		"IP_HDRINCL" },
	{ IP_OPTIONS,		"IP_OPTIONS" },
	{ IP_ROUTER_ALERT,	"IP_ROUTER_ALERT" },
	{ IP_RECVOPTS,		"IP_RECVOPTS" },
	{ IP_RETOPTS,		"IP_RETOPTS" },
	{ IP_PKTINFO,		"IP_PKTINFO" },
	{ IP_PKTOPTIONS,	"IP_PKTOPTIONS" },
	{ IP_MTU_DISCOVER,	"IP_MTU_DISCOVER" },
	{ IP_RECVERR,		"IP_RECVERR" },
	{ IP_RECVTTL,		"IP_RECVTTL" },
	{ IP_RECVTOS,		"IP_RECVTOS" },
	{ IP_MTU,		"IP_MTU" },
	{ IP_FREEBIND,		"IP_FREEBIND" },
	{ IP_IPSEC_POLICY,	"IP_IPSEC_POLICY" },
	{ IP_XFRM_POLICY,	"IP_XFRM_POLICY" },
	{ IP_PASSSEC,		"IP_PASSSEC" },
	{ IP_TRANSPARENT,	"IP_TRANSPARENT" },
	// TCP-level options
	{ TCP_NODELAY,  	"TCP_NODELAY" },
	{ TCP_MAXSEG,		"TCP_MAXSEG" }, 
	{ TCP_CORK, 		"TCP_CORK" },
	{ TCP_KEEPIDLE, 	"TCP_KEEPIDLE" },
	{ TCP_KEEPINTVL, 	"TCP_KEEPINTVL" },
	{ TCP_KEEPCNT,		"TCP_KEEPCNT" },
	{ TCP_SYNCNT, 		"TCP_SYNCNT" },
	{ TCP_LINGER2, 		"TCP_LINGER2" },
	{ TCP_DEFER_ACCEPT, 	"TCP_DEFER_ACCEPT" },
	{ TCP_WINDOW_CLAMP, 	"TCP_WINDOW_CLAMP" },
	{ TCP_INFO,		"TCP_INFO" },
	{ TCP_QUICKACK,		"TCP_QUICKACK" },
	{ TCP_CONGESTION,	"TCP_CONGESTION" },
	{ TCP_MD5SIG,		"TCP_MD5SIG" },
	{ TCP_THIN_LINEAR_TIMEOUTS, "TCP_THIN_LINEAR_TIMEOUTS" },
	{ TCP_THIN_DUPACK,     	"TCP_THIN_DUPACK" },
	{ TCP_USER_TIMEOUT,	"TCP_USER_TIMEOUT" },
	{ TCP_REPAIR,		"TCP_REPAIR" },
	{ TCP_REPAIR_QUEUE, 	"TCP_REPAIR_QUEUE" },
	{ TCP_QUEUE_SEQ, 	"TCP_QUEUE_SEQ" },
	{ TCP_REPAIR_OPTIONS,	"TCP_REPAIR_OPTIONS" },
	{ TCP_FASTOPEN, 	"TCP_FASTOPEN" },
	{ TCP_TIMESTAMP,	"TCP_TIMESTAMP" },
	{ TCP_NOTSENT_LOWAT,	"TCP_NOTSENT_LOWAT" }
};



#endif
