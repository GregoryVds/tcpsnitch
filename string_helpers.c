#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "string_helpers.h"
#include "lib.h"
#include "config.h"

///////////////////////////////////////////////////////////////////////////////

/* Extract IP address to human readable string */
#define ADDR_WIDTH 40  // Include null byte
char *alloc_host_str(const struct sockaddr_storage *addr) {
	char *addr_str = (char *)calloc(sizeof(char), ADDR_WIDTH);
	const char *r;

	if (addr->ss_family == AF_INET) {
		const struct sockaddr_in *ipv4;
		ipv4 = (const struct sockaddr_in *)addr;
		r = inet_ntop(AF_INET, &(ipv4->sin_addr), addr_str, ADDR_WIDTH);
	} else if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *ipv6;
		ipv6 = (const struct sockaddr_in6 *)addr;
		r = inet_ntop(AF_INET6, &(ipv6->sin6_addr), addr_str,
			      ADDR_WIDTH);
	} else {
		DEBUG(ERROR,
		      "alloc_host_str() failed due to "
		      "unsupported ss_family.");
		return NULL;
	}

	if (r == NULL) {
		DEBUG(ERROR, "inet_ntop() failed. %s", strerror(errno));
		return NULL;
	}

	return addr_str;
}

#define PORT_WIDTH 6  // Include null byte
char *alloc_port_str(const struct sockaddr_storage *addr) {
	char *port_str = (char *)calloc(sizeof(char), PORT_WIDTH);
	int n;

	if (addr->ss_family == AF_INET) {
		const struct sockaddr_in *ipv4;
		ipv4 = (const struct sockaddr_in *)addr;
		n = snprintf(port_str, PORT_WIDTH, "%d", ntohs(ipv4->sin_port));
	} else if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *ipv6;
		ipv6 = (const struct sockaddr_in6 *)addr;
		n = snprintf(port_str, PORT_WIDTH, "%d",
			     ntohs(ipv6->sin6_port));
	} else {
		DEBUG(ERROR,
		      "alloc_port_str() failed due to "
		      "unsupported ss_family.");
		return NULL;
	}

	if (n < 0) {
		DEBUG(ERROR, "snprintf() failed. %s", strerror(errno));
		return NULL;
	}
	if (n >= PORT_WIDTH) {
		DEBUG(ERROR, "snprintf() failed (truncated).");
		return NULL;
	}

	return port_str;
}

#define FULL_ADDR_WIDTH 46  // ADDR:PORT\0
char *alloc_addr_str(const struct sockaddr *addr) {
	const struct sockaddr_storage *addr_sto;
	addr_sto = (const struct sockaddr_storage *)addr;

	char *full_str = (char *)calloc(sizeof(char), FULL_ADDR_WIDTH);
	char *addr_str = alloc_host_str(addr_sto);
	char *port_str = alloc_port_str(addr_sto);
	strncat(full_str, addr_str, FULL_ADDR_WIDTH - 1);
	strncat(full_str, ":", (FULL_ADDR_WIDTH - 1) - strlen(full_str));
	strncat(full_str, port_str, (FULL_ADDR_WIDTH - 1) - strlen(full_str));
	free(addr_str);
	free(port_str);
	return full_str;
}

///////////////////////////////////////////////////////////////////////////////

// This function is called in DEBUG() thus it cannot itself call DEBUG() 
// otherwise it starts an infinite loop.
char *alloc_abs_path_str(const char *file_name) {
	const char *base_path = getenv(ENV_NETSPY_PATH);
	if (base_path == NULL) base_path = NETSPY_DEFAULT_PATH; 
	int full_path_length = strlen(base_path) + strlen(file_name) + 2;
	char *full_path = (char *)malloc(sizeof(char) * full_path_length);
	if (full_path == NULL) {
		DEBUG(ERROR, "malloc() failed. Could not allocate path str.");
		return NULL;
	}
	// We cannot use DEBUG on snprintf error.
	snprintf(full_path, full_path_length, "%s/%s", base_path, file_name);
	return full_path;
}

char *alloc_pcap_path_str() { return alloc_abs_path_str(NETSPY_PCAP_FILE); }
char *alloc_log_path_str() { return alloc_abs_path_str(NETSPY_LOG_FILE); }
char *alloc_json_path_str() { return alloc_abs_path_str(NETSPY_JSON_FILE); }

#define TIMESTAMP_WIDTH 10
char *alloc_dirname_str(char *app_name) {
	int app_name_length = strlen(app_name);
	int n = app_name_length + TIMESTAMP_WIDTH + 2;  // APP_TIMESTAMP\0
	char *dirname = (char *)calloc(sizeof(char), n);
	strncat(dirname, app_name, app_name_length);
	strncat(dirname, "_", 1);
	snprintf(dirname + strlen(dirname), TIMESTAMP_WIDTH, "%lu",
		 get_time_sec());
	return dirname;
}

///////////////////////////////////////////////////////////////////////////////

#define PATH_LENGTH 30
#define CMDLINE_LENGTH 1024

char *alloc_cmdline_str(char **app_name) {
	// Build path to /proc/pid/cmdline in path
	char path[PATH_LENGTH];
	pid_t pid = getpid();
	if (snprintf(path, PATH_LENGTH, "/proc/%d/cmdline", pid) >=
	    PATH_LENGTH) {
		DEBUG(ERROR, "snprintf() failed (truncated).");
	}

	// Read /proc/pid/cmdline in cmdline
	FILE *fp = fopen(path, "r");
	if (fp == NULL) DEBUG(ERROR, "fopen() failed. %s", strerror(errno));
	char *cmdline = (char *)malloc(sizeof(char) * CMDLINE_LENGTH);
	size_t rc = fread(cmdline, 1, CMDLINE_LENGTH, fp);
	if (rc == 0) DEBUG(ERROR, "fread() failed.");
	fclose(fp);

	// Replace null bytes between args by white spaces &
	// make char *app_name point to the app_name.
	int i;
	int app_name_length = strlen(cmdline);
	*app_name = (char *)calloc(sizeof(char), app_name_length + 1);
	for (i = 0; i < rc - 1; i++) {
		if (i < app_name_length) (*app_name)[i] = cmdline[i];
		if (cmdline[i] == '\0') cmdline[i] = ' ';
	}

	return cmdline;
}

#define KERNEL_WIDTH 30
char *alloc_kernel_str() {
	FILE *fp;
	if ((fp = popen("uname -r", "r")) == NULL) {
		DEBUG(ERROR, "open() failed. %s", strerror(errno));
		return NULL;
	}

	char *kernel = (char *)calloc(sizeof(char), KERNEL_WIDTH);
	if (fgets(kernel, KERNEL_WIDTH, fp) == NULL) {
		DEBUG(ERROR,
		      "fgets() failed. Error or end of file occured "
		      "while not characters have been read");
		return NULL;
	}

	if (pclose(fp) == -1) {
		DEBUG(ERROR, "pclose() failed. %s", strerror(errno));
	}

	// Erase \n at last position.
	kernel[strlen(kernel) - 1] = '\0';
	return kernel;
}

///////////////////////////////////////////////////////////////////////////////

typedef struct {
	int cons;
	const char str[30]; 
} IntStrPair;

/* Socket domains */
static const IntStrPair SOCKET_DOMAINS[] = {
	{ AF_UNIX, 	"AF_UNIX" }, 
	{ AF_INET, 	"AF_INET" },
	{ AF_INET6, 	"AF_INET6" },
	{ AF_IPX, 	"AF_IPX" },
	{ AF_NETLINK,	"AF_NETLINK" },
	{ AF_PACKET, 	"AF_PACKET" }
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
	// Socket-level options (asm-generic/socket.h) 
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
	// IP-level options (linux/in.h) Wrong place?		
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
	// TCP-level options (netinet/tcp.h)
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
	{ TCP_TIMESTAMP,	"TCP_TIMESTAMP" }
};

#define MEMBER_SIZE(type, member) sizeof(((type *)0)->member)

static char *alloc_string_from_cons(int cons, const IntStrPair *map, 
	                            int map_size) {
	static const int str_size = MEMBER_SIZE(IntStrPair, str);
	int i;
	char *str = (char *)malloc(str_size);
	if (str == NULL) {
		DEBUG(ERROR, "malloc() failed. Cannot build string.");
		return str;
	}

	// Search for const in map.
 	const IntStrPair *cur;
	for (i = 0; i < map_size; i++) {
		cur = (map+i);
		if (cur->cons == cons) {
			strncpy(str, cur->str, str_size);
			return str; 
		}
	}
	
	// No match found, just write the constant digit.
	snprintf(str, str_size, "%d", cons);
	return str;
}

char *alloc_sock_domain_str(int domain) {
	int map_size = sizeof(SOCKET_DOMAINS)/sizeof(IntStrPair);	
	char *str = alloc_string_from_cons(domain, SOCKET_DOMAINS, map_size);
	return str;
}

char *alloc_sock_type_str(int type) {
	int map_size = sizeof(SOCKET_TYPES)/sizeof(IntStrPair);	
	char *str = alloc_string_from_cons(type, SOCKET_TYPES, map_size);
	return str;
}

char *alloc_sock_optname_str(int optname) {
	int map_size = sizeof(SOCKET_OPTIONS)/sizeof(IntStrPair);	
	char *str = alloc_string_from_cons(optname, SOCKET_OPTIONS, map_size);
	return str;
}

///////////////////////////////////////////////////////////////////////////////

char *alloc_error_str(int err) {
	char *ori_str = strerror(err);
	size_t str_len = strlen(ori_str) + 1;
	char *alloc_str = (char *)malloc(str_len);
	if (alloc_str == NULL) {
		DEBUG(ERROR, "malloc() failed.");
		return NULL;
	}
	strncpy(alloc_str, ori_str, str_len);
	return alloc_str;
}

///////////////////////////////////////////////////////////////////////////////
