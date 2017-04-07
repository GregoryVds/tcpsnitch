#define _GNU_SOURCE

#ifndef CONSTANTS_H
#define CONSTANTS_H

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
#include <stdbool.h>
#include <sys/socket.h>
#ifdef __ANDROID__
#include <linux/udp.h>
#else
#include <netinet/udp.h>
#endif
#include <unistd.h>
#include "lib.h"

#define MEMBER_SIZE(type, member) sizeof(((type *)0)->member)

#define ADD(constant) \
        { constant, #constant }
/* We use #ifdef directives to produce code that is easily portable on multiple
 * libc versions which may define different set of constants. */

typedef struct {
        int cons;
        const char str[40];
} IntStrPair;

#include "constants/errnos.h"
#include "constants/fcntl_cmds.h"
#include "constants/ioctl_requests.h"
#include "constants/ipproto_ip_options.h"
#include "constants/ipproto_ipv6_options.h"
#include "constants/ipproto_tcp_options.h"
#include "constants/ipproto_udp_options.h"
#include "constants/socket_domains.h"
#include "constants/socket_types.h"
#include "constants/sockopt_levels.h"
#include "constants/sol_packet_options.h"
#include "constants/sol_socket_options.h"

char *alloc_errno_str(int err);
char *alloc_fcntl_cmd_str(int cmd);
char *alloc_ioctl_request_str(int request);
char *alloc_sockoptname(int level, int optname);
char *alloc_sockopt_level(int level);
char *alloc_sock_domain_str(int domain);
char *alloc_sock_type_str(int type);

#endif
