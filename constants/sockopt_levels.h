#include "asm-generic/socket.h"
#include "netinet/tcp.h"
#include "linux/tipc.h"
#include "linux/can.h"
#include "linux/can/raw.h"
#include "linux/irda.h"
#include "linux/rds.h"
#ifndef __ANDROID__
#include "netrose/rose.h"
#include "netatalk/at.h"
#include "netinet/udp.h"
#endif

static const IntStrPair SOCKOPT_LEVELS[] = {
    // /usr/include/asm-generic/socket.h
#ifdef SOL_SOCKET
    ADD(SOL_SOCKET),
#endif
    // /usr/include/netinet/tcp.h
#ifdef SOL_TCP
    ADD(SOL_TCP),
#endif
    // /usr/include/netinet/udp.h
#ifdef SOL_UDP
    ADD(SOL_UDP),
#endif
    // /usr/include/x86_64-linux-gnu/bits/in.h
#ifdef SOL_IP
    ADD(SOL_IP),
#endif
#ifdef SOL_IPV6
    ADD(SOL_IPV6),
#endif
#ifdef SOL_ICMPV6
    ADD(SOL_ICMPV6),
#endif
    // /usr/include/x86_64-linux-gnu/bits/socket.h
#ifdef SOL_RAW
    ADD(SOL_RAW),
#endif
#ifdef SOL_DECNET
    ADD(SOL_DECNET),
#endif
#ifdef SOL_X25
    ADD(SOL_X25),
#endif
#ifdef SOL_PACKET
    ADD(SOL_PACKET),
#endif
#ifdef SOL_ATM
    ADD(SOL_ATM),
#endif
#ifdef SOL_AAL
    ADD(SOL_AAL),
#endif
#ifdef SOL_IRDA
    ADD(SOL_IRDA),
#endif
    // /usr/include/netatalk/at.h
#ifdef SOL_ATALK
    ADD(SOL_ATALK),
#endif
    // /usr/include/netrose/rose.h
#ifdef SOL_ROSE
    ADD(SOL_ROSE),
#endif
    // /usr/include/netrose/netrom.h
#ifdef SOL_NETROM
    ADD(SOL_NETROM),
#endif
    // /usr/include/netax25/ax25.h
#ifdef SOL_AX25
    ADD(SOL_AX25),
#endif
    // /usr/include/netipx/ipx.h
#ifdef SOL_IPX
    ADD(SOL_IPX),
#endif
    // /usr/include/linux/tipc.h
#ifdef SOL_TIPC
    ADD(SOL_TIPC),
#endif
#ifdef SOL_CAN_BASE
    // /usr/include/linux/can.h
    ADD(SOL_CAN_BASE),
#endif
    // /usr/include/linux/can/raw.h
#ifdef SOL_CAN_RAW
    ADD(SOL_CAN_RAW),
#endif
    // /usr/include/linux/irda.h
#ifdef SOL_IRLMP
    ADD(SOL_IRLMP),
#endif
#ifdef SOL_IRTTP
    ADD(SOL_IRTTP),
#endif
    // /usr/include/linux/rds.h
#ifdef SOL_RDS
    ADD(SOL_RDS)
#endif
};
