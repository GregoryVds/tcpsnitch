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
    ADD(SOL_SOCKET),
    // /usr/include/netinet/tcp.h
    ADD(SOL_TCP),
    // /usr/include/netinet/udp.h
    ADD(SOL_UDP),
    // /usr/include/x86_64-linux-gnu/bits/in.h
    ADD(SOL_IP),
    ADD(SOL_IPV6),
    ADD(SOL_ICMPV6),
    // /usr/include/x86_64-linux-gnu/bits/socket.h
    ADD(SOL_RAW),
    ADD(SOL_DECNET),
    ADD(SOL_X25),
    ADD(SOL_PACKET),
    ADD(SOL_ATM),
    ADD(SOL_AAL),
    ADD(SOL_IRDA),
    // /usr/include/netatalk/at.h
    ADD(SOL_ATALK),
    // /usr/include/netrose/rose.h
    ADD(SOL_ROSE),
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
    ADD(SOL_TIPC),
    // /usr/include/linux/can.h
    ADD(SOL_CAN_BASE),
    // /usr/include/linux/can/raw.h
    ADD(SOL_CAN_RAW),
    // /usr/include/linux/irda.h
    ADD(SOL_IRLMP),
    ADD(SOL_IRTTP),
    // /usr/include/linux/rds.h
#ifdef SOL_RDS
    ADD(SOL_RDS)
#endif
};
