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
