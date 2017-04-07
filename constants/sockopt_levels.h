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
