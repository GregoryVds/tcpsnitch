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
