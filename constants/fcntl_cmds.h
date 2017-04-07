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
