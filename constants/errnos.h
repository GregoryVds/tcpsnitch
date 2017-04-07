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
