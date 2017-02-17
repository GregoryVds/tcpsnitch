/*
 * Author: Gregory Vander Schueren
 * Email: gregory.vanderschueren@gmail.com
 * Date: October, 2016
 */

#define _GNU_SOURCE

#include "lib.h"
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "init.h"
#include "logger.h"
#include "string_builders.h"
#include "tcp_events.h"

/*
 Use "standard" font here to generate ASCII arts:
 http://patorjk.com/software/taag/#p=display&f=Standard
*/

/*
  ____   ___   ____ _  _______ _____      _    ____ ___
 / ___| / _ \ / ___| |/ / ____|_   _|    / \  |  _ \_ _|
 \___ \| | | | |   | ' /|  _|   | |     / _ \ | |_) | |
  ___) | |_| | |___| . \| |___  | |    / ___ \|  __/| |
 |____/ \___/ \____|_|\_\_____| |_|   /_/   \_\_|  |___|

 sys/socket.h - Internet Protocol family

 functions: socket(), bind(), connect(), shutdown(), listen(), accept(),
 setsockopt(), send(), recv(), sendto(), recvfrom(), sendmsg(),  recvmsg(),
 sendmmsg(), recvmmsg(), getsockname().

*/

typedef int (*orig_socket_type)(int domain, int type, int protocol);
orig_socket_type orig_socket;

int socket(int domain, int type, int protocol) {
        if (!orig_socket)
                orig_socket = (orig_socket_type)dlsym(RTLD_NEXT, "socket");

        int fd = orig_socket(domain, type, protocol);
        if (is_tcp_socket(fd)) tcp_ev_socket(fd, domain, type, protocol);
        return fd;
}

typedef int (*orig_bind_type)(int fd, const struct sockaddr *addr,
                              socklen_t len);
orig_bind_type orig_bind;

int bind(int fd, const struct sockaddr *addr, socklen_t len) {
        if (!orig_bind) orig_bind = (orig_bind_type)dlsym(RTLD_NEXT, "bind");

        int ret = orig_bind(fd, addr, len);
        int err = errno;
        if (is_tcp_socket(fd)) tcp_ev_bind(fd, ret, err, addr, len);

        errno = err;
        return ret;
}

typedef int (*orig_connect_type)(int fd, const struct sockaddr *addr,
                                 socklen_t len);
orig_connect_type orig_connect;

int connect(int fd, const struct sockaddr *addr, socklen_t len) {
        if (!orig_connect)
                orig_connect = (orig_connect_type)dlsym(RTLD_NEXT, "connect");

        if (is_tcp_socket(fd) && conf_opt_c) tcp_start_capture(fd, addr);
        int ret = orig_connect(fd, addr, len);
        int err = errno;
        if (is_tcp_socket(fd)) tcp_ev_connect(fd, ret, err, addr, len);

        errno = err;
        return ret;
}

typedef int (*orig_shutdown_type)(int fd, int how);
orig_shutdown_type orig_shutdown;

int shutdown(int fd, int how) {
        if (!orig_shutdown)
                orig_shutdown =
                    (orig_shutdown_type)dlsym(RTLD_NEXT, "shutdown");

        int ret = orig_shutdown(fd, how);
        int err = errno;
        if (is_tcp_socket(fd)) tcp_ev_shutdown(fd, ret, err, how);

        errno = err;
        return ret;
}

typedef int (*orig_listen_type)(int fd, int n);
orig_listen_type orig_listen;

int listen(int fd, int n) {
        if (!orig_listen)
                orig_listen = (orig_listen_type)dlsym(RTLD_NEXT, "listen");

        int ret = orig_listen(fd, n);
        int err = errno;
        if (is_tcp_socket(fd)) tcp_ev_listen(fd, ret, err, n);

        errno = err;
        return ret;
}

typedef int (*orig_accept_type)(int fd, struct sockaddr *addr,
                                socklen_t *addr_len);
orig_accept_type orig_accept;

int accept(int fd, struct sockaddr *addr, socklen_t *addr_len) {
        if (!orig_accept)
                orig_accept = (orig_accept_type)dlsym(RTLD_NEXT, "accept");

        int ret = orig_accept(fd, addr, addr_len);
        int err = errno;
        if (is_tcp_socket(fd)) tcp_ev_accept(fd, ret, err, addr, addr_len);

        errno = err;
        return ret;
}

typedef int (*orig_getsockopt_type)(int fd, int level, int optname,
                                    void *optval, socklen_t *optlen);

orig_getsockopt_type orig_getsockopt;

int getsockopt(int fd, int level, int optname, void *optval,
               socklen_t *optlen) {
        if (!orig_getsockopt)
                orig_getsockopt =
                    (orig_getsockopt_type)dlsym(RTLD_NEXT, "getsockopt");

        int ret = orig_getsockopt(fd, level, optname, optval, optlen);
        int err = errno;
        if (is_tcp_socket(fd))
                tcp_ev_getsockopt(fd, ret, err, level, optname, optval,
                                  uoptlen);

        errno = err;
        return ret;
}

typedef int (*orig_setsockopt_type)(int fd, int level, int optname,
                                    const void *optval, socklen_t optlen);
orig_setsockopt_type orig_setsockopt;

int setsockopt(int fd, int level, int optname, const void *optval,
               socklen_t optlen) {
        if (!orig_setsockopt)
                orig_setsockopt =
                    (orig_setsockopt_type)dlsym(RTLD_NEXT, "setsockopt");

        int ret = orig_setsockopt(fd, level, optname, optval, optlen);
        int err = errno;
        if (is_tcp_socket(fd))
                tcp_ev_setsockopt(fd, ret, err, level, optname, optval, optlen);

        errno = err;
        return ret;
}

#if defined(__ANDROID__)
typedef ssize_t (*orig_send_type)(int fd, const void *buf, size_t n,
                                  unsigned int flags);
#else
typedef ssize_t (*orig_send_type)(int fd, const void *buf, size_t n, int flags);
#endif

orig_send_type orig_send;

#if defined(__ANDROID__) && __ANDROID_API__ <= 19
ssize_t send(int fd, const void *buf, size_t n, unsigned int flags) {
#else
ssize_t send(int fd, const void *buf, size_t n, int flags) {
#endif
        if (!orig_send) orig_send = (orig_send_type)dlsym(RTLD_NEXT, "send");

        ssize_t ret = orig_send(fd, buf, n, flags);
        int err = errno;
        if (is_tcp_socket(fd)) tcp_ev_send(fd, (int)ret, err, n, flags);

        errno = err;
        return ret;
}

#if defined(__ANDROID__) && __ANDROID_API__ <= 19
typedef ssize_t (*orig_recv_type)(int fd, void *buf, size_t n,
                                  unsigned int flags);
#else
typedef ssize_t (*orig_recv_type)(int fd, void *buf, size_t n, int flags);
#endif

orig_recv_type orig_recv;

#if defined(__ANDROID__) && __ANDROID_API__ <= 19
ssize_t recv(int fd, void *buf, size_t n, unsigned int flags) {
#else
ssize_t recv(int fd, void *buf, size_t n, int flags) {
#endif
        if (!orig_recv) orig_recv = (orig_recv_type)dlsym(RTLD_NEXT, "recv");

        ssize_t ret = orig_recv(fd, buf, n, flags);
        int err = errno;
        if (is_tcp_socket(fd)) tcp_ev_recv(fd, ret, err, n, flags);

        errno = err;
        return ret;
}

typedef ssize_t (*orig_sendto_type)(int fd, const void *buf, size_t n,
                                    int flags, const struct sockaddr *addr,
                                    socklen_t addr_len);
orig_sendto_type orig_sendto;

ssize_t sendto(int fd, const void *buf, size_t n, int flags,
               const struct sockaddr *addr, socklen_t addr_len) {
        if (!orig_sendto)
                orig_sendto = (orig_sendto_type)dlsym(RTLD_NEXT, "sendto");

        ssize_t ret = orig_sendto(fd, buf, n, flags, addr, addr_len);
        int err = errno;
        if (is_tcp_socket(fd))
                tcp_ev_sendto(fd, ret, err, n, flags, addr, addr_len);

        errno = err;
        return ret;
}

#if defined(__ANDROID__) && __ANDROID_API__ <= 19
typedef ssize_t (*orig_recvfrom_type)(int fd, void *buf, size_t n,
                                      unsigned int flags,
                                      const struct sockaddr *__addr,
                                      socklen_t *addr_len);
#elif defined(__ANDROID__)
typedef ssize_t (*orig_recvfrom_type)(int fd, void *buf, size_t n, int flags,
                                      const struct sockaddr *__addr,
                                      socklen_t *addr_len);
#else
typedef ssize_t (*orig_recvfrom_type)(int fd, void *buf, size_t n, int flags,
                                      struct sockaddr *__addr,
                                      socklen_t *addr_len);
#endif

orig_recvfrom_type orig_recvfrom;

#if defined(__ANDROID__) && __ANDROID_API__ <= 19
ssize_t recvfrom(int fd, void *buf, size_t n, unsigned int flags,
                 const struct sockaddr *addr, socklen_t *addr_len) {
#elif defined(__ANDROID__)
ssize_t recvfrom(int fd, void *buf, size_t n, int flags,
                 const struct sockaddr *addr, socklen_t *addr_len) {
#else
ssize_t recvfrom(int fd, void *buf, size_t n, int flags, struct sockaddr *addr,
                 socklen_t *addr_len) {
#endif
        if (!orig_recvfrom)
                orig_recvfrom =
                    (orig_recvfrom_type)dlsym(RTLD_NEXT, "recvfrom");

        ssize_t ret = orig_recvfrom(fd, buf, n, flags, addr, addr_len);
        int err = errno;
        if (is_tcp_socket(fd))
                tcp_ev_recvfrom(fd, ret, err, n, flags, addr, addr_len);

        errno = err;
        return ret;
}

#if defined(__ANDROID__) && __ANDROID_API__ <= 19
typedef ssize_t (*orig_sendmsg_type)(int fd, const struct msghdr *message,
                                     unsigned int flags);
#else
typedef ssize_t (*orig_sendmsg_type)(int fd, const struct msghdr *message,
                                     int flags);
#endif

orig_sendmsg_type orig_sendmsg;

#if defined(__ANDROID__) && __ANDROID_API__ <= 19
ssize_t sendmsg(int fd, const struct msghdr *message, unsigned int flags) {
#else
ssize_t sendmsg(int fd, const struct msghdr *message, int flags) {
#endif
        if (!orig_sendmsg)
                orig_sendmsg = (orig_sendmsg_type)dlsym(RTLD_NEXT, "sendmsg");

        ssize_t ret = orig_sendmsg(fd, message, flags);
        int err = errno;
        if (is_tcp_socket(fd)) tcp_ev_sendmsg(fd, ret, err, message, flags);

        errno = err;
        return ret;
}

#if defined(__ANDROID__) && __ANDROID_API__ <= 19
typedef ssize_t (*orig_recvmsg_type)(int fd, struct msghdr *message,
                                     unsigned int flags);
#else
typedef ssize_t (*orig_recvmsg_type)(int fd, struct msghdr *message, int flags);
#endif

orig_recvmsg_type orig_recvmsg;

#if defined(__ANDROID__) && __ANDROID_API__ <= 19
ssize_t recvmsg(int fd, struct msghdr *message, unsigned int flags) {
#else
ssize_t recvmsg(int fd, struct msghdr *message, int flags) {
#endif
        if (!orig_recvmsg)
                orig_recvmsg = (orig_recvmsg_type)dlsym(RTLD_NEXT, "recvmsg");

        ssize_t ret = orig_recvmsg(fd, message, flags);
        int err = errno;
        if (is_tcp_socket(fd)) tcp_ev_recvmsg(fd, ret, err, message, flags);

        errno = err;
        return ret;
}

#if !defined(__ANDROID__) || __ANDROID_API__ >= 21

#if !defined(__ANDROID__)
typedef int (*orig_sendmmsg_type)(int fd, struct mmsghdr *vmessages,
                                  unsigned int vlen, int flags);
#elif __ANDROID_API__ >= 21
typedef int (*orig_sendmmsg_type)(int fd, const struct mmsghdr *vmessages,
                                  unsigned int vlen, int flags);
#endif

orig_sendmmsg_type orig_sendmmsg;

#if !defined(__ANDROID__)
int sendmmsg(int fd, struct mmsghdr *vmessages, unsigned int vlen, int flags) {
#elif __ANDROID_API__ >= 21
int sendmmsg(int fd, const struct mmsghdr *vmessages, unsigned int vlen,
             int flags) {
#endif
        if (!orig_sendmmsg)
                orig_sendmmsg =
                    (orig_sendmmsg_type)dlsym(RTLD_NEXT, "sendmmsg");

        int ret = orig_sendmmsg(fd, vmessages, vlen, flags);
        int err = errno;
        if (is_tcp_socket(fd))
                tcp_ev_sendmmsg(fd, ret, err, vmessages, vlen, flags);

        errno = err;
        return ret;
}

#if !defined(__ANDROID__)
typedef int (*orig_recvmmsg_type)(int fd, struct mmsghdr *vmessages,
                                  unsigned int vlen, int flags,
                                  struct timespec *tmo);
#elif __ANDROID_API__ >= 21
typedef int (*orig_recvmmsg_type)(int fd, struct mmsghdr *vmessages,
                                  unsigned int vlen, int flags,
                                  const struct timespec *tmo);
#endif

orig_recvmmsg_type orig_recvmmsg;

#if !defined(__ANDROID__)
int recvmmsg(int fd, struct mmsghdr *vmessages, unsigned int vlen, int flags,
             struct timespec *tmo) {
#elif __ANDROID_API__ >= 21
int recvmmsg(int fd, struct mmsghdr *vmessages, unsigned int vlen, int flags,
             const struct timespec *tmo) {
#endif
        if (!orig_recvmmsg)
                orig_recvmmsg =
                    (orig_recvmmsg_type)dlsym(RTLD_NEXT, "recvmmsg");

        int ret = orig_recvmmsg(fd, vmessages, vlen, flags, tmo);
        int err = errno;
        if (is_tcp_socket(fd))
                tcp_ev_recvmmsg(fd, ret, err, vmessages, vlen, flags, tmo);

        errno = err;
        return ret;
}

#endif  // #if !defined(__ANDROID__) || __ANDROID_API__ >= 21

typedef int (*orig_getsockname_type)(int fd, struct sockaddr *addr,
                                     socklen_t *len);

orig_getsockname_type orig_getsockname;

int getsockname(int fd, struct sockaddr *addr, socklen_t *len) {
        if (!orig_getsockname)
                orig_getsockname =
                    (orig_getsockname_type)dlsym(RTLD_NEXT, "getsockname");

        int ret = orig_getsockname(fd, addr, len);
        int err = errno;
        if (is_tcp_socket(fd)) tcp_ev_getsockname(fd, ret, err, addr, len);

        errno = err;
        return ret;
}

/*
  _   _ _   _ ___ ____ _____ ____       _    ____ ___
 | | | | \ | |_ _/ ___|_   _|  _ \     / \  |  _ \_ _|
 | | | |  \| || |\___ \ | | | | | |   / _ \ | |_) | |
 | |_| | |\  || | ___) || | | |_| |  / ___ \|  __/| |
  \___/|_| \_|___|____/ |_| |____/  /_/   \_\_|  |___|

 unistd.h - standard symbolic constants and types

 functions: write(), read(), close(), fork(), dup(), dup2(), dup3()

*/

typedef ssize_t (*orig_write_type)(int fd, const void *buf, size_t n);
orig_write_type orig_write;

ssize_t write(int fd, const void *buf, size_t n) {
        if (!orig_write)
                orig_write = (orig_write_type)dlsym(RTLD_NEXT, "write");

        int ret = orig_write(fd, buf, n);
        int err = errno;
        if (is_tcp_socket(fd)) tcp_ev_write(fd, ret, err, n);

        errno = err;
        return ret;
}

typedef ssize_t (*orig_read_type)(int fd, void *buf, size_t nbytes);
orig_read_type orig_read;

ssize_t read(int fd, void *buf, size_t nbytes) {
        if (!orig_read) orig_read = (orig_read_type)dlsym(RTLD_NEXT, "read");

        int ret = orig_read(fd, buf, nbytes);
        int err = errno;
        if (is_tcp_socket(fd)) tcp_ev_read(fd, ret, err, nbytes);

        errno = err;
        return ret;
}

typedef int (*orig_close_type)(int fd);
orig_close_type orig_close;

int close(int fd) {
        if (!orig_close)
                orig_close = (orig_close_type)dlsym(RTLD_NEXT, "close");

        bool is_tcp = is_tcp_socket(fd);
        int ret = orig_close(fd);
        int err = errno;
        if (is_tcp) tcp_ev_close(fd, ret, err, true);

        errno = err;
        return ret;
}

typedef pid_t (*orig_fork_type)(void);
orig_fork_type orig_fork;

pid_t fork(void) {
        if (!orig_fork) orig_fork = (orig_fork_type)dlsym(RTLD_NEXT, "fork");
        LOG(INFO, "fork() called.");

        pid_t ret = orig_fork();
        int err = errno;
        if (ret == 0) reset_tcpsnitch();  // Child

        errno = err;
        return ret;
}

typedef int (*orig_dup_type)(int fd);
orig_dup_type orig_dup;

int dup(int fd) {
        if (!orig_dup) orig_dup = (orig_dup_type)dlsym(RTLD_NEXT, "dup");

        int ret = orig_dup(fd);
        int err = errno;
        if (is_tcp_socket(fd)) tcp_ev_dup(fd, ret, err);

        errno = err;
        return ret;
}

typedef int (*orig_dup2_type)(int fd, int newfd);
orig_dup2_type orig_dup2;

int dup2(int fd, int newfd) {
        if (!orig_dup2) orig_dup2 = (orig_dup2_type)dlsym(RTLD_NEXT, "dup2");

        int ret = orig_dup2(fd, newfd);
        int err = errno;
        if (is_tcp_socket(fd)) tcp_ev_dup2(fd, ret, err, newfd);

        errno = err;
        return ret;
}

typedef int (*orig_dup3_type)(int fd, int newfd, int flags);
orig_dup3_type orig_dup3;

int dup3(int fd, int newfd, int flags) {
        if (!orig_dup3) orig_dup3 = (orig_dup3_type)dlsym(RTLD_NEXT, "dup3");

        int ret = orig_dup3(fd, newfd, flags);
        int err = errno;
        if (is_tcp_socket(fd)) tcp_ev_dup3(fd, ret, err, newfd, flags);

        errno = err;
        return ret;
}

/*
  _   _ _ _____       _    ____ ___
 | | | |_ _/ _ \     / \  |  _ \_ _|
 | | | || | | | |   / _ \ | |_) | |
 | |_| || | |_| |  / ___ \|  __/| |
  \___/|___\___/  /_/   \_\_|  |___|

 sys/uio.h - definitions for vector I/O operations

 functions: writev(), readv()

*/

typedef ssize_t (*orig_writev_type)(int fd, const struct iovec *iovec,
                                    int count);
orig_writev_type orig_writev;

ssize_t writev(int fd, const struct iovec *iovec, int count) {
        if (!orig_writev)
                orig_writev = (orig_writev_type)dlsym(RTLD_NEXT, "writev");

        int ret = orig_writev(fd, iovec, count);
        int err = errno;
        if (is_tcp_socket(fd)) tcp_ev_writev(fd, ret, err, iovec, count);

        errno = err;
        return ret;
}

typedef ssize_t (*orig_readv_type)(int fd, const struct iovec *iovec,
                                   int count);
orig_readv_type orig_readv;

ssize_t readv(int fd, const struct iovec *iovec, int count) {
        if (!orig_readv)
                orig_readv = (orig_readv_type)dlsym(RTLD_NEXT, "readv");

        int ret = orig_readv(fd, iovec, count);
        int err = errno;
        if (is_tcp_socket(fd)) tcp_ev_readv(fd, ret, err, iovec, count);

        errno = err;
        return ret;
}

/*
  ___ ___   ____ _____ _          _    ____ ___
 |_ _/ _ \ / ___|_   _| |        / \  |  _ \_ _|
  | | | | | |     | | | |       / _ \ | |_) | |
  | | |_| | |___  | | | |___   / ___ \|  __/| |
 |___\___/ \____| |_| |_____| /_/   \_\_|  |___|

  sys/ioctl.h - control device

  functions: ioctl()
*/

#ifdef __ANDROID__
typedef int (*orig_ioctl_type)(int fd, int request, ...);
#else
typedef int (*orig_ioctl_type)(int fd, unsigned long int request, ...);
#endif

orig_ioctl_type orig_ioctl;

#ifdef __ANDROID__
int ioctl(int fd, int request, ...) {
#else
int ioctl(int fd, unsigned long int request, ...) {
#endif
        va_list argp;
        va_start(argp, request);
        void *value = va_arg(argp, void *);
        va_end(argp);

        if (!orig_ioctl)
                orig_ioctl = (orig_ioctl_type)dlsym(RTLD_NEXT, "ioctl");

        int ret = orig_ioctl(fd, request, value);
        int err = errno;
        if (is_tcp_socket(fd)) tcp_ev_ioctl(fd, ret, err, request);

        errno = err;
        return ret;
}

/*
  ____  _____ _   _ ____  _____ ___ _     _____      _    ____ ___
 / ___|| ____| \ | |  _ \|  ___|_ _| |   | ____|    / \  |  _ \_ _|
 \___ \|  _| |  \| | | | | |_   | || |   |  _|     / _ \ | |_) | |
  ___) | |___| |\  | |_| |  _|  | || |___| |___   / ___ \|  __/| |
 |____/|_____|_| \_|____/|_|   |___|_____|_____| /_/   \_\_|  |___|

 sendfile.h - transfer data between file descriptors

 functions: sendfile()
*/

typedef ssize_t (*orig_sendfile_type)(int out_fd, int in_fd, off_t *offset,
                                      size_t count);
orig_sendfile_type orig_sendfile;

ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
        if (!orig_sendfile)
                orig_sendfile =
                    (orig_sendfile_type)dlsym(RTLD_NEXT, "sendfile");

        int ret = orig_sendfile(out_fd, in_fd, offset, count);
        int err = errno;
        if (is_tcp_socket(out_fd)) tcp_ev_sendfile(out_fd, ret, err, count);

        errno = err;
        return ret;
}

/*
  ____   ___  _     _          _    ____ ___
 |  _ \ / _ \| |   | |        / \  |  _ \_ _|
 | |_) | | | | |   | |       / _ \ | |_) | |
 |  __/| |_| | |___| |___   / ___ \|  __/| |
 |_|    \___/|_____|_____| /_/   \_\_|  |___|

 poll.h - definitions for the poll() function

 functions: poll(), ppoll()
*/

typedef int (*orig_poll_type)(struct pollfd *fds, nfds_t nfds, int timeout);

orig_poll_type orig_poll;

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
        if (!orig_poll) orig_poll = (orig_poll_type)dlsym(RTLD_NEXT, "poll");

        int ret = orig_poll(fds, nfds, timeout);
        int err = errno;
        unsigned long i;
        for (i = 0; i < nfds; i++) {
                struct pollfd pollfd = fds[i];
                if (is_tcp_socket(pollfd.fd))
                        tcp_ev_poll(pollfd.fd, ret, err, pollfd.events,
                                    pollfd.revents, timeout);
        }

        errno = err;
        return ret;
}

typedef int (*orig_ppoll_type)(struct pollfd *fds, nfds_t nfds,
                               const struct timespec *tmo_p,
                               const sigset_t *sigmask);

orig_ppoll_type orig_ppoll;

int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p,
          const sigset_t *sigmask) {
        if (!orig_ppoll)
                orig_ppoll = (orig_ppoll_type)dlsym(RTLD_NEXT, "ppoll");

        int ret = orig_ppoll(fds, nfds, tmo_p, sigmask);
        int err = errno;
        unsigned long i;
        for (i = 0; i < nfds; i++) {
                struct pollfd pollfd = fds[i];
                if (is_tcp_socket(pollfd.fd))
                        tcp_ev_ppoll(pollfd.fd, ret, err, pollfd.events,
                                     pollfd.revents, tmo_p);
        }

        errno = err;
        return ret;
}

/*
  ____  _____ _     _____ ____ _____      _    ____ ___
 / ___|| ____| |   | ____/ ___|_   _|    / \  |  _ \_ _|
 \___ \|  _| | |   |  _|| |     | |     / _ \ | |_) | |
  ___) | |___| |___| |__| |___  | |    / ___ \|  __/| |
 |____/|_____|_____|_____\____| |_|   /_/   \_\_|  |___|

 sys/select.h

 functions: select(), pselect().
*/

typedef int (*orig_select_type)(int nfds, fd_set *readfds, fd_set *writefds,
                                fd_set *exceptfds, struct timeval *timeout);

orig_select_type orig_select;

#define READ_FLAG 0b1
#define WRITE_FLAG 0b10
#define EXCEPT_FLAG 0b100

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
           struct timeval *timeout) {
        if (!orig_select)
                orig_select = (orig_select_type)dlsym(RTLD_NEXT, "select");

        short req_ev[nfds - 1];
        memset(req_ev, 0, sizeof(req_ev));

        int fd;
        for (fd = 0; fd < nfds; fd++) {
                if (is_tcp_socket(fd)) {
                        if (readfds && FD_ISSET(fd, readfds))
                                (req_ev[fd] = req_ev[fd] | READ_FLAG);
                        if (writefds && FD_ISSET(fd, writefds))
                                (req_ev[fd] = req_ev[fd] | WRITE_FLAG);
                        if (exceptfds && FD_ISSET(fd, exceptfds))
                                (req_ev[fd] = req_ev[fd] | EXCEPT_FLAG);
                }
        }

        int ret = orig_select(nfds, readfds, writefds, exceptfds, timeout);
        int err = errno;

        for (fd = 0; fd < nfds; fd++) {
                if (is_tcp_socket(fd) &&
                    req_ev[fd]) {  // Socket was in initial call
                        tcp_ev_select(fd, ret, err, (req_ev[fd] & READ_FLAG),
                                      (req_ev[fd] & WRITE_FLAG),
                                      (req_ev[fd] & EXCEPT_FLAG),
                                      readfds && FD_ISSET(fd, readfds),
                                      writefds && FD_ISSET(fd, writefds),
                                      exceptfds && FD_ISSET(fd, exceptfds),
                                      timeout);
                }
        }

        return ret;
}

typedef int (*orig_pselect_type)(int nfds, fd_set *readfds, fd_set *writefds,
                                 fd_set *exceptfds,
                                 const struct timespec *timeout,
                                 const sigset_t *sigmask);

orig_pselect_type orig_pselect;

int pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
            const struct timespec *timeout, const sigset_t *sigmask) {
        if (!orig_pselect)
                orig_pselect = (orig_pselect_type)dlsym(RTLD_NEXT, "pselect");

        short req_ev[nfds - 1];
        memset(req_ev, 0, sizeof(req_ev));

        int fd;
        for (fd = 0; fd < nfds; fd++) {
                if (is_tcp_socket(fd)) {
                        if (readfds && FD_ISSET(fd, readfds))
                                (req_ev[fd] = req_ev[fd] | READ_FLAG);
                        if (writefds && FD_ISSET(fd, writefds))
                                (req_ev[fd] = req_ev[fd] | WRITE_FLAG);
                        if (exceptfds && FD_ISSET(fd, exceptfds))
                                (req_ev[fd] = req_ev[fd] | EXCEPT_FLAG);
                }
        }

        int ret =
            orig_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
        int err = errno;

        for (fd = 0; fd < nfds; fd++) {
                if (is_tcp_socket(fd) && req_ev[fd]) {
                        tcp_ev_pselect(fd, ret, err, (req_ev[fd] & READ_FLAG),
                                       (req_ev[fd] & WRITE_FLAG),
                                       (req_ev[fd] & EXCEPT_FLAG),
                                       readfds && FD_ISSET(fd, readfds),
                                       writefds && FD_ISSET(fd, writefds),
                                       exceptfds && FD_ISSET(fd, exceptfds),
                                       timeout);
                }
        }

        errno = err;
        return ret;
}
