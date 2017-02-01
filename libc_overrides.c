/*
 * Author: Gregory Vander Schueren
 * Email: gregory.vanderschueren@gmail.com
 * Date: October, 2016
 */

/*
 * This file contains all (and the only) symbols that should be exposed by
 * the NETSPY library. Those symbols are most of the networking related
 * functions from the C standard librairies.
 *
 * NETSPY works by intercepting all calls to theses functions and by performing
 * custom processing before and/or after calling the real implementation. This
 * will prove valuable when trying the model the network behaviour of
 * applications.
 *
 * On Linux, NETSPY works using LD_PRELOAD. This environnement variable tells
 * the linker to automatically link librairies in LD_PRELOAD BEFORE any other
 * dynamic librairy. When multiple librairies which define the same symbol are
 * linked, the first one to be linked gets the precedence. This way, we can
 * effectively override any function from the C standard library. We then use
 * the dynamic linking library <dlfcn.h> to get a reference to the original
 * implementation and call it.
 *
 * NETPSY has currently only been tested on Linux with the glibc implementation
 * of the C standard librairies. We mainly override Posix functions, but also
 * some Linux specific functions such sendfile().
 *
 */

#define _GNU_SOURCE

#include "lib.h"
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
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
 Use "standard" font of http://patorjk.com/software/taag to generate ASCII arts
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
 sendmmsg(), recvmmsg().

*/

typedef int (*orig_socket_type)(int __domain, int __type, int __protocol);
orig_socket_type orig_socket;

int socket(int __domain, int __type, int __protocol) {
        if (!orig_socket)
                orig_socket = (orig_socket_type)dlsym(RTLD_NEXT, "socket");

        int fd = orig_socket(__domain, __type, __protocol);
        if (is_tcp_socket(fd)) tcp_ev_socket(fd, __domain, __type, __protocol);

        return fd;
}

typedef int (*orig_bind_type)(int __fd, const struct sockaddr *__addr,
                              socklen_t __len);
orig_bind_type orig_bind;

int bind(int __fd, const struct sockaddr *__addr, socklen_t __len) {
        if (!orig_bind) orig_bind = (orig_bind_type)dlsym(RTLD_NEXT, "bind");

        int ret = orig_bind(__fd, __addr, __len);
        int err = errno;
        if (is_tcp_socket(__fd)) tcp_ev_bind(__fd, ret, err, __addr, __len);

        errno = err;
        return ret;
}

typedef int (*orig_connect_type)(int __fd, const struct sockaddr *__addr,
                                 socklen_t __len);
orig_connect_type orig_connect;

int connect(int __fd, const struct sockaddr *__addr, socklen_t __len) {
        if (!orig_connect)
                orig_connect = (orig_connect_type)dlsym(RTLD_NEXT, "connect");

        if (is_tcp_socket(__fd) && conf_opt_c) tcp_start_capture(__fd, __addr);
        int ret = orig_connect(__fd, __addr, __len);
        int err = errno;
        if (is_tcp_socket(__fd)) tcp_ev_connect(__fd, ret, err, __addr, __len);

        errno = err;
        return ret;
}

typedef int (*orig_shutdown_type)(int __fd, int __how);
orig_shutdown_type orig_shutdown;

int shutdown(int __fd, int __how) {
        if (!orig_shutdown)
                orig_shutdown =
                    (orig_shutdown_type)dlsym(RTLD_NEXT, "shutdown");

        int ret = orig_shutdown(__fd, __how);
        int err = errno;
        if (is_tcp_socket(__fd)) tcp_ev_shutdown(__fd, ret, err, __how);

        errno = err;
        return ret;
}

typedef int (*orig_listen_type)(int __fd, int __n);
orig_listen_type orig_listen;

int listen(int __fd, int __n) {
        if (!orig_listen)
                orig_listen = (orig_listen_type)dlsym(RTLD_NEXT, "listen");

        int ret = orig_listen(__fd, __n);
        int err = errno;
        if (is_tcp_socket(__fd)) tcp_ev_listen(__fd, ret, err, __n);

        errno = err;
        return ret;
}

typedef int (*orig_accept_type)(int __fd, struct sockaddr *__addr,
                                socklen_t *__addr_len);
orig_accept_type orig_accept;

int accept(int __fd, struct sockaddr *__addr, socklen_t *__addr_len) {
        if (!orig_accept)
                orig_accept = (orig_accept_type)dlsym(RTLD_NEXT, "accept");

        int ret = orig_accept(__fd, __addr, __addr_len);
        int err = errno;
        if (is_tcp_socket(__fd))
                tcp_ev_accept(__fd, ret, err, __addr, __addr_len);

        errno = err;
        return ret;
}

typedef int (*orig_setsockopt_type)(int __fd, int __level, int __optname,
                                    const void *__optval, socklen_t __optlen);
orig_setsockopt_type orig_setsockopt;

int setsockopt(int __fd, int __level, int __optname, const void *__optval,
               socklen_t __optlen) {
        if (!orig_setsockopt)
                orig_setsockopt =
                    (orig_setsockopt_type)dlsym(RTLD_NEXT, "setsockopt");

        int ret = orig_setsockopt(__fd, __level, __optname, __optval, __optlen);
        int err = errno;
        if (is_tcp_socket(__fd))
                tcp_ev_setsockopt(__fd, ret, err, __level, __optname);

        errno = err;
        return ret;
}

#if defined(__ANDROID__)
typedef ssize_t (*orig_send_type)(int __fd, const void *__buf, size_t __n,
                                  unsigned int __flags);
#else
typedef ssize_t (*orig_send_type)(int __fd, const void *__buf, size_t __n,
                                  int __flags);
#endif

orig_send_type orig_send;

#if defined(__ANDROID__) && __ANDROID_API__ <= 19
ssize_t send(int __fd, const void *__buf, size_t __n, unsigned int __flags) {
#else
ssize_t send(int __fd, const void *__buf, size_t __n, int __flags) {
#endif
        if (!orig_send) orig_send = (orig_send_type)dlsym(RTLD_NEXT, "send");

        ssize_t ret = orig_send(__fd, __buf, __n, __flags);
        int err = errno;
        if (is_tcp_socket(__fd)) tcp_ev_send(__fd, (int)ret, err, __n, __flags);

        errno = err;
        return ret;
}

#if defined(__ANDROID__) && __ANDROID_API__ <= 19
typedef ssize_t (*orig_recv_type)(int __fd, void *__buf, size_t __n,
                                  unsigned int __flags);
#else
typedef ssize_t (*orig_recv_type)(int __fd, void *__buf, size_t __n,
                                  int __flags);
#endif

orig_recv_type orig_recv;

#if defined(__ANDROID__) && __ANDROID_API__ <= 19
ssize_t recv(int __fd, void *__buf, size_t __n, unsigned int __flags) {
#else
ssize_t recv(int __fd, void *__buf, size_t __n, int __flags) {
#endif
        if (!orig_recv) orig_recv = (orig_recv_type)dlsym(RTLD_NEXT, "recv");

        ssize_t ret = orig_recv(__fd, __buf, __n, __flags);
        int err = errno;
        if (is_tcp_socket(__fd)) tcp_ev_recv(__fd, ret, err, __n, __flags);

        errno = err;
        return ret;
}

typedef ssize_t (*orig_sendto_type)(int __fd, const void *__buf, size_t __n,
                                    int __flags, const struct sockaddr *__addr,
                                    socklen_t __addr_len);
orig_sendto_type orig_sendto;

ssize_t sendto(int __fd, const void *__buf, size_t __n, int __flags,
               const struct sockaddr *__addr, socklen_t __addr_len) {
        if (!orig_sendto)
                orig_sendto = (orig_sendto_type)dlsym(RTLD_NEXT, "sendto");

        ssize_t ret =
            orig_sendto(__fd, __buf, __n, __flags, __addr, __addr_len);
        int err = errno;
        if (is_tcp_socket(__fd))
                tcp_ev_sendto(__fd, ret, err, __n, __flags, __addr, __addr_len);

        errno = err;
        return ret;
}

#if defined(__ANDROID__) && __ANDROID_API__ <= 19
typedef ssize_t (*orig_recvfrom_type)(int __fd, void *__restrict __buf,
                                      size_t __n, unsigned int __flags,
                                      const struct sockaddr *__addr,
                                      socklen_t *__restrict __addr_len);
#else
typedef ssize_t (*orig_recvfrom_type)(int __fd, void *__restrict __buf,
                                      size_t __n, int __flags,
                                      struct sockaddr *__addr,
                                      socklen_t *__restrict __addr_len);
#endif

orig_recvfrom_type orig_recvfrom;

#if defined(__ANDROID__) && __ANDROID_API__ <= 19
ssize_t recvfrom(int __fd, void *__restrict __buf, size_t __n,
                 unsigned int __flags, const struct sockaddr *__addr,
                 socklen_t *__addr_len) {
#else
ssize_t recvfrom(int __fd, void *__restrict __buf, size_t __n, int __flags,
                 struct sockaddr *__addr, socklen_t *__addr_len) {
#endif
        if (!orig_recvfrom)
                orig_recvfrom =
                    (orig_recvfrom_type)dlsym(RTLD_NEXT, "recvfrom");

        ssize_t ret =
            orig_recvfrom(__fd, __buf, __n, __flags, __addr, __addr_len);
        int err = errno;
        if (is_tcp_socket(__fd))
                tcp_ev_recvfrom(__fd, ret, err, __n, __flags, __addr,
                                *__addr_len);

        errno = err;
        return ret;
}

#if defined(__ANDROID__) && __ANDROID_API__ <= 19
typedef ssize_t (*orig_sendmsg_type)(int __fd, const struct msghdr *__message,
                                     unsigned int __flags);
#else
typedef ssize_t (*orig_sendmsg_type)(int __fd, const struct msghdr *__message,
                                     int __flags);
#endif

orig_sendmsg_type orig_sendmsg;

#if defined(__ANDROID__) && __ANDROID_API__ <= 19
ssize_t sendmsg(int __fd, const struct msghdr *__message,
                unsigned int __flags) {
#else
ssize_t sendmsg(int __fd, const struct msghdr *__message, int __flags) {
#endif
        if (!orig_sendmsg)
                orig_sendmsg = (orig_sendmsg_type)dlsym(RTLD_NEXT, "sendmsg");

        ssize_t ret = orig_sendmsg(__fd, __message, __flags);
        int err = errno;
        if (is_tcp_socket(__fd))
                tcp_ev_sendmsg(__fd, ret, err, __message, __flags);

        errno = err;
        return ret;
}

#if defined(__ANDROID__) && __ANDROID_API__ <= 19
typedef ssize_t (*orig_recvmsg_type)(int __fd, struct msghdr *__message,
                                     unsigned int __flags);
#else
typedef ssize_t (*orig_recvmsg_type)(int __fd, struct msghdr *__message,
                                     int __flags);
#endif

orig_recvmsg_type orig_recvmsg;

#if defined(__ANDROID__) && __ANDROID_API__ <= 19
ssize_t recvmsg(int __fd, struct msghdr *__message, unsigned int __flags) {
#else
ssize_t recvmsg(int __fd, struct msghdr *__message, int __flags) {
#endif
        if (!orig_recvmsg)
                orig_recvmsg = (orig_recvmsg_type)dlsym(RTLD_NEXT, "recvmsg");

        ssize_t ret = orig_recvmsg(__fd, __message, __flags);
        int err = errno;
        if (is_tcp_socket(__fd))
                tcp_ev_recvmsg(__fd, ret, err, __message, __flags);

        errno = err;
        return ret;
}

#if !defined(__ANDROID__) || __ANDROID_API__ >= 21
typedef int (*orig_sendmmsg_type)(int __fd, struct mmsghdr *__vmessages,
                                  unsigned int __vlen, int __flags);

orig_sendmmsg_type orig_sendmmsg;

int sendmmsg(int __fd, struct mmsghdr *__vmessages, unsigned int __vlen,
             int __flags) {
        if (!orig_sendmmsg)
                orig_sendmmsg =
                    (orig_sendmmsg_type)dlsym(RTLD_NEXT, "sendmmsg");

        int ret = orig_sendmmsg(__fd, __vmessages, __vlen, __flags);
        int err = errno;
        if (is_tcp_socket(__fd))
                tcp_ev_sendmmsg(__fd, ret, err, __vmessages, __vlen, __flags);

        errno = err;
        return ret;
}

typedef int (*orig_recvmmsg_type)(int __fd, struct mmsghdr *__vmessages,
                                  unsigned int __vlen, int __flags,
                                  struct timespec *__tmo);

orig_recvmmsg_type orig_recvmmsg;

int recvmmsg(int __fd, struct mmsghdr *__vmessages, unsigned int __vlen,
             int __flags, struct timespec *__tmo) {
        if (!orig_recvmmsg)
                orig_recvmmsg =
                    (orig_recvmmsg_type)dlsym(RTLD_NEXT, "recvmmsg");

        int ret = orig_recvmmsg(__fd, __vmessages, __vlen, __flags, __tmo);
        int err = errno;
        if (is_tcp_socket(__fd))
                tcp_ev_recvmmsg(__fd, ret, err, __vmessages, __vlen, __flags,
                                __tmo);

        errno = err;
        return ret;
}
#endif

/*
  _   _ _   _ ___ ____ _____ ____       _    ____ ___
 | | | | \ | |_ _/ ___|_   _|  _ \     / \  |  _ \_ _|
 | | | |  \| || |\___ \ | | | | | |   / _ \ | |_) | |
 | |_| | |\  || | ___) || | | |_| |  / ___ \|  __/| |
  \___/|_| \_|___|____/ |_| |____/  /_/   \_\_|  |___|

 unistd.h - standard symbolic constants and types

 functions: write(), read(), close(), fork(), syscall().

*/

typedef ssize_t (*orig_write_type)(int __fd, const void *__buf, size_t __n);
orig_write_type orig_write;

ssize_t write(int __fd, const void *__buf, size_t __n) {
        if (!orig_write)
                orig_write = (orig_write_type)dlsym(RTLD_NEXT, "write");

        int ret = orig_write(__fd, __buf, __n);
        int err = errno;
        if (is_tcp_socket(__fd)) tcp_ev_write(__fd, ret, err, __n);

        errno = err;
        return ret;
}

typedef ssize_t (*orig_read_type)(int __fd, void *__buf, size_t __nbytes);
orig_read_type orig_read;

ssize_t read(int __fd, void *__buf, size_t __nbytes) {
        if (!orig_read) orig_read = (orig_read_type)dlsym(RTLD_NEXT, "read");

        int ret = orig_read(__fd, __buf, __nbytes);
        int err = errno;
        if (is_tcp_socket(__fd)) tcp_ev_read(__fd, ret, err, __nbytes);

        errno = err;
        return ret;
}

typedef int (*orig_close_type)(int __fd);
orig_close_type orig_close;

int close(int __fd) {
        if (!orig_close)
                orig_close = (orig_close_type)dlsym(RTLD_NEXT, "close");

        bool is_tcp = is_tcp_socket(__fd);
        int ret = orig_close(__fd);
        int err = errno;
        if (is_tcp) tcp_ev_close(__fd, ret, err, true);

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

/*
  _   _ ___ ___       _    ____ ___
 | | | |_ _/ _ \     / \  |  _ \_ _|
 | | | || | | | |   / _ \ | |_) | |
 | |_| || | |_| |  / ___ \|  __/| |
  \___/|___\___/  /_/   \_\_|  |___|

 sys/uio.h - definitions for vector I/O operations

 functions: writev(), readv()

*/

typedef ssize_t (*orig_writev_type)(int __fd, const struct iovec *__iovec,
                                    int __count);
orig_writev_type orig_writev;

ssize_t writev(int __fd, const struct iovec *__iovec, int __count) {
        if (!orig_writev)
                orig_writev = (orig_writev_type)dlsym(RTLD_NEXT, "writev");

        int ret = orig_writev(__fd, __iovec, __count);
        int err = errno;
        if (is_tcp_socket(__fd))
                tcp_ev_writev(__fd, ret, err, __iovec, __count);

        errno = err;
        return ret;
}

typedef ssize_t (*orig_readv_type)(int __fd, const struct iovec *__iovec,
                                   int __count);
orig_readv_type orig_readv;

ssize_t readv(int __fd, const struct iovec *__iovec, int __count) {
        if (!orig_readv)
                orig_readv = (orig_readv_type)dlsym(RTLD_NEXT, "readv");

        int ret = orig_readv(__fd, __iovec, __count);
        int err = errno;
        if (is_tcp_socket(__fd)) tcp_ev_readv(__fd, ret, err, __iovec, __count);

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

typedef ssize_t (*orig_sendfile_type)(int __out_fd, int __in_fd,
                                      off_t *__offset, size_t __count);
orig_sendfile_type orig_sendfile;

ssize_t sendfile(int __out_fd, int __in_fd, off_t *__offset, size_t __count) {
        if (!orig_sendfile)
                orig_sendfile =
                    (orig_sendfile_type)dlsym(RTLD_NEXT, "sendfile");

        if (is_tcp_socket(__out_fd))
                LOG(WARN, "NOT IMPLEMENTED: sendfile() on socket %d", __out_fd);

        return orig_sendfile(__out_fd, __in_fd, __offset, __count);
}

/*
  ____   ___  _     _          _    ____ ___
 |  _ \ / _ \| |   | |        / \  |  _ \_ _|
 | |_) | | | | |   | |       / _ \ | |_) | |
 |  __/| |_| | |___| |___   / ___ \|  __/| |
 |_|    \___/|_____|_____| /_/   \_\_|  |___|

 poll.h - definitions for the poll() function

 functions: poll()
*/

typedef int (*orig_poll_type)(struct pollfd *__fds, nfds_t __nfds,
                              int __timeout);
orig_poll_type orig_poll;

int poll(struct pollfd *__fds, nfds_t __nfds, int __timeout) {
        if (!orig_poll) orig_poll = (orig_poll_type)dlsym(RTLD_NEXT, "poll");

        unsigned long ndfs = __nfds;
        int i;
        for (i = 0; (unsigned long)i < ndfs; i++) {
                struct pollfd *pollfd = __fds + i;
                if (is_tcp_socket(pollfd->fd)) {
                        short events = pollfd->events;
                        char flags[100] = "events:";
                        if (events & POLLIN) strcat(flags, " POLLIN");
                        if (events & POLLPRI) strcat(flags, " POLLPRI");
                        if (events & POLLOUT) strcat(flags, " POLLOUT");
                        if (events & POLLRDHUP) strcat(flags, " POLLRDHUP");
                        if (events & POLLERR) strcat(flags, " POLLERR");
                        if (events & POLLHUP) strcat(flags, " POLLHUP");
                        if (events & POLLNVAL) strcat(flags, " POLLNVAL");
                        LOG(INFO, "poll() on socket %d (%s)", pollfd->fd,
                            flags);
                }
        }
        return orig_poll(__fds, __nfds, __timeout);
}
