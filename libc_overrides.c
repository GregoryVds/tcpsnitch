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
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "init.h"
#include "logger.h"
#include "sock_events.h"
#include "string_builders.h"

#define EXPORT __attribute__((visibility("default")))
#define LIBC_VERSION (__GLIBC__ * 100 + __GLIBC_MINOR__)

#define arg2 a
#define arg3 arg2, b
#define arg4 arg3, c
#define arg5 arg4, d
#define arg6 arg5, e

#define override(FUNCTION, RETURN_TYPE, ARGS_COUNT, ...)                   \
        typedef RETURN_TYPE (*FUNCTION##_type)(int fd, __VA_ARGS__);       \
        FUNCTION##_type orig_##FUNCTION;                                   \
                                                                           \
        EXPORT RETURN_TYPE FUNCTION(int fd, __VA_ARGS__) {                 \
                if (!orig_##FUNCTION)                                      \
                        orig_##FUNCTION =                                  \
                            (FUNCTION##_type)dlsym(RTLD_NEXT, #FUNCTION);  \
                RETURN_TYPE ret = orig_##FUNCTION(fd, arg##ARGS_COUNT);    \
                int err = errno;                                           \
                if (is_inet_socket(fd))                                    \
                        sock_ev_##FUNCTION(fd, ret, err, arg##ARGS_COUNT); \
                errno = err;                                               \
                return ret;                                                \
        }

#define override_1arg(FUNCTION, RETURN_TYPE)                              \
        typedef RETURN_TYPE (*FUNCTION##_type)(int fd);                   \
        FUNCTION##_type orig_##FUNCTION;                                  \
                                                                          \
        EXPORT RETURN_TYPE FUNCTION(int fd) {                             \
                if (!orig_##FUNCTION)                                     \
                        orig_##FUNCTION =                                 \
                            (FUNCTION##_type)dlsym(RTLD_NEXT, #FUNCTION); \
                RETURN_TYPE ret = orig_##FUNCTION(fd);                    \
                int err = errno;                                          \
                if (is_inet_socket(fd)) sock_ev_##FUNCTION(fd, ret, err); \
                errno = err;                                              \
                return ret;                                               \
        }

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
 accept4(), setsockopt(), send(), recv(), sendto(), recvfrom(), sendmsg(),
 recvmsg(), sendmmsg(), recvmmsg(), getsockname(), getpeername(), sockatmark(),
 isfdtype().

*/

typedef int (*socket_type)(int domain, int type, int protocol);
socket_type orig_socket;

EXPORT int socket(int domain, int type, int protocol) {
        if (!orig_socket) orig_socket = (socket_type)dlsym(RTLD_NEXT, "socket");
        int fd = orig_socket(domain, type, protocol);
        if (is_inet_socket(fd)) sock_ev_socket(fd, domain, type, protocol);
        return fd;
}

typedef int (*connect_type)(int fd, const struct sockaddr *addr, socklen_t len);
connect_type orig_connect;

EXPORT int connect(int fd, const struct sockaddr *addr, socklen_t len) {
        if (!orig_connect)
                orig_connect = (connect_type)dlsym(RTLD_NEXT, "connect");

        if (is_inet_socket(fd) && conf_opt_c) sock_start_capture(fd, addr);
        int ret = orig_connect(fd, addr, len);
        int err = errno;
        if (is_inet_socket(fd)) sock_ev_connect(fd, ret, err, addr, len);

        errno = err;
        return ret;
}

override(bind, int, 3, const struct sockaddr *a, socklen_t b);
override(shutdown, int, 2, int a) override(listen, int, 2, int a);
override(accept, int, 3, struct sockaddr *a, socklen_t *b);
override(accept4, int, 4, struct sockaddr *a, socklen_t *b, int c);
override(getsockopt, int, 5, int a, int b, void *c, socklen_t *d);
override(setsockopt, int, 5, int a, int b, const void *c, socklen_t d);

#if defined(__ANDROID__) && __ANDROID_API__ <= 19
override(send, ssize_t, 4, const void *a, size_t b, unsigned int c);
override(recv, ssize_t, 4, void *a, size_t b, unsigned int c);
#else
override(send, ssize_t, 4, const void *a, size_t b, int c);
override(recv, ssize_t, 4, void *a, size_t b, int c);
#endif

override(sendto, ssize_t, 6, const void *a, size_t b, int c,
         const struct sockaddr *d, socklen_t e);
#if defined(__ANDROID__) && __ANDROID_API__ <= 19
override(recvfrom, ssize_t, 6, void *a, size_t b, unsigned int c,
         const struct sockaddr *d, socklen_t *e);
#elif defined(__ANDROID__)
override(recvfrom, ssize_t, 6, void *a, size_t b, int c,
         const struct sockaddr *d, socklen_t *e);
#else
override(recvfrom, ssize_t, 6, void *a, size_t b, int c, struct sockaddr *d,
         socklen_t *e);
#endif

#if defined(__ANDROID__) && __ANDROID_API__ <= 19
override(sendmsg, ssize_t, 3, const struct msghdr *a, unsigned int b);
override(recvmsg, ssize_t, 3, struct msghdr *a, unsigned int b);
#else
override(sendmsg, ssize_t, 3, const struct msghdr *a, int b);
override(recvmsg, ssize_t, 3, struct msghdr *a, int b);
#endif

#if defined(__ANDROID__) && __ANDROID_API__ >= 21
override(sendmmsg, int, 4, const struct mmsghdr *a, unsigned int b, int c);
override(recvmmsg, int, 5, struct mmsghdr *a, unsigned int b, int c,
         const struct timespec *d);
#elif LIBC_VERSION > 219  // Absolutely not sure this is the right boundary!
override(sendmmsg, int, 4, struct mmsghdr *a, unsigned int b, int c);
override(recvmmsg, int, 5, struct mmsghdr *a, unsigned int b, int c,
         struct timespec *d);
#else
override(sendmmsg, int, 4, struct mmsghdr *a, unsigned int b, int c);
override(recvmmsg, int, 5, struct mmsghdr *a, unsigned int b, int c,
         const struct timespec *d);
#endif

override(getsockname, int, 3, struct sockaddr *a, socklen_t *b);
override(getpeername, int, 3, struct sockaddr *a, socklen_t *b);
override_1arg(sockatmark, int);
override(isfdtype, int, 2, int a);

/*
  _   _ _   _ ___ ____ _____ ____       _    ____ ___
 | | | | \ | |_ _/ ___|_   _|  _ \     / \  |  _ \_ _|
 | | | |  \| || |\___ \ | | | | | |   / _ \ | |_) | |
 | |_| | |\  || | ___) || | | |_| |  / ___ \|  __/| |
  \___/|_| \_|___|____/ |_| |____/  /_/   \_\_|  |___|

 unistd.h - standard symbolic constants and types

 functions: write(), read(), close(), fork(), dup(), dup2(), dup3()

*/

override(write, ssize_t, 3, const void *a, size_t b);
override(read, ssize_t, 3, void *a, size_t b);

typedef int (*close_type)(int fd);
close_type orig_close;

EXPORT int close(int fd) {
        if (!orig_close) orig_close = (close_type)dlsym(RTLD_NEXT, "close");

        bool is_inet = is_inet_socket(fd);
        int ret = orig_close(fd);
        int err = errno;
        if (is_inet) sock_ev_close(fd, ret, err);

        errno = err;
        return ret;
}

override_1arg(dup, int);
override(dup2, int, 2, int a);
override(dup3, int, 3, int a, int b);

typedef pid_t (*fork_type)(void);
fork_type orig_fork;

EXPORT pid_t fork(void) {
        if (!orig_fork) orig_fork = (fork_type)dlsym(RTLD_NEXT, "fork");
        LOG(INFO, "fork() called.");

        pid_t ret = orig_fork();
        int err = errno;
        if (ret == 0) reset_tcpsnitch();  // Child

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

override(writev, ssize_t, 3, const struct iovec *a, int b);
override(readv, ssize_t, 3, const struct iovec *a, int b);

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
typedef int (*ioctl_type)(int fd, int request, ...);
#else
typedef int (*ioctl_type)(int fd, unsigned long int request, ...);
#endif

ioctl_type orig_ioctl;

#ifdef __ANDROID__
EXPORT int ioctl(int fd, int request, ...) {
#else
EXPORT int ioctl(int fd, unsigned long int request, ...) {
#endif
        va_list argp;
        va_start(argp, request);
        void *value = va_arg(argp, void *);
        va_end(argp);

        if (!orig_ioctl) orig_ioctl = (ioctl_type)dlsym(RTLD_NEXT, "ioctl");

        int ret = orig_ioctl(fd, request, value);
        int err = errno;
        if (is_inet_socket(fd)) sock_ev_ioctl(fd, ret, err, request);

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

override(sendfile, ssize_t, 4, int a, off_t *b, size_t c);

/*
  ____   ___  _     _          _    ____ ___
 |  _ \ / _ \| |   | |        / \  |  _ \_ _|
 | |_) | | | | |   | |       / _ \ | |_) | |
 |  __/| |_| | |___| |___   / ___ \|  __/| |
 |_|    \___/|_____|_____| /_/   \_\_|  |___|

 poll.h - definitions for the poll() function

 functions: poll(), ppoll()
*/

typedef int (*poll_type)(struct pollfd *fds, nfds_t nfds, int timeout);
poll_type orig_poll;

EXPORT int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
        if (!orig_poll) orig_poll = (poll_type)dlsym(RTLD_NEXT, "poll");

        int ret = orig_poll(fds, nfds, timeout);
        int err = errno;
        unsigned long i;
        for (i = 0; i < nfds; i++) {
                struct pollfd pollfd = fds[i];
                if (is_inet_socket(pollfd.fd))
                        sock_ev_poll(pollfd.fd, ret, err, pollfd.events,
                                     pollfd.revents, timeout);
        }

        errno = err;
        return ret;
}

typedef int (*ppoll_type)(struct pollfd *fds, nfds_t nfds,
                          const struct timespec *tmo_p,
                          const sigset_t *sigmask);
ppoll_type orig_ppoll;

EXPORT int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p,
          const sigset_t *sigmask) {
        if (!orig_ppoll) orig_ppoll = (ppoll_type)dlsym(RTLD_NEXT, "ppoll");

        int ret = orig_ppoll(fds, nfds, tmo_p, sigmask);
        int err = errno;
        unsigned long i;
        for (i = 0; i < nfds; i++) {
                struct pollfd pollfd = fds[i];
                if (is_inet_socket(pollfd.fd))
                        sock_ev_ppoll(pollfd.fd, ret, err, pollfd.events,
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

typedef int (*select_type)(int nfds, fd_set *readfds, fd_set *writefds,
                           fd_set *exceptfds, struct timeval *timeout);
select_type orig_select;

#define READ_FLAG 0b1
#define WRITE_FLAG 0b10
#define EXCEPT_FLAG 0b100

EXPORT int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
           struct timeval *timeout) {
        if (!orig_select) orig_select = (select_type)dlsym(RTLD_NEXT, "select");

        short req_ev[nfds];
        memset(req_ev, 0, sizeof(req_ev));

        int fd;
        for (fd = 0; fd < nfds; fd++) {
                if (is_inet_socket(fd)) {
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
                if (is_inet_socket(fd) &&
                    req_ev[fd]) {  // Socket was in initial call
                        sock_ev_select(fd, ret, err, (req_ev[fd] & READ_FLAG),
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

typedef int (*pselect_type)(int nfds, fd_set *readfds, fd_set *writefds,
                            fd_set *exceptfds, const struct timespec *timeout,
                            const sigset_t *sigmask);
pselect_type orig_pselect;

EXPORT int pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
            const struct timespec *timeout, const sigset_t *sigmask) {
        if (!orig_pselect)
                orig_pselect = (pselect_type)dlsym(RTLD_NEXT, "pselect");

        short req_ev[nfds];
        memset(req_ev, 0, sizeof(req_ev));

        int fd;
        for (fd = 0; fd < nfds; fd++) {
                if (is_inet_socket(fd)) {
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
                if (is_inet_socket(fd) && req_ev[fd]) {
                        sock_ev_pselect(fd, ret, err, (req_ev[fd] & READ_FLAG),
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

/*
  _____ ____ _   _ _____ _          _    ____ ___
 |  ___/ ___| \ | |_   _| |        / \  |  _ \_ _|
 | |_ | |   |  \| | | | | |       / _ \ | |_) | |
 |  _|| |___| |\  | | | | |___   / ___ \|  __/| |
 |_|   \____|_| \_| |_| |_____| /_/   \_\_|  |___|

 fcntl.h

 functions: fcntl()
*/

typedef int (*fcntl_type)(int fd, int cmd, ...);
fcntl_type orig_fcntl;

EXPORT int fcntl(int fd, int cmd, ...) {
        if (!orig_fcntl) orig_fcntl = (fcntl_type)dlsym(RTLD_NEXT, "fcntl");

        va_list argp;
        void *arg;
        va_start(argp, cmd);
        arg = va_arg(argp, void *);
        va_end(argp);

        int ret = orig_fcntl(fd, cmd, arg);
        int err = errno;
        if (is_inet_socket(fd)) sock_ev_fcntl(fd, ret, err, cmd, arg);

        errno = err;
        return ret;
}

/*
  _____ ____   ___  _     _          _    ____ ___
 | ____|  _ \ / _ \| |   | |        / \  |  _ \_ _|
 |  _| | |_) | | | | |   | |       / _ \ | |_) | |
 | |___|  __/| |_| | |___| |___   / ___ \|  __/| |
 |_____|_|    \___/|_____|_____| /_/   \_\_|  |___|

  sys/epoll.h

  functions: epoll_ctl(), epoll_wait(), epoll_pwait().
*/

typedef int (*epoll_ctl_type)(int epfd, int op, int fd,
                              struct epoll_event *event);

epoll_ctl_type orig_epoll_ctl;

EXPORT int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
        if (!orig_epoll_ctl)
                orig_epoll_ctl = (epoll_ctl_type)dlsym(RTLD_NEXT, "epoll_ctl");

        int ret = orig_epoll_ctl(epfd, op, fd, event);
        int err = errno;
        if (is_inet_socket(fd))
                sock_ev_epoll_ctl(fd, ret, err, op, event->events);

        errno = err;
        return ret;
}

typedef int (*epoll_wait_type)(int epfd, struct epoll_event *events,
                               int maxevents, int timeout);

epoll_wait_type orig_epoll_wait;

EXPORT int epoll_wait(int epfd, struct epoll_event *events, int maxevents,
               int timeout) {
        if (!orig_epoll_wait)
                orig_epoll_wait =
                    (epoll_wait_type)dlsym(RTLD_NEXT, "epoll_wait");

        int ret = orig_epoll_wait(epfd, events, maxevents, timeout);
        int err = errno;
        for (int i = 0; i < ret; i++) {
                int fd = events[i].data.fd;
                if (is_inet_socket(fd)) {
                        uint32_t returned_events = events[i].events;
                        sock_ev_epoll_wait(fd, ret, err, timeout,
                                           returned_events);
                }
        }

        errno = err;
        return ret;
}

typedef int (*epoll_pwait_type)(int epfd, struct epoll_event *events,
                                int maxevents, int timeout,
                                const sigset_t *sigmask);

epoll_pwait_type orig_epoll_pwait;

EXPORT int epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
                int timeout, const sigset_t *sigmask) {
        if (!orig_epoll_pwait)
                orig_epoll_pwait =
                    (epoll_pwait_type)dlsym(RTLD_NEXT, "epoll_pwait");

        int ret = orig_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
        int err = errno;
        for (int i = 0; i < ret; i++) {
                int fd = events[i].data.fd;
                if (is_inet_socket(fd)) {
                        uint32_t returned_events = events[i].events;
                        sock_ev_epoll_pwait(fd, ret, err, timeout,
                                            returned_events);
                }
        }

        errno = err;
        return ret;
}

/*
  ____ _____ ____ ___ ___       _    ____ ___
 / ___|_   _|  _ \_ _/ _ \     / \  |  _ \_ _|
 \___ \ | | | | | | | | | |   / _ \ | |_) | |
  ___) || | | |_| | | |_| |  / ___ \|  __/| |
 |____/ |_| |____/___\___/  /_/   \_\_|  |___|

 stdio.h

 functions: fdopen()
*/

override(fdopen, FILE *, 2, const char *a);
