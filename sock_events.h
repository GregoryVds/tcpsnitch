#ifndef SOCK_EVENTS_H
#define SOCK_EVENTS_H

#include <netinet/tcp.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>

typedef enum SockEventType {
        SOCK_EV_SOCKET,
        SOCK_EV_FORKED_SOCKET,
        SOCK_EV_GHOST_SOCKET,
        SOCK_EV_BIND,
        SOCK_EV_CONNECT,
        SOCK_EV_SHUTDOWN,
        SOCK_EV_LISTEN,
        SOCK_EV_ACCEPT,
        SOCK_EV_ACCEPT4,
        SOCK_EV_GETSOCKOPT,
        SOCK_EV_SETSOCKOPT,
        SOCK_EV_SEND,
        SOCK_EV_RECV,
        SOCK_EV_SENDTO,
        SOCK_EV_RECVFROM,
        SOCK_EV_SENDMSG,
        SOCK_EV_RECVMSG,
#if !defined(__ANDROID__) || __ANDROID_API__ >= 21
        SOCK_EV_SENDMMSG,
        SOCK_EV_RECVMMSG,
#endif
        SOCK_EV_GETSOCKNAME,
        SOCK_EV_GETPEERNAME,
        SOCK_EV_SOCKATMARK,
        SOCK_EV_ISFDTYPE,
        // unistd.h
        SOCK_EV_WRITE,
        SOCK_EV_READ,
        SOCK_EV_CLOSE,
        SOCK_EV_DUP,
        SOCK_EV_DUP2,
        SOCK_EV_DUP3,
        // sys/uio.h
        SOCK_EV_WRITEV,
        SOCK_EV_READV,
        // sys/ioctl.h
        SOCK_EV_IOCTL,
        // sendfile.h
        SOCK_EV_SENDFILE,
        // poll.h
        SOCK_EV_POLL,
        SOCK_EV_PPOLL,
        // sys/select.h
        SOCK_EV_SELECT,
        SOCK_EV_PSELECT,
        // fcntl.h
        SOCK_EV_FCNTL,
        // epoll.h
        SOCK_EV_EPOLL_CTL,
        SOCK_EV_EPOLL_WAIT,
        SOCK_EV_EPOLL_PWAIT,
        // stdio.h
        SOCK_EV_FDOPEN,
        // others
        SOCK_EV_TCP_INFO
} SockEventType;

typedef struct {
        SockEventType type;
        struct timeval timestamp;
        int return_value;
        bool success;
        char *error_str;
        long id;
        pid_t thread_id;
} SockEvent;

typedef struct {
        int domain;
        int type;
        int protocol;
        bool sock_cloexec;
        bool sock_nonblock;
        bool filled;
} SockInfo;

typedef struct {
        SockEvent super;
        SockInfo sock_info;
} SockEvSocket;

typedef struct {
        SockEvent super;
        SockInfo sock_info;
} SockEvForkedSocket;

/* A ghost socket represents a socket for which we never saw its creation.
 * Maybe it was passed from another process using sendmsg, maybe it was created
 * using a direct syscall. To verify if we don't forget any source of new
 * socket. */
typedef struct {
        SockEvent super;
        SockInfo sock_info;
} SockEvGhostSocket;

typedef struct {
        struct sockaddr_storage sockaddr_sto;
        socklen_t len;
} Addr;

typedef struct {
        SockEvent super;
        Addr addr;
} SockEvBind;

typedef struct {
        SockEvent super;
        Addr addr;
} SockEvConnect;

typedef struct {
        SockEvent super;
        bool shut_rd;
        bool shut_wr;
} SockEvShutdown;

typedef struct {
        SockEvent super;
        int backlog;
} SockEvListen;

typedef struct {
        SockEvent super;
        SockInfo sock_info;
        Addr addr;
} SockEvAccept;

typedef struct {
        SockEvent super;
        SockInfo sock_info;
        Addr addr;
        int flags;
} SockEvAccept4;

typedef struct {
        int level;
        int optname;
        void *optval;
        socklen_t optlen;
} Sockopt;

typedef struct {
        SockEvent super;
        Sockopt sockopt;
} SockEvGetsockopt;

typedef struct {
        SockEvent super;
        Sockopt sockopt;
} SockEvSetsockopt;

typedef struct {
        SockEvent super;
        size_t bytes;
        int flags;
} SockEvSend;

typedef struct {
        SockEvent super;
        size_t bytes;
        int flags;
} SockEvRecv;

typedef struct {
        SockEvent super;
        size_t bytes;
        int flags;
        Addr addr;
} SockEvSendto;

typedef struct {
        SockEvent super;
        size_t bytes;
        int flags;
        Addr addr;
} SockEvRecvfrom;

typedef struct {
        int iovec_count;
        size_t *iovec_sizes;
} Iovec;

typedef struct {
        Iovec iovec;
        struct sockaddr_storage addr;
        int flags;
        struct msghdr *msghdr;
} Msghdr;

typedef struct {
        SockEvent super;
        size_t bytes;
        int flags;
        Msghdr msghdr;
} SockEvSendmsg;

typedef struct {
        SockEvent super;
        size_t bytes;
        int flags;
        Msghdr msghdr;
} SockEvRecvmsg;

typedef struct {
        time_t seconds;
        long nanoseconds;
} Timeout;

#if !defined(__ANDROID__) || __ANDROID_API__ >= 21
typedef struct {
        Msghdr msghdr;
        unsigned int bytes_transmitted;
} Mmsghdr;

typedef struct {
        SockEvent super;
        size_t bytes;
        int flags;
        int mmsghdr_count;
        Mmsghdr *mmsghdr_vec;
} SockEvSendmmsg;

typedef struct {
        SockEvent super;
        size_t bytes;
        int flags;
        Timeout timeout;
        int mmsghdr_count;
        Mmsghdr *mmsghdr_vec;
} SockEvRecvmmsg;
#endif

typedef struct {
        SockEvent super;
        Addr addr;
} SockEvGetsockname;

typedef struct {
        SockEvent super;
        Addr addr;
} SockEvGetpeername;

typedef struct { SockEvent super; } SockEvSockatmark;

typedef struct {
        SockEvent super;
        int fdtype;
} SockEvIsfdtype;

typedef struct {
        SockEvent super;
        size_t bytes;
} SockEvWrite;

typedef struct {
        SockEvent super;
        size_t bytes;
} SockEvRead;

typedef struct { SockEvent super; } SockEvClose;

typedef struct {
        SockEvent super;
        SockInfo sock_info;
} SockEvDup;

typedef struct {
        SockEvent super;
        SockInfo sock_info;
        int newfd;
} SockEvDup2;

typedef struct {
        SockEvent super;
        SockInfo sock_info;
        int newfd;
        bool o_cloexec;
} SockEvDup3;

typedef struct {
        SockEvent super;
        size_t bytes;
        Iovec iovec;
} SockEvWritev;

typedef struct {
        SockEvent super;
        size_t bytes;
        Iovec iovec;
} SockEvReadv;

typedef struct {
        SockEvent super;
#ifdef __ANDROID__
        int request;
#else
        unsigned long int request;
#endif
} SockEvIoctl;

typedef struct {
        SockEvent super;
        size_t bytes;
} SockEvSendfile;

typedef struct {
        bool pollin;
        bool pollpri;
        bool pollout;
        bool pollrdhup;
        bool pollerr;
        bool pollhup;
        bool pollnval;
} PollEvents;

typedef struct {
        SockEvent super;
        Timeout timeout;
        PollEvents requested_events;
        PollEvents returned_events;
} SockEvPoll;

typedef struct {
        SockEvent super;
        Timeout timeout;
        PollEvents requested_events;
        PollEvents returned_events;
} SockEvPpoll;

typedef struct {
        bool read;
        bool write;
        bool except;
} SelectEvents;

typedef struct {
        SockEvent super;
        Timeout timeout;
        SelectEvents requested_events;
        SelectEvents returned_events;
} SockEvSelect;

typedef struct {
        SockEvent super;
        Timeout timeout;
        SelectEvents requested_events;
        SelectEvents returned_events;
} SockEvPselect;

typedef struct {
        SockEvent super;
        SockInfo sock_info;
        int cmd;
        int arg;
} SockEvFcntl;

typedef struct {
        SockEvent super;
        int op;
        uint32_t requested_events;
} SockEvEpollCtl;

typedef struct {
        SockEvent super;
        int timeout;
        uint32_t returned_events;
} SockEvEpollWait;

typedef struct {
        SockEvent super;
        int timeout;
        uint32_t returned_events;
} SockEvEpollPwait;

typedef struct {
        SockEvent super;
        char *mode;
} SockEvFdopen;

typedef struct {
        SockEvent super;
        struct tcp_info info;
} SockEvTcpInfo;

typedef struct SockEventNode SockEventNode;
struct SockEventNode {
        SockEvent *data;
        SockEventNode *next;
};

typedef struct {
        // To be freed
        SockEventNode *head;  // Head for list of events.
        SockEventNode *tail;  // Tail for list of events.
        // Others
        int id;
        int fd;
        SockInfo sock_info;
        long events_count;
        unsigned long bytes_sent;      // Total bytes sent.
        unsigned long bytes_received;  // Total bytes received.
        long last_info_dump_micros;  // Time of last info dump in microseconds.
        long last_info_dump_bytes;   // Total bytes (sent+recv) at last dump.
        bool bound;
        struct sockaddr_storage bound_addr;
        int rtt;
        bool *capture_switch;
} Socket;

const char *string_from_sock_event_type(SockEventType type);

void free_socket(Socket *con);

// Packet capture

void sock_start_capture(int fd, const struct sockaddr *connect_addr);

// Events hooks

void sock_ev_socket(int fd, int domain, int type, int protocol);

void sock_ev_bind(int fd, int ret, int err, const struct sockaddr *addr,
                  socklen_t len);

void sock_ev_connect(int fd, int ret, int err, const struct sockaddr *addr,
                     socklen_t len);

void sock_ev_shutdown(int fd, int ret, int err, int how);

void sock_ev_listen(int fd, int ret, int err, int backlog);

void sock_ev_accept(int fd, int ret, int err, struct sockaddr *addr,
                    socklen_t *addr_len);

void sock_ev_accept4(int fd, int ret, int err, struct sockaddr *addr,
                     socklen_t *addr_len, int flags);

void sock_ev_getsockopt(int fd, int ret, int err, int level, int optname,
                        const void *optval, socklen_t *optlen);

void sock_ev_setsockopt(int fd, int ret, int err, int level, int optname,
                        const void *optval, socklen_t optlen);

void sock_ev_send(int fd, int ret, int err, const void *buf, size_t bytes,
                  int flags);

void sock_ev_recv(int fd, int ret, int err, void *buf, size_t bytes, int flags);

void sock_ev_sendto(int fd, int ret, int err, const void *buf, size_t bytes,
                    int flags, const struct sockaddr *addr, socklen_t len);

void sock_ev_recvfrom(int fd, int ret, int err, void *buf, size_t bytes,
                      int flags, const struct sockaddr *addr, socklen_t *len);

void sock_ev_sendmsg(int fd, int ret, int err, const struct msghdr *msg,
                     int flags);

void sock_ev_recvmsg(int fd, int ret, int err, const struct msghdr *msg,
                     int flags);

#if !defined(__ANDROID__) || __ANDROID_API__ >= 21
void sock_ev_sendmmsg(int fd, int ret, int err, const struct mmsghdr *vmessages,
                      unsigned int vlen, int flags);

void sock_ev_recvmmsg(int fd, int ret, int err, const struct mmsghdr *vmessages,
                      unsigned int vlen, int flags, const struct timespec *tmo);
#endif

void sock_ev_getsockname(int fd, int ret, int err, struct sockaddr *addr,
                         socklen_t *addrlen);

void sock_ev_getpeername(int fd, int ret, int err, struct sockaddr *addr,
                         socklen_t *addrlen);

void sock_ev_sockatmark(int fd, int ret, int err);

void sock_ev_isfdtype(int fd, int ret, int err, int fdtype);

void sock_ev_write(int fd, int ret, int err, const void *buf, size_t bytes);

void sock_ev_read(int fd, int ret, int err, void *buf, size_t bytes);

void sock_ev_close(int fd, int ret, int err);

void sock_ev_dup(int fd, int ret, int err);

void sock_ev_dup2(int fd, int ret, int err, int newfd);

void sock_ev_dup3(int fd, int ret, int err, int newfd, int flags);

void sock_ev_writev(int fd, int ret, int err, const struct iovec *iovec,
                    int iovec_count);

void sock_ev_readv(int fd, int ret, int err, const struct iovec *iovec,
                   int iovec_count);

#ifdef __ANDROID__
void sock_ev_ioctl(int fd, int ret, int err, int request);
#else
void sock_ev_ioctl(int fd, int ret, int err, unsigned long int request);
#endif

void sock_ev_sendfile(int fd, int ret, int err, int in_fd, off_t *offset,
                      size_t bytes);

void sock_ev_poll(int fd, int ret, int err, short requested_events,
                  short returned_event, int timeout);

void sock_ev_ppoll(int fd, int ret, int err, short requested_events,
                   short returned_event, const struct timespec *timeout);

void sock_ev_select(int fd, int ret, int err, bool req_read, bool req_write,
                    bool req_except, bool ret_read, bool ret_write,
                    bool ret_except, struct timeval *timeout);

void sock_ev_pselect(int fd, int ret, int err, bool req_read, bool req_write,
                     bool req_except, bool ret_read, bool ret_write,
                     bool ret_except, const struct timespec *timeout);

void sock_ev_fcntl(int fd, int ret, int err, int cmd, ...);

void sock_ev_epoll_ctl(int fd, int ret, int err, int op,
                       uint32_t requested_events);

void sock_ev_epoll_wait(int fd, int ret, int err, int timeout,
                        uint32_t returned_events);

void sock_ev_epoll_pwait(int fd, int ret, int err, int timeout,
                         uint32_t returned_events);

void sock_ev_fdopen(int fd, FILE *ret, int err, const char *mode);

void sock_ev_tcp_info(int fd, int ret, int err, struct tcp_info *info);

void dump_all_sock_events(void);

void sock_ev_free(void);  // Free state.
// Free state and restore to default state (called after fork()).
void sock_ev_reset(void);

#endif
