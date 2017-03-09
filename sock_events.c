#define _GNU_SOURCE

#include "sock_events.h"
#include <assert.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <poll.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "constant_strings.h"
#include "constants.h"
#include "init.h"
#include "json_builder.h"
#include "lib.h"
#include "logger.h"
#include "packet_sniffer.h"
#include "resizable_array.h"
#include "string_builders.h"
#include "verbose_mode.h"

#ifdef __ANDROID__
#define MUTEX_ERRORCHECK PTHREAD_ERRORCHECK_MUTEX_INITIALIZER
#else
#define MUTEX_ERRORCHECK PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP
#endif

static pthread_mutex_t connections_count_mutex = MUTEX_ERRORCHECK;
static int connections_count = 0;

/* Private functions */

static SocketState *alloc_connection(int fd) {
	SocketState *con;
	if (!(con = (SocketState *)my_calloc(sizeof(SocketState))))
		goto error;

	// Get & increment connections_count
	mutex_lock(&connections_count_mutex);
	con->id = connections_count;
	connections_count++;
	mutex_unlock(&connections_count_mutex);

        con->fd = fd;
	// Has to be done AFTER getting the con->id
	con->directory = create_numbered_dir_in_path(logs_dir_path, con->id);
	return con;
error:
        LOG_FUNC_ERROR;
        return NULL;
}

#define CASE_EV(ev_type_cons, ev_type, err_val)              \
        case ev_type_cons:                                   \
                ev = (SockEvent *)my_calloc(sizeof(ev_type)); \
                success = (return_value != err_val);         \
                break;

static SockEvent *alloc_event(SockEventType type, int return_value, int err,
                             int id) {
        bool success;
        SockEvent *ev;
        switch (type) {
                CASE_EV(SOCK_EV_SOCKET, SockEvSocket, 0);
                CASE_EV(SOCK_EV_BIND, SockEvBind, -1);
                CASE_EV(SOCK_EV_CONNECT, SockEvConnect, -1);
                CASE_EV(SOCK_EV_SHUTDOWN, SockEvShutdown, -1);
                CASE_EV(SOCK_EV_LISTEN, SockEvListen, -1);
                CASE_EV(SOCK_EV_ACCEPT, SockEvAccept, -1);
                CASE_EV(SOCK_EV_ACCEPT4, SockEvAccept4, -1);
                CASE_EV(SOCK_EV_GETSOCKOPT, SockEvGetsockopt, -1);
                CASE_EV(SOCK_EV_SETSOCKOPT, SockEvSetsockopt, -1);
                CASE_EV(SOCK_EV_SEND, SockEvSend, -1);
                CASE_EV(SOCK_EV_RECV, SockEvRecv, -1);
                CASE_EV(SOCK_EV_SENDTO, SockEvSendto, -1);
                CASE_EV(SOCK_EV_RECVFROM, SockEvRecvfrom, -1);
                CASE_EV(SOCK_EV_SENDMSG, SockEvSendmsg, -1);
                CASE_EV(SOCK_EV_RECVMSG, SockEvRecvmsg, -1);
#if !defined(__ANDROID__) || __ANDROID_API__ >= 21
                CASE_EV(SOCK_EV_SENDMMSG, SockEvSendmmsg, -1);
                CASE_EV(SOCK_EV_RECVMMSG, SockEvRecvmmsg, -1);
#endif
                CASE_EV(SOCK_EV_GETSOCKNAME, SockEvGetsockname, -1);
                CASE_EV(SOCK_EV_GETPEERNAME, SockEvGetpeername, -1);
                CASE_EV(SOCK_EV_SOCKATMARK, SockEvSockatmark, -1);
                CASE_EV(SOCK_EV_ISFDTYPE, SockEvIsfdtype, -1);
                CASE_EV(SOCK_EV_WRITE, SockEvWrite, -1);
                CASE_EV(SOCK_EV_READ, SockEvRead, -1);
                CASE_EV(SOCK_EV_CLOSE, SockEvClose, -1);
                CASE_EV(SOCK_EV_DUP, SockEvDup, -1);
                CASE_EV(SOCK_EV_DUP2, SockEvDup2, -1);
                CASE_EV(SOCK_EV_DUP3, SockEvDup3, -1);
                CASE_EV(SOCK_EV_WRITEV, SockEvWritev, -1);
                CASE_EV(SOCK_EV_READV, SockEvReadv, -1);
                CASE_EV(SOCK_EV_IOCTL, SockEvIoctl, -1);
                CASE_EV(SOCK_EV_SENDFILE, SockEvSendfile, -1);
                CASE_EV(SOCK_EV_POLL, SockEvPoll, -1);
                CASE_EV(SOCK_EV_PPOLL, SockEvPpoll, -1);
                CASE_EV(SOCK_EV_SELECT, SockEvSelect, -1);
                CASE_EV(SOCK_EV_PSELECT, SockEvPselect, -1);
                CASE_EV(SOCK_EV_FCNTL, SockEvFcntl, -1);
                CASE_EV(SOCK_EV_EPOLL_CTL, SockEvEpollCtl, -1);
                CASE_EV(SOCK_EV_EPOLL_WAIT, SockEvEpollWait, -1);
                CASE_EV(SOCK_EV_EPOLL_PWAIT, SockEvEpollPwait, -1);
                CASE_EV(SOCK_EV_FDOPEN, SockEvFdopen, 0);
                CASE_EV(SOCK_EV_TCP_INFO, SockEvTcpInfo, -1);
        }
        if (!ev) goto error;
        fill_timeval(&(ev->timestamp));
        ev->type = type;
        ev->return_value = return_value;
        ev->success = success;
        ev->error_str = success ? NULL : alloc_error_str(err);
        ev->id = id;
        ev->thread_id = syscall(SYS_gettid);
        return ev;
error:
        LOG_FUNC_ERROR;
        return NULL;
}

static void free_event(SockEvent *ev) {
        free(ev->error_str);
        switch (ev->type) {
                case SOCK_EV_GETSOCKOPT:
                        free(((SockEvGetsockopt *)ev)->sockopt.optval);
                        break;
                case SOCK_EV_SETSOCKOPT:
                        free(((SockEvSetsockopt *)ev)->sockopt.optval);
                        break;
                case SOCK_EV_READV:
                        free(((SockEvReadv *)ev)->iovec.iovec_sizes);
                        break;
                case SOCK_EV_WRITEV:
                        free(((SockEvWritev *)ev)->iovec.iovec_sizes);
                        break;
#if !defined(__ANDROID__) || __ANDROID_API__ >= 21
                case SOCK_EV_SENDMMSG:
                        free(((SockEvSendmmsg *)ev)->mmsghdr_vec);
                        break;
                case SOCK_EV_RECVMSG:
                        free(((SockEvRecvmmsg *)ev)->mmsghdr_vec);
                        break;
#endif
                case SOCK_EV_FDOPEN:
                        free(((SockEvFdopen *)ev)->mode);
                        break;
                default:
                        break;
        }
        free(ev);
}

static void free_events_list(SockEventNode *head) {
        SockEventNode *tmp;
        while (head != NULL) {
                free_event(head->data);
                tmp = head;
                head = head->next;
                free(tmp);
        }
}

static void push_event(SocketState *con, SockEvent *ev) {
        SockEventNode *node = (SockEventNode *)my_malloc(sizeof(SockEventNode));
        node->data = ev;
        node->next = NULL;

        if (!con->head)
                con->head = node;
        else
                con->tail->next = node;
        con->tail = node;
        con->events_count++;
        return;
}

static void fill_addr(Addr *a, const struct sockaddr *addr, socklen_t len) {
        memcpy(&a->sockaddr_sto, addr, len);
        a->len = len;
}

static void fill_poll_events(PollEvents *pe, int events) {
        pe->pollin = (events & POLLIN);
        pe->pollpri = (events & POLLPRI);
        pe->pollout = (events & POLLOUT);
        pe->pollrdhup = (events & POLLRDHUP);
        pe->pollerr = (events & POLLERR);
        pe->pollhup = (events & POLLHUP);
        pe->pollnval = (events & POLLNVAL);
}

static socklen_t fill_iovec(Iovec *iov1, const struct iovec *iov2,
                            int iovec_count) {
        iov1->iovec_count = iovec_count;
        if (iovec_count <= 0) return 0;

        iov1->iovec_sizes = (size_t *)my_malloc(sizeof(size_t *) * iovec_count);
        socklen_t bytes = 0;
        for (int i = 0; i < iovec_count; i++) {
                if (iov1->iovec_sizes) iov1->iovec_sizes[i] = iov2[i].iov_len;
                bytes += iov2[i].iov_len;
        }
        return bytes;
}

static socklen_t fill_tcp_msghdr(Msghdr *m1, const struct msghdr *m2) {
        // We copy the msg_control fields of the "struct msghdr" to another
        // such struct, since we must have such a struct available later to
        // use the CMSG macros for extracting the ancillary data.

        // Msg name
        if (m2->msg_name) memcpy(&m1->addr, m2->msg_name, m2->msg_namelen);

        // Control data (ancillary data)
        m1->msghdr = my_calloc(sizeof(struct msghdr));
        m1->msghdr->msg_controllen = m2->msg_controllen;
        if (m2->msg_controllen)
                m1->msghdr->msg_control = my_malloc(m2->msg_controllen);
        memcpy(m1->msghdr->msg_control, m2->msg_control, m2->msg_controllen);
        
        // Flags
        m1->flags = m2->msg_flags;

        // Iovec
        return fill_iovec(&m1->iovec, m2->msg_iov, m2->msg_iovlen);
}

static unsigned int fill_tcp_mmsghdr_vec(Mmsghdr *tcp_mmsghdr_vec,
                                         const struct mmsghdr *mmsghdr_vec,
                                         unsigned int vlen) {
        unsigned int bytes = 0;
        for (unsigned int i = 0; i < vlen; i++) {
                const struct mmsghdr *mmsghdr = (mmsghdr_vec + i);
                Mmsghdr *tcp_mmsghdr = (tcp_mmsghdr_vec + i);
                tcp_mmsghdr->bytes_transmitted = mmsghdr->msg_len;
                bytes += fill_tcp_msghdr(&tcp_mmsghdr->tcp_msghdr,
                                         &mmsghdr->msg_hdr);
        }
        return bytes;
}

static void fill_sockopt(Sockopt *sockopt, int level, int optname,
                         const void *optval, socklen_t optlen) {
        sockopt->level = level;
        sockopt->optname = optname;
        sockopt->optlen = optlen;
        sockopt->optval = my_malloc(optlen);
        memcpy(sockopt->optval, optval, optlen);
        return;
}

typedef int (*orig_bind_type)(int fd, const struct sockaddr *addr,
                              socklen_t len);
orig_bind_type orig_bind;

#define MIN_PORT 32768  // cat /proc/sys/net/ipv4/ip_local_port_range
#define MAX_PORT 60999
static int force_bind(int fd, SocketState *con, bool IPV6) {
        LOG(INFO, "Forcing bind on connection %d.", con->id);
        LOG_FUNC_INFO;
        if (!orig_bind) orig_bind = (orig_bind_type)dlsym(RTLD_NEXT, "bind");

        for (int port = MIN_PORT; port <= MAX_PORT; port++) {
                int rc;
                if (IPV6) {
                        struct sockaddr_in6 a;
                        a.sin6_family = AF_INET6;
                        a.sin6_port = htons(port);  // Any port
                        a.sin6_addr = in6addr_any;
                        rc = orig_bind(fd, (struct sockaddr *)&a, sizeof(a));
                } else {
                        struct sockaddr_in a;
                        a.sin_family = AF_INET;
                        a.sin_port = htons(port);
                        a.sin_addr.s_addr = INADDR_ANY;
                        rc = orig_bind(fd, (struct sockaddr *)&a, sizeof(a));
                }
                if (rc == 0) return 0;                 // Sucessfull bind. Stop.
                if (errno != EADDRINUSE) goto error1;  // Unexpected error.
                // Expected error EADDRINUSE. Try next port.
        }
        // Could not bind if we reach this point.
        goto error_out;
error1:
        LOG(ERROR, "bind() failed. %s.", strerror(errno));
        goto error_out;
error_out:
        LOG_FUNC_ERROR;
        LOG(INFO, "Packet capture filter on dest IP/PORT only.");
        return -1;
}

static void tcp_dump_json(SocketState *con) {
        if (con->directory == NULL) goto error1;
        LOG_FUNC_INFO;
        char *json_str, *json_file_str;

        if (!(json_file_str = alloc_json_path_str(con))) goto error_out;
        FILE *fp = fopen(json_file_str, "a");
        free(json_file_str);
        if (!fp) goto error_out;

        SockEventNode *tmp, *cur = con->head;
        while (cur != NULL) {
                SockEvent *ev = cur->data;
                if (!(json_str = alloc_sock_ev_json(ev))) goto error_out;

                my_fputs(json_str, fp);
                my_fputs("\n", fp);

                free(json_str);
                free_event(cur->data);
                tmp = cur;
                cur = cur->next;
                free(tmp);
        }
        con->head = NULL;
        con->tail = NULL;

        if (fclose(fp) == EOF) goto error2;
        return;
error2:
        LOG(ERROR, "fclose() failed. %s.", strerror(errno));
        goto error_out;
error1:
        LOG(ERROR, "con->directory is NULL.");
error_out:
        LOG_FUNC_ERROR;
        return;
}

static void tcp_dump_tcp_info(int fd) {
        struct tcp_info *info =
            (struct tcp_info *)my_malloc(sizeof(struct tcp_info));
        int ret = fill_tcp_info(fd, info);
        int err = errno;
        sock_ev_tcp_info(fd, ret, err, info);
}

static bool should_dump_tcp_info(const SocketState *con) {
        if (!is_tcp_socket(con->fd)) return false;

        if (conf_opt_u > 0) {
                long cur_time = get_time_micros();
                long time_elasped = cur_time - con->last_info_dump_micros;
                if (time_elasped > conf_opt_u) return true;
        }

        if (conf_opt_b > 0) {
                long cur_bytes = con->bytes_sent + con->bytes_received;
                long bytes_elapsed = cur_bytes - con->last_info_dump_bytes;
                if (bytes_elapsed > conf_opt_b) return true;
        }

        return false;
}

/* Public functions */

void free_socket_state(SocketState *con) {
        if (!con) return;  // NULL
        free_events_list(con->head);
        free(con->directory);
        free(con);
}

void tcp_start_capture(int fd, const struct sockaddr *addr_to) {
        LOG(INFO, "Starting packet capture.");
        LOG_FUNC_INFO;
        SocketState *con = ra_get_and_lock_elem(fd);
        if (!con) goto error_out;

        // We force a bind if the socket is not bound. This allows us to know
        // the source port and use a more specific filter for the capture.
        if (!con->bound) force_bind(fd, con, addr_to->sa_family == AF_INET6);

        // Build pcap file path
        char *pcap_file_path = alloc_pcap_path_str(con);
        if (!pcap_file_path) goto error_out;

        // Build capture filter
        const struct sockaddr *addr_from =
            (con->bound) ? (const struct sockaddr *)&con->bound_addr : NULL;

        const char *capture_filter = alloc_capture_filter(addr_from, addr_to);
        if (!capture_filter) goto error1;
        con->capture_switch = start_capture(capture_filter, pcap_file_path);

        free(pcap_file_path);
        ra_unlock_elem(fd);
        return;
error1:
        free(pcap_file_path);
error_out:
        ra_unlock_elem(fd);
        LOG_FUNC_ERROR;
        return;
}

#define SOCK_EV_PRELUDE(ev_type_cons, ev_type)                                  \
	init_tcpsnitch();                                                      \
	SocketState *con = NULL;                                             \
	if (ev_type_cons != SOCK_EV_SOCKET && ev_type_cons != SOCK_EV_ACCEPT)    \
		con = ra_get_and_lock_elem(fd);                                \
	if (!con) {                                                            \
		if (ev_type_cons != SOCK_EV_SOCKET &&                           \
		    ev_type_cons != SOCK_EV_ACCEPT) {                           \
			LOG(WARN,                                              \
			    "Opening of TCP connection on fd %d was not "      \
			    "detected.",                                       \
			    fd);                                               \
		}                                                              \
		con = alloc_connection(fd);                                    \
		if (!con || !ra_put_elem(fd, con)) {                           \
			LOG_FUNC_ERROR;                                         \
			return;                                                \
		}                                                              \
		con = NULL;                                                    \
		con = ra_get_and_lock_elem(fd);                                \
		if (!con) {                                                    \
			LOG_FUNC_ERROR;                                         \
			return;                                                \
		}                                                              \
	}                                                                      \
	const char *ev_name = string_from_sock_event_type(ev_type_cons);        \
	LOG(INFO, "%s on connection %d (fd %d).", ev_name, con->id, fd);       \
	ev_type *ev =                                                          \
	    (ev_type *)alloc_event(ev_type_cons, ret, err, con->events_count); \
	if (!ev) {                                                             \
		LOG_FUNC_ERROR;                                                 \
		ra_unlock_elem(fd);                                            \
		return;                                                        \
	}

#define SOCK_EV_POSTLUDE(ev_type_cons)                                     \
        push_event(con, (SockEvent *)ev);                                  \
        output_event((SockEvent *)ev);                                     \
        bool dump_tcp_info =                                              \
            should_dump_tcp_info(con) && ev_type_cons != SOCK_EV_TCP_INFO; \
        ra_unlock_elem(fd);                                               \
        if (dump_tcp_info) tcp_dump_tcp_info(fd);

const char *string_from_sock_event_type(SockEventType type) {
        static const char *strings[] = {
                "socket",
                "bind",
                "connect",
                "shutdown",
                "listen",
                "accept",
                "accept4",
                "getsockopt",
                "setsockopt",
                "send",
                "recv",
                "sendto",
                "recvfrom",
                "sendmsg",
                "recvmsg",
#if !defined(__ANDROID__) || __ANDROID_API__ >= 21
                "sendmmsg",
                "recvmmsg",
#endif
                "getsockname",
                "getpeername",
                "sockatmark",
                "isfdtype",
                "write",
                "read",
                "close",
                "dup",
                "dup2",
                "dup3",
                "writev",
                "readv",
                "ioctl",
                "sendfile",
                "poll",
                "ppoll",
                "select",
                "pselect",
                "fcntl",
                "epoll_ctl",
                "epoll_wait",
                "epoll_pwait",
                "fdopen",
                "tcp_info"
        };
        assert(sizeof(strings) / sizeof(char *) == SOCK_EV_TCP_INFO + 1);
        return strings[type];
}

#define SOCK_TYPE_MASK 0b1111
void sock_ev_socket(int fd, int domain, int type, int protocol) {
        /* Check if connection already exits and was not properly closed. */
        if (ra_is_present(fd)) sock_ev_close(fd, 0, 0, false);
        int err = 0;
        int ret = fd;

        // Inst. local vars SocketState *con & SockEvSocket *ev
        SOCK_EV_PRELUDE(SOCK_EV_SOCKET, SockEvSocket);

        ev->domain = domain;
        ev->type = type & SOCK_TYPE_MASK;
        ev->protocol = protocol;
#if !defined(__ANDROID__) || __ANDROID_API__ >= 21
        ev->sock_cloexec = type & SOCK_CLOEXEC;
        ev->sock_nonblock = type & SOCK_NONBLOCK;
#else
        ev->sock_cloexec = false;
        ev->sock_nonblock = false;
#endif

        SOCK_EV_POSTLUDE(SOCK_EV_SOCKET);
}

void sock_ev_bind(int fd, int ret, int err, const struct sockaddr *addr,
                 socklen_t len) {
        // Inst. local vars SocketState *con & SockEvBind *ev
        SOCK_EV_PRELUDE(SOCK_EV_BIND, SockEvBind);

        fill_addr(&(ev->addr), addr, len);
        if (!ret) {
                // Save bound addr as we will later use it for capture filter.
                con->bound = true;
                memcpy(&con->bound_addr, &ev->addr.sockaddr_sto, ev->addr.len);
        }

        SOCK_EV_POSTLUDE(SOCK_EV_BIND);
}

void sock_ev_connect(int fd, int ret, int err, const struct sockaddr *addr,
                    socklen_t len) {
        // Inst. local vars SocketState *con & SockEvConnect *ev
        SOCK_EV_PRELUDE(SOCK_EV_CONNECT, SockEvConnect);

        fill_addr(&(ev->addr), addr, len);

        SOCK_EV_POSTLUDE(SOCK_EV_CONNECT);
}

void sock_ev_shutdown(int fd, int ret, int err, int how) {
        // Inst. local vars SocketState *con & SockEvShutdown *ev
        SOCK_EV_PRELUDE(SOCK_EV_SHUTDOWN, SockEvShutdown);

        ev->shut_rd = (how == SHUT_RD) || (how == SHUT_RDWR);
        ev->shut_wr = (how == SHUT_WR) || (how == SHUT_RDWR);

        SOCK_EV_POSTLUDE(SOCK_EV_SHUTDOWN);
}

void sock_ev_listen(int fd, int ret, int err, int backlog) {
        // Inst. local vars SocketState *con & SockEvListen *ev
        SOCK_EV_PRELUDE(SOCK_EV_LISTEN, SockEvListen);

        ev->backlog = backlog;

        SOCK_EV_POSTLUDE(SOCK_EV_LISTEN);
}

#define ACCEPT_NEW_CON                                              \
	SocketState *new_con = alloc_connection(fd);              \
	if (!new_con) goto error;                                   \
	if (!ra_put_elem(ret, new_con)) goto error;                 \
	new_con = NULL;                                             \
	new_con = ra_get_and_lock_elem(fd);                         \
	if (!new_con) goto error;                                   \
	SockEvAccept *new_ev =                                       \
	    (SockEvAccept *)alloc_event(SOCK_EV_ACCEPT, ret, err, 0); \
	memcpy(&new_ev, &ev, sizeof(SockEvAccept));                  \
	push_event(new_con, (SockEvent *)new_ev);                    \
	output_event((SockEvent *)new_ev);                           \
	if (!ra_put_elem(ret, new_con)) goto error;

void sock_ev_accept(int fd, int ret, int err, struct sockaddr *addr,
                   socklen_t *addr_len) {
        // Inst. local vars SocketState *con & SockEvAccept *ev
        SOCK_EV_PRELUDE(SOCK_EV_ACCEPT, SockEvAccept);

        if (ret != -1 && addr) fill_addr(&(ev->addr), addr, *addr_len);
        ACCEPT_NEW_CON;

        SOCK_EV_POSTLUDE(SOCK_EV_ACCEPT);
error:
        LOG_FUNC_ERROR;
        ra_unlock_elem(fd);
}

void sock_ev_accept4(int fd, int ret, int err, struct sockaddr *addr,
                    socklen_t *addr_len, int flags) {
        // Inst. local vars SocketState *con & SockEvAccept4 *ev
        SOCK_EV_PRELUDE(SOCK_EV_ACCEPT4, SockEvAccept4);

        if (ret != -1 && addr) fill_addr(&(ev->addr), addr, *addr_len);
        ev->flags = flags;
        ACCEPT_NEW_CON;

        SOCK_EV_POSTLUDE(SOCK_EV_ACCEPT4);
error:
        LOG_FUNC_ERROR;
        ra_unlock_elem(fd);
}

void sock_ev_getsockopt(int fd, int ret, int err, int level, int optname,
                       const void *optval, socklen_t optlen) {
        // Inst. local vars SocketState *con & SockEvGetsockopt *ev
        SOCK_EV_PRELUDE(SOCK_EV_GETSOCKOPT, SockEvGetsockopt);

        fill_sockopt(&ev->sockopt, level, optname, optval, optlen);

        SOCK_EV_POSTLUDE(SOCK_EV_SETSOCKOPT);
}

void sock_ev_setsockopt(int fd, int ret, int err, int level, int optname,
                       const void *optval, socklen_t optlen) {
        // Inst. local vars SocketState *con & SockEvSetsockopt *ev
        SOCK_EV_PRELUDE(SOCK_EV_SETSOCKOPT, SockEvSetsockopt);

        fill_sockopt(&ev->sockopt, level, optname, optval, optlen);

        SOCK_EV_POSTLUDE(SOCK_EV_SETSOCKOPT);
}

void sock_ev_send(int fd, int ret, int err, size_t bytes, int flags) {
        // Inst. local vars SocketState *con & SockEvSend *ev
        SOCK_EV_PRELUDE(SOCK_EV_SEND, SockEvSend);

        ev->bytes = bytes;
        ev->flags = flags;
        con->bytes_sent += bytes;

        SOCK_EV_POSTLUDE(SOCK_EV_SEND);
}

void sock_ev_recv(int fd, int ret, int err, size_t bytes, int flags) {
        // Inst. local vars SocketState *con & SockEvRecv *ev
        SOCK_EV_PRELUDE(SOCK_EV_RECV, SockEvRecv);

        ev->bytes = bytes;
        ev->flags = flags;
        con->bytes_received += bytes;

        SOCK_EV_POSTLUDE(SOCK_EV_RECV);
}

void sock_ev_sendto(int fd, int ret, int err, size_t bytes, int flags,
                   const struct sockaddr *addr, socklen_t len) {
        // Inst. local vars SocketState *con & SockEvSendto *ev
        SOCK_EV_PRELUDE(SOCK_EV_SENDTO, SockEvSendto);

	ev->bytes = bytes;
	ev->flags = flags;
	con->bytes_sent += bytes;
        if (addr) fill_addr(&(ev->addr), addr, len);

        SOCK_EV_POSTLUDE(SOCK_EV_SENDTO);
}

void sock_ev_recvfrom(int fd, int ret, int err, size_t bytes, int flags,
                     const struct sockaddr *addr, socklen_t *len) {
        // Inst. local vars SocketState *con & SockEvRecvfrom *ev
        SOCK_EV_PRELUDE(SOCK_EV_RECVFROM, SockEvRecvfrom);

	ev->bytes = bytes;
	ev->flags = flags;
	con->bytes_received += bytes;
        if (ret != -1 && addr) fill_addr(&(ev->addr), addr, *len);

        SOCK_EV_POSTLUDE(SOCK_EV_RECVFROM);
}

void sock_ev_sendmsg(int fd, int ret, int err, const struct msghdr *msg,
                    int flags) {
        // Inst. local vars SocketState *con & SockEvSendmsg *ev
        SOCK_EV_PRELUDE(SOCK_EV_SENDMSG, SockEvSendmsg);

        ev->bytes = fill_tcp_msghdr(&ev->tcp_msghdr, msg);
        ev->flags = flags;
        con->bytes_sent += ev->bytes;

        SOCK_EV_POSTLUDE(SOCK_EV_SENDMSG);
}

void sock_ev_recvmsg(int fd, int ret, int err, const struct msghdr *msg,
                    int flags) {
        // Inst. local vars SocketState *con & SockEvRecvmsg *ev
        SOCK_EV_PRELUDE(SOCK_EV_RECVMSG, SockEvRecvmsg);

        ev->bytes = fill_tcp_msghdr(&ev->tcp_msghdr, msg);
        ev->flags = flags;
        con->bytes_received += ev->bytes;

        SOCK_EV_POSTLUDE(SOCK_EV_RECVMSG);
}

#if !defined(__ANDROID__) || __ANDROID_API__ >= 21

#if !defined(__ANDROID__)
void sock_ev_sendmmsg(int fd, int ret, int err, struct mmsghdr *vmessages,
                     unsigned int vlen, int flags) {
#elif __ANDROID_API__ >= 21
void sock_ev_sendmmsg(int fd, int ret, int err, const struct mmsghdr *vmessages,
                     unsigned int vlen, int flags) {
#endif
        // Inst. local vars SocketState *con & SockEvSendmmsg *ev
        SOCK_EV_PRELUDE(SOCK_EV_SENDMMSG, SockEvSendmmsg);

        ev->flags = flags;

        ev->mmsghdr_count = vlen;
        ev->mmsghdr_vec = (Mmsghdr *)my_malloc(vlen * sizeof(Mmsghdr));
        ev->bytes = fill_tcp_mmsghdr_vec(ev->mmsghdr_vec, vmessages, vlen);

        con->bytes_sent += ev->bytes;
        SOCK_EV_POSTLUDE(SOCK_EV_SENDMMSG);
}

#if !defined(__ANDROID__)
void sock_ev_recvmmsg(int fd, int ret, int err, struct mmsghdr *vmessages,
                     unsigned int vlen, int flags, struct timespec *tmo) {
#elif __ANDROID_API__ >= 21
void sock_ev_recvmmsg(int fd, int ret, int err, struct mmsghdr *vmessages,
                     unsigned int vlen, int flags, const struct timespec *tmo) {
#endif
        // Inst. local vars SocketState *con & SockEvRecvmmsg *ev
        SOCK_EV_PRELUDE(SOCK_EV_RECVMMSG, SockEvRecvmmsg);

        ev->flags = flags;
        ev->timeout.seconds = tmo ? tmo->tv_sec : 0;
        ev->timeout.nanoseconds = tmo ? tmo->tv_nsec : 0;

        ev->mmsghdr_count = vlen;
        ev->mmsghdr_vec = (Mmsghdr *)my_malloc(vlen * sizeof(Mmsghdr));
        ev->bytes = fill_tcp_mmsghdr_vec(ev->mmsghdr_vec, vmessages, vlen);

        con->bytes_received += ev->bytes;
        SOCK_EV_POSTLUDE(SOCK_EV_SENDMMSG);
}

#endif  // #if !defined(__ANDROID__) || __ANDROID_API__ >= 21

void sock_ev_getsockname(int fd, int ret, int err, struct sockaddr *addr,
                        socklen_t *addrlen) {
        // Inst. local vars SocketState *con & SockEvGetsockname *ev
        SOCK_EV_PRELUDE(SOCK_EV_GETSOCKNAME, SockEvGetsockname);

        if (ret != -1) fill_addr(&(ev->addr), addr, *addrlen);

        SOCK_EV_POSTLUDE(SOCK_EV_GETSOCKNAME);
}

void sock_ev_getpeername(int fd, int ret, int err, struct sockaddr *addr,
                        socklen_t *addrlen) {
        // Inst. local vars SocketState *con & SockEvGetpeername *ev
        SOCK_EV_PRELUDE(SOCK_EV_GETPEERNAME, SockEvGetpeername);

        if (ret != -1) fill_addr(&(ev->addr), addr, *addrlen);

        SOCK_EV_POSTLUDE(SOCK_EV_GETPEERNAME);
}

void sock_ev_sockatmark(int fd, int ret, int err) {
        // Inst. local vars SocketState *con & SockEvSockatmark *ev
        SOCK_EV_PRELUDE(SOCK_EV_SOCKATMARK, SockEvSockatmark);
        SOCK_EV_POSTLUDE(SOCK_EV_SOCKATMARK);
}

void sock_ev_isfdtype(int fd, int ret, int err, int fdtype) {
        // Inst. local vars SocketState *con & SockEvIsfdtype *ev
        SOCK_EV_PRELUDE(SOCK_EV_ISFDTYPE, SockEvIsfdtype);

        ev->fdtype = fdtype;

        SOCK_EV_POSTLUDE(SOCK_EV_ISFDTYPE);
}

void sock_ev_write(int fd, int ret, int err, size_t bytes) {
        // Inst. local vars SocketState *con & SockEvWrite *ev
        SOCK_EV_PRELUDE(SOCK_EV_WRITE, SockEvWrite);

        ev->bytes = bytes;
        con->bytes_sent += bytes;

        SOCK_EV_POSTLUDE(SOCK_EV_WRITE);
}

void sock_ev_read(int fd, int ret, int err, size_t bytes) {
        // Inst. local vars SocketState *con & SockEvRead *ev
        SOCK_EV_PRELUDE(SOCK_EV_READ, SockEvRead);

        ev->bytes = bytes;
        con->bytes_received += bytes;

        SOCK_EV_POSTLUDE(SOCK_EV_READ);
}

void sock_ev_close(int fd, int ret, int err, bool detected) {
        SocketState *con = ra_remove_elem(fd);
        if (!con) goto error;

        LOG(INFO, "close on connection %d.", con->id);
        SockEvClose *ev = (SockEvClose *)alloc_event(SOCK_EV_CLOSE, ret, err,
                                                   con->events_count);
        if (!ev) goto error;

        ev->detected = detected;
        if (con->capture_switch != NULL)
                stop_capture(con->capture_switch, con->rtt * 2);

        push_event(con, (SockEvent *)ev);
        output_event((SockEvent *)ev);

        tcp_dump_json(con);
        free_socket_state(con);
        return;
error:
        LOG_FUNC_ERROR;
        return;
}

void sock_ev_dup(int fd, int ret, int err) {
        // Inst. local vars SocketState *con & SockEvDup *ev
        SOCK_EV_PRELUDE(SOCK_EV_DUP, SockEvDup);
        SOCK_EV_POSTLUDE(SOCK_EV_DUP);
}

void sock_ev_dup2(int fd, int ret, int err, int newfd) {
        // Inst. local vars SocketState *con & SockEvDup2 *ev
        SOCK_EV_PRELUDE(SOCK_EV_DUP2, SockEvDup2);

        ev->newfd = newfd;

        SOCK_EV_POSTLUDE(SOCK_EV_DUP2);
}

void sock_ev_dup3(int fd, int ret, int err, int newfd, int flags) {
        // Inst. local vars SocketState *con & SockEvDup3 *ev
        SOCK_EV_PRELUDE(SOCK_EV_DUP3, SockEvDup3);

        ev->newfd = newfd;
        ev->o_cloexec = (flags == O_CLOEXEC);

        SOCK_EV_POSTLUDE(SOCK_EV_DUP3);
}

void sock_ev_writev(int fd, int ret, int err, const struct iovec *iovec,
                   int iovec_count) {
        // Inst. local vars SocketState *con & SockEvWritev *ev
        SOCK_EV_PRELUDE(SOCK_EV_WRITEV, SockEvWritev);

        ev->bytes = fill_iovec(&ev->iovec, iovec, iovec_count);
        con->bytes_sent += ev->bytes;

        SOCK_EV_POSTLUDE(SOCK_EV_WRITEV);
}

void sock_ev_readv(int fd, int ret, int err, const struct iovec *iovec,
                  int iovec_count) {
        // Inst. local vars SocketState *con & SockEvReadv *ev
        SOCK_EV_PRELUDE(SOCK_EV_READV, SockEvReadv);

        ev->bytes = fill_iovec(&ev->iovec, iovec, iovec_count);
        con->bytes_received += ev->bytes;

        SOCK_EV_POSTLUDE(SOCK_EV_READV);
}

#ifdef __ANDROID__
void sock_ev_ioctl(int fd, int ret, int err, int request) {
#else
void sock_ev_ioctl(int fd, int ret, int err, unsigned long int request) {
#endif
        // Inst. local vars SocketState *con & SockEvIoctl *ev
        SOCK_EV_PRELUDE(SOCK_EV_IOCTL, SockEvIoctl);

        ev->request = request;

        SOCK_EV_POSTLUDE(SOCK_EV_IOCTL);
}

void sock_ev_sendfile(int fd, int ret, int err, size_t bytes) {
        // Inst. local vars SocketState *con & SockEvSendfile *ev
        SOCK_EV_PRELUDE(SOCK_EV_SENDFILE, SockEvSendfile);

        ev->bytes = bytes;
        con->bytes_received += ev->bytes;

        SOCK_EV_POSTLUDE(SOCK_EV_SENDFILE);
}

void sock_ev_poll(int fd, int ret, int err, short requested_events,
                 short returned_events, int timeout) {
        // Inst. local vars SocketState *con & SockEvPoll *ev
        SOCK_EV_PRELUDE(SOCK_EV_POLL, SockEvPoll);

        ev->timeout.seconds = (timeout / 1000);
        ev->timeout.nanoseconds = (timeout % 1000) * 1000;
        fill_poll_events(&ev->requested_events, requested_events);
        fill_poll_events(&ev->returned_events, returned_events);

        SOCK_EV_POSTLUDE(SOCK_EV_POLL);
}

void sock_ev_ppoll(int fd, int ret, int err, short requested_events,
                  short returned_events, const struct timespec *timeout) {
        // Inst. local vars SocketState *con & SockEvPpoll *ev
        SOCK_EV_PRELUDE(SOCK_EV_PPOLL, SockEvPpoll);

        ev->timeout.seconds = timeout ? timeout->tv_sec : 0;
        ev->timeout.nanoseconds = timeout ? timeout->tv_nsec : 0;
        fill_poll_events(&ev->requested_events, requested_events);
        fill_poll_events(&ev->returned_events, returned_events);

        SOCK_EV_POSTLUDE(SOCK_EV_PPOLL);
}

void sock_ev_select(int fd, int ret, int err, bool req_read, bool req_write,
                   bool req_except, bool ret_read, bool ret_write,
                   bool ret_except, struct timeval *timeout) {
        // Inst. local vars SocketState *con & SockEvSelect *ev
        SOCK_EV_PRELUDE(SOCK_EV_SELECT, SockEvSelect);

        ev->timeout.seconds = timeout ? timeout->tv_sec : 0;
        ev->timeout.nanoseconds = timeout ? timeout->tv_usec * 1000 : 0;
        ev->requested_events.read = req_read;
        ev->requested_events.write = req_write;
        ev->requested_events.except = req_except;
        ev->returned_events.read = ret_read;
        ev->returned_events.write = ret_write;
        ev->returned_events.except = ret_except;

        SOCK_EV_POSTLUDE(SOCK_EV_SELECT);
}

void sock_ev_pselect(int fd, int ret, int err, bool req_read, bool req_write,
                    bool req_except, bool ret_read, bool ret_write,
                    bool ret_except, const struct timespec *timeout) {
        // Inst. local vars SocketState *con & SockEvPselect *ev
        SOCK_EV_PRELUDE(SOCK_EV_PSELECT, SockEvPselect);

        ev->timeout.seconds = timeout ? timeout->tv_sec : 0;
        ev->timeout.nanoseconds = timeout ? timeout->tv_nsec : 0;
        ev->requested_events.read = req_read;
        ev->requested_events.write = req_write;
        ev->requested_events.except = req_except;
        ev->returned_events.read = ret_read;
        ev->returned_events.write = ret_write;
        ev->returned_events.except = ret_except;

        SOCK_EV_POSTLUDE(SOCK_EV_PSELECT);
}

void sock_ev_fcntl(int fd, int ret, int err, int cmd, ...) {
        // Inst. local vars SocketState *con & SockEvFcntl *ev
        SOCK_EV_PRELUDE(SOCK_EV_FCNTL, SockEvFcntl);

        ev->cmd = cmd;

        switch (cmd) {
                case F_GETFD:
                case F_GETFL:
                case F_GETOWN:
                case F_GETSIG:
                case F_GETLEASE:
                case F_GETPIPE_SZ:
                        break;  // Arg: void
                case F_DUPFD:
                case F_DUPFD_CLOEXEC:
                case F_SETFD:
                case F_SETFL:
                case F_SETOWN:
                case F_SETSIG:
                case F_SETLEASE:
                case F_NOTIFY:
                case F_SETPIPE_SZ:
                        // Arg: int
                        {
                                va_list argp;
                                int arg;
                                va_start(argp, cmd);
                                arg = va_arg(argp, int);
                                va_end(argp);
                                ev->arg = arg;
                        }
                case F_SETLK:
                case F_SETLKW:
                case F_GETLK:
#ifdef __ANDROID__
                case F_GETLK64:
                case F_SETLK64:
                case F_SETLKW64:
#else
                case F_OFD_SETLK:
                case F_OFD_SETLKW:
                case F_OFD_GETLK:
#endif
                        // Arg: struct flock *
                        break;
                case F_GETOWN_EX:
                case F_SETOWN_EX:
                        // Arg: struct f_owner_ex *
                        break;
                default:
                        LOG(WARN, "cmd unknown: %d - fcntl dropped", cmd);
        }

        SOCK_EV_POSTLUDE(SOCK_EV_FCNTL);
}

void sock_ev_epoll_ctl(int fd, int ret, int err, int op,
                      uint32_t requested_events) {
        // Inst. local vars SocketState *con & SockEvEpollCtl *ev
        SOCK_EV_PRELUDE(SOCK_EV_EPOLL_CTL, SockEvEpollCtl);

        ev->op = op;
        ev->requested_events = requested_events;

        SOCK_EV_POSTLUDE(SOCK_EV_EPOLL_CTL);
}

void sock_ev_epoll_wait(int fd, int ret, int err, int timeout,
                       uint32_t returned_events) {
        // Inst. local vars SocketState *con & SockEvEpollWait *ev
        SOCK_EV_PRELUDE(SOCK_EV_EPOLL_WAIT, SockEvEpollWait);

        ev->returned_events = returned_events;
        ev->timeout = timeout;

        SOCK_EV_POSTLUDE(SOCK_EV_EPOLL_WAIT);
}

void sock_ev_epoll_pwait(int fd, int ret, int err, int timeout,
                        uint32_t returned_events) {
        // Inst. local vars SocketState *con & SockEvEpollPwait *ev
        SOCK_EV_PRELUDE(SOCK_EV_EPOLL_PWAIT, SockEvEpollPwait);

        ev->returned_events = returned_events;
        ev->timeout = timeout;

        SOCK_EV_POSTLUDE(SOCK_EV_EPOLL_PWAIT);
}

void sock_ev_fdopen(int fd, FILE *_ret, int err, const char *mode) {
        int ret = (_ret != NULL);
        // Inst. local vars SocketState *con & SockEvFdopen *ev
        SOCK_EV_PRELUDE(SOCK_EV_FDOPEN, SockEvFdopen);

        int n = strlen(mode) + 1;
        ev->mode = (char *)my_malloc(sizeof(char) * n);
        strncpy(ev->mode, mode, n);

        SOCK_EV_POSTLUDE(SOCK_EV_FDOPEN);
}

void sock_ev_tcp_info(int fd, int ret, int err, struct tcp_info *info) {
        // Inst. local vars SocketState *con & SockEvTcpInfo *ev
        SOCK_EV_PRELUDE(SOCK_EV_TCP_INFO, SockEvTcpInfo);
        LOG_FUNC_INFO;

        memcpy(&(ev->info), info, sizeof(struct tcp_info));
        con->last_info_dump_bytes = con->bytes_sent + con->bytes_received;
        con->last_info_dump_micros = get_time_micros();
        con->rtt = info->tcpi_rtt;
        free(info);

        SOCK_EV_POSTLUDE(SOCK_EV_TCP_INFO);
}

void dump_all_sock_events(void) {
        LOG_FUNC_INFO;
        for (long i = 0; i < ra_get_size(); i++) {
                if (ra_is_present(i)) { 
                        SocketState *socket = ra_get_and_lock_elem(i);
                        if (socket) tcp_dump_json(socket);
                        ra_unlock_elem(i);
                }
        }
}

void tcp_free(void) {
        ra_free();
        // We don't check for errors on this one. This is called
        // after fork() and will logically failed if the mutex
        // was lock at the time of forking. This is normal.
        pthread_mutex_destroy(&connections_count_mutex);
}

void tcp_reset(void) {
        ra_reset();
        mutex_init(&connections_count_mutex);
        connections_count = 0;
}
