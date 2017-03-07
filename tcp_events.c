#define _GNU_SOURCE

#include "tcp_events.h"
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

typedef struct {
        bool *switch_flag;
        int con_fd;
} JSONDumperThreadArgs;

static pthread_mutex_t connections_count_mutex = MUTEX_ERRORCHECK;
static int connections_count = 0;

/* Private functions */

static TcpConnection *alloc_connection(int fd) {
	TcpConnection *con;
	if (!(con = (TcpConnection *)my_calloc(sizeof(TcpConnection))))
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
        LOG_FUNC_FAIL;
        return NULL;
}

#define CASE_EV(ev_type_cons, ev_type, err_val)              \
        case ev_type_cons:                                   \
                ev = (TcpEvent *)my_calloc(sizeof(ev_type)); \
                success = (return_value != err_val);         \
                break;

static TcpEvent *alloc_event(TcpEventType type, int return_value, int err,
                             int id) {
        bool success;
        TcpEvent *ev;
        switch (type) {
                CASE_EV(TCP_EV_SOCKET, TcpEvSocket, 0);
                CASE_EV(TCP_EV_BIND, TcpEvBind, -1);
                CASE_EV(TCP_EV_CONNECT, TcpEvConnect, -1);
                CASE_EV(TCP_EV_SHUTDOWN, TcpEvShutdown, -1);
                CASE_EV(TCP_EV_LISTEN, TcpEvListen, -1);
                CASE_EV(TCP_EV_ACCEPT, TcpEvAccept, -1);
                CASE_EV(TCP_EV_ACCEPT4, TcpEvAccept4, -1);
                CASE_EV(TCP_EV_GETSOCKOPT, TcpEvGetsockopt, -1);
                CASE_EV(TCP_EV_SETSOCKOPT, TcpEvSetsockopt, -1);
                CASE_EV(TCP_EV_SEND, TcpEvSend, -1);
                CASE_EV(TCP_EV_RECV, TcpEvRecv, -1);
                CASE_EV(TCP_EV_SENDTO, TcpEvSendto, -1);
                CASE_EV(TCP_EV_RECVFROM, TcpEvRecvfrom, -1);
                CASE_EV(TCP_EV_SENDMSG, TcpEvSendmsg, -1);
                CASE_EV(TCP_EV_RECVMSG, TcpEvRecvmsg, -1);
#if !defined(__ANDROID__) || __ANDROID_API__ >= 21
                CASE_EV(TCP_EV_SENDMMSG, TcpEvSendmmsg, -1);
                CASE_EV(TCP_EV_RECVMMSG, TcpEvRecvmmsg, -1);
#endif
                CASE_EV(TCP_EV_GETSOCKNAME, TcpEvGetsockname, -1);
                CASE_EV(TCP_EV_GETPEERNAME, TcpEvGetpeername, -1);
                CASE_EV(TCP_EV_SOCKATMARK, TcpEvSockatmark, -1);
                CASE_EV(TCP_EV_ISFDTYPE, TcpEvIsfdtype, -1);
                CASE_EV(TCP_EV_WRITE, TcpEvWrite, -1);
                CASE_EV(TCP_EV_READ, TcpEvRead, -1);
                CASE_EV(TCP_EV_CLOSE, TcpEvClose, -1);
                CASE_EV(TCP_EV_DUP, TcpEvDup, -1);
                CASE_EV(TCP_EV_DUP2, TcpEvDup2, -1);
                CASE_EV(TCP_EV_DUP3, TcpEvDup3, -1);
                CASE_EV(TCP_EV_WRITEV, TcpEvWritev, -1);
                CASE_EV(TCP_EV_READV, TcpEvReadv, -1);
                CASE_EV(TCP_EV_IOCTL, TcpEvIoctl, -1);
                CASE_EV(TCP_EV_SENDFILE, TcpEvSendfile, -1);
                CASE_EV(TCP_EV_POLL, TcpEvPoll, -1);
                CASE_EV(TCP_EV_PPOLL, TcpEvPpoll, -1);
                CASE_EV(TCP_EV_SELECT, TcpEvSelect, -1);
                CASE_EV(TCP_EV_PSELECT, TcpEvPselect, -1);
                CASE_EV(TCP_EV_FCNTL, TcpEvFcntl, -1);
                CASE_EV(TCP_EV_EPOLL_CTL, TcpEvEpollCtl, -1);
                CASE_EV(TCP_EV_EPOLL_WAIT, TcpEvEpollWait, -1);
                CASE_EV(TCP_EV_EPOLL_PWAIT, TcpEvEpollPwait, -1);
                CASE_EV(TCP_EV_FDOPEN, TcpEvFdopen, 0);
                CASE_EV(TCP_EV_TCP_INFO, TcpEvTcpInfo, -1);
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
        LOG_FUNC_FAIL;
        return NULL;
}

static void free_event(TcpEvent *ev) {
        free(ev->error_str);
        switch (ev->type) {
                case TCP_EV_GETSOCKOPT:
                        free(((TcpEvGetsockopt *)ev)->sockopt.optval);
                        break;
                case TCP_EV_SETSOCKOPT:
                        free(((TcpEvSetsockopt *)ev)->sockopt.optval);
                        break;
                case TCP_EV_READV:
                        free(((TcpEvReadv *)ev)->iovec.iovec_sizes);
                        break;
                case TCP_EV_WRITEV:
                        free(((TcpEvWritev *)ev)->iovec.iovec_sizes);
                        break;
#if !defined(__ANDROID__) || __ANDROID_API__ >= 21
                case TCP_EV_SENDMMSG:
                        free(((TcpEvSendmmsg *)ev)->mmsghdr_vec);
                        break;
                case TCP_EV_RECVMSG:
                        free(((TcpEvRecvmmsg *)ev)->mmsghdr_vec);
                        break;
#endif
                case TCP_EV_FDOPEN:
                        free(((TcpEvFdopen *)ev)->mode);
                        break;
                default:
                        break;
        }
        free(ev);
}

static void free_events_list(TcpEventNode *head) {
        TcpEventNode *tmp;
        while (head != NULL) {
                free_event(head->data);
                tmp = head;
                head = head->next;
                free(tmp);
        }
}

static void push_event(TcpConnection *con, TcpEvent *ev) {
        TcpEventNode *node = (TcpEventNode *)my_malloc(sizeof(TcpEventNode));
        if (!node) goto error;

        node->data = ev;
        node->next = NULL;
        if (!con->head)
                con->head = node;
        else
                con->tail->next = node;
        con->tail = node;
        con->events_count++;
        return;
error:
        LOG_FUNC_FAIL;
        return;
}

static void fill_addr(TcpAddr *a, const struct sockaddr *addr, socklen_t len) {
        memcpy(&a->sockaddr_sto, addr, len);
        a->len = len;
}

static void fill_poll_events(TcpPollEvents *pe, int events) {
        pe->pollin = (events & POLLIN);
        pe->pollpri = (events & POLLPRI);
        pe->pollout = (events & POLLOUT);
        pe->pollrdhup = (events & POLLRDHUP);
        pe->pollerr = (events & POLLERR);
        pe->pollhup = (events & POLLHUP);
        pe->pollnval = (events & POLLNVAL);
}

static socklen_t fill_iovec(TcpIovec *iov1, const struct iovec *iov2,
                            int iovec_count) {
        iov1->iovec_count = iovec_count;
        if (iovec_count <= 0) return 0;

        iov1->iovec_sizes = (size_t *)my_malloc(sizeof(size_t *) * iovec_count);
        if (!iov1->iovec_sizes) goto error;

        socklen_t bytes = 0;
        for (int i = 0; i < iovec_count; i++) {
                if (iov1->iovec_sizes) iov1->iovec_sizes[i] = iov2[i].iov_len;
                bytes += iov2[i].iov_len;
        }
        return bytes;
error:
        LOG_FUNC_FAIL;
        return -1;
}

static socklen_t fill_tcp_msghdr(TcpMsghdr *m1, const struct msghdr *m2) {
        // We copy the msg_control fields of the "struct msghdr" to another
        // such struct, since we must have such a struct available later to
        // use the CMSG macros for extracting the ancillary data.

        // Msg name
        if (m2->msg_name) memcpy(&m1->addr, m2->msg_name, m2->msg_namelen);

        // Control data (ancillary data)
        m1->msghdr = my_malloc(sizeof(struct msghdr));
        m1->msghdr->msg_controllen = m2->msg_controllen;
        if (m2->msg_controllen)
                m1->msghdr->msg_control = my_malloc(m2->msg_controllen);
        memcpy(m1->msghdr->msg_control, m2->msg_control, m2->msg_controllen);

        // Flags
        m1->flags = m2->msg_flags;

        // Iovec
        return fill_iovec(&m1->iovec, m2->msg_iov, m2->msg_iovlen);
}

static unsigned int fill_tcp_mmsghdr_vec(TcpMmsghdr *tcp_mmsghdr_vec,
                                         const struct mmsghdr *mmsghdr_vec,
                                         unsigned int vlen) {
        unsigned int bytes = 0;
        for (unsigned int i = 0; i < vlen; i++) {
                const struct mmsghdr *mmsghdr = (mmsghdr_vec + i);
                TcpMmsghdr *tcp_mmsghdr = (tcp_mmsghdr_vec + i);
                tcp_mmsghdr->bytes_transmitted = mmsghdr->msg_len;
                bytes += fill_tcp_msghdr(&tcp_mmsghdr->tcp_msghdr,
                                         &mmsghdr->msg_hdr);
        }
        return bytes;
}

static void fill_sockopt(TcpSockopt *sockopt, int level, int optname,
                         const void *optval, socklen_t optlen) {
        sockopt->level = level;
        sockopt->optname = optname;

        sockopt->optval = my_malloc(optlen);
        if (sockopt->optval) {
                sockopt->optlen = optlen;
                memcpy(sockopt->optval, optval, optlen);
        }
        return;
}

typedef int (*orig_bind_type)(int fd, const struct sockaddr *addr,
                              socklen_t len);
orig_bind_type orig_bind;

#define MIN_PORT 32768  // cat /proc/sys/net/ipv4/ip_local_port_range
#define MAX_PORT 60999
static int force_bind(int fd, TcpConnection *con, bool IPV6) {
        LOG(INFO, "Forcing bind on connection %d.", con->id);
        LOG_FUNC_D;
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
        LOG_FUNC_FAIL;
        LOG(INFO, "Packet capture filter on dest IP/PORT only.");
        return -1;
}

static void tcp_dump_json(TcpConnection *con) {
        if (con->directory == NULL) goto error1;
        LOG_FUNC_D;
        char *json_str, *json_file_str;

        if (!(json_file_str = alloc_json_path_str(con))) goto error_out;
        FILE *fp = fopen(json_file_str, "a");
        free(json_file_str);
        if (!fp) goto error_out;

        TcpEventNode *tmp, *cur = con->head;
        while (cur != NULL) {
                TcpEvent *ev = cur->data;
                if (!(json_str = alloc_tcp_ev_json(ev))) goto error_out;

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
        con->last_json_dump_evcount = con->events_count;
        con->last_json_dump_micros = get_time_micros();

        if (fclose(fp) == EOF) goto error2;
        return;
error2:
        LOG(ERROR, "fclose() failed. %s.", strerror(errno));
        goto error_out;
error1:
        LOG(ERROR, "con->directory is NULL.");
error_out:
        LOG_FUNC_FAIL;
        return;
}

static void *json_dumper_thread(void *params) {
        LOG_FUNC_D;
        JSONDumperThreadArgs *args = (JSONDumperThreadArgs *)params;

        struct timespec time;
        time.tv_sec = conf_opt_t / 1000;
        time.tv_nsec = (conf_opt_t % 1000) * 1000 * 1000;  // opt_t is in ms

        while (*args->switch_flag) {
                TcpConnection *con = ra_get_and_lock_elem(args->con_fd);
                if (!con) goto out;
                tcp_dump_json(con);
                ra_unlock_elem(args->con_fd);
                nanosleep(&time, NULL);
        }
        goto out;
out:
        LOG(INFO, "json_dumper_thread for fd %d terminated.", args->con_fd);
        free(args->switch_flag);
        free(args);
        return NULL;
}

static bool should_dump_json(const TcpConnection *con) {
        long cur_time = get_time_micros();
        long time_elasped = cur_time - con->last_json_dump_micros;
        return (time_elasped > conf_opt_t * 1000 ||
                con->events_count - con->last_json_dump_evcount >= conf_opt_e);
}

static void tcp_dump_tcp_info(int fd) {
        struct tcp_info *info =
            (struct tcp_info *)malloc(sizeof(struct tcp_info));
        int ret = fill_tcp_info(fd, info);
        int err = errno;
        tcp_ev_tcp_info(fd, ret, err, info);
}

static bool should_dump_tcp_info(const TcpConnection *con) {
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

void free_connection(TcpConnection *con) {
        if (!con) return;  // NULL
        free_events_list(con->head);
        free(con->directory);
        free(con);
}

void tcp_start_capture(int fd, const struct sockaddr *addr_to) {
        LOG(INFO, "Starting packet capture.");
        LOG_FUNC_D;
        TcpConnection *con = ra_get_and_lock_elem(fd);
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
        LOG_FUNC_FAIL;
        return;
}

void start_json_dumper_thread(TcpConnection *con, int fd) {
        bool *json_dump_switch = (bool *)my_malloc(sizeof(bool));
        if (!json_dump_switch) goto error_out;
        *json_dump_switch = true;

        JSONDumperThreadArgs *args =
            (JSONDumperThreadArgs *)my_malloc(sizeof(JSONDumperThreadArgs));
        if (!args) goto error1;

        args->con_fd = fd;
        args->switch_flag = json_dump_switch;
        con->json_dump_switch = json_dump_switch;

        pthread_t thread;
        int rc = pthread_create(&thread, NULL, json_dumper_thread, args);
        if (rc) goto error2;
        return;
error2:
        LOG(ERROR, "pthread_create_failed(). %s.", strerror(rc));
        free(args);
error1:
        free(json_dump_switch);
error_out:
        LOG_FUNC_FAIL;
}

#define TCP_EV_PRELUDE(ev_type_cons, ev_type)                                  \
	init_tcpsnitch();                                                      \
	TcpConnection *con = NULL;                                             \
	if (ev_type_cons != TCP_EV_SOCKET && ev_type_cons != TCP_EV_ACCEPT)    \
		con = ra_get_and_lock_elem(fd);                                \
	if (!con) {                                                            \
		if (ev_type_cons != TCP_EV_SOCKET &&                           \
		    ev_type_cons != TCP_EV_ACCEPT) {                           \
			LOG(WARN,                                              \
			    "Opening of TCP connection on fd %d was not "      \
			    "detected.",                                       \
			    fd);                                               \
		}                                                              \
		con = alloc_connection(fd);                                    \
		if (!con || !ra_put_elem(fd, con)) {                           \
			LOG_FUNC_FAIL;                                         \
			return;                                                \
		}                                                              \
		con = NULL;                                                    \
		con = ra_get_and_lock_elem(fd);                                \
		if (!con) {                                                    \
			LOG_FUNC_FAIL;                                         \
			return;                                                \
		}                                                              \
		if (conf_opt_t) start_json_dumper_thread(con, fd);             \
	}                                                                      \
	const char *ev_name = string_from_tcp_event_type(ev_type_cons);        \
	LOG(INFO, "%s on connection %d (fd %d).", ev_name, con->id, fd);       \
	ev_type *ev =                                                          \
	    (ev_type *)alloc_event(ev_type_cons, ret, err, con->events_count); \
	if (!ev) {                                                             \
		LOG_FUNC_FAIL;                                                 \
		ra_unlock_elem(fd);                                            \
		return;                                                        \
	}

#define TCP_EV_POSTLUDE(ev_type_cons)                                     \
        push_event(con, (TcpEvent *)ev);                                  \
        output_event((TcpEvent *)ev);                                     \
        bool dump_tcp_info =                                              \
            should_dump_tcp_info(con) && ev_type_cons != TCP_EV_TCP_INFO; \
        if (should_dump_json(con)) tcp_dump_json(con);                    \
        ra_unlock_elem(fd);                                               \
        if (dump_tcp_info) tcp_dump_tcp_info(fd);

const char *string_from_tcp_event_type(TcpEventType type) {
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
        assert(sizeof(strings) / sizeof(char *) == TCP_EV_TCP_INFO + 1);
        return strings[type];
}

#define SOCK_TYPE_MASK 0b1111
void tcp_ev_socket(int fd, int domain, int type, int protocol) {
        /* Check if connection already exits and was not properly closed. */
        if (ra_is_present(fd)) tcp_ev_close(fd, 0, 0, false);
        int err = 0;
        int ret = fd;

        // Inst. local vars TcpConnection *con & TcpEvSocket *ev
        TCP_EV_PRELUDE(TCP_EV_SOCKET, TcpEvSocket);

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

        TCP_EV_POSTLUDE(TCP_EV_SOCKET);
}

void tcp_ev_bind(int fd, int ret, int err, const struct sockaddr *addr,
                 socklen_t len) {
        // Inst. local vars TcpConnection *con & TcpEvBind *ev
        TCP_EV_PRELUDE(TCP_EV_BIND, TcpEvBind);

        fill_addr(&(ev->addr), addr, len);
        if (!ret) {
                // Save bound addr as we will later use it for capture filter.
                con->bound = true;
                memcpy(&con->bound_addr, &ev->addr.sockaddr_sto, ev->addr.len);
        }

        TCP_EV_POSTLUDE(TCP_EV_BIND);
}

void tcp_ev_connect(int fd, int ret, int err, const struct sockaddr *addr,
                    socklen_t len) {
        // Inst. local vars TcpConnection *con & TcpEvConnect *ev
        TCP_EV_PRELUDE(TCP_EV_CONNECT, TcpEvConnect);

        fill_addr(&(ev->addr), addr, len);

        TCP_EV_POSTLUDE(TCP_EV_CONNECT);
}

void tcp_ev_shutdown(int fd, int ret, int err, int how) {
        // Inst. local vars TcpConnection *con & TcpEvShutdown *ev
        TCP_EV_PRELUDE(TCP_EV_SHUTDOWN, TcpEvShutdown);

        ev->shut_rd = (how == SHUT_RD) || (how == SHUT_RDWR);
        ev->shut_wr = (how == SHUT_WR) || (how == SHUT_RDWR);

        TCP_EV_POSTLUDE(TCP_EV_SHUTDOWN);
}

void tcp_ev_listen(int fd, int ret, int err, int backlog) {
        // Inst. local vars TcpConnection *con & TcpEvListen *ev
        TCP_EV_PRELUDE(TCP_EV_LISTEN, TcpEvListen);

        ev->backlog = backlog;

        TCP_EV_POSTLUDE(TCP_EV_LISTEN);
}

#define ACCEPT_NEW_CON                                              \
	TcpConnection *new_con = alloc_connection(fd);              \
	if (!new_con) goto error;                                   \
	if (!ra_put_elem(ret, new_con)) goto error;                 \
	new_con = NULL;                                             \
	new_con = ra_get_and_lock_elem(fd);                         \
	if (!new_con) goto error;                                   \
	if (conf_opt_t) start_json_dumper_thread(new_con, fd);      \
	TcpEvAccept *new_ev =                                       \
	    (TcpEvAccept *)alloc_event(TCP_EV_ACCEPT, ret, err, 0); \
	memcpy(&new_ev, &ev, sizeof(TcpEvAccept));                  \
	push_event(new_con, (TcpEvent *)new_ev);                    \
	output_event((TcpEvent *)new_ev);                           \
	if (!ra_put_elem(ret, new_con)) goto error;

void tcp_ev_accept(int fd, int ret, int err, struct sockaddr *addr,
                   socklen_t *addr_len) {
        // Inst. local vars TcpConnection *con & TcpEvAccept *ev
        TCP_EV_PRELUDE(TCP_EV_ACCEPT, TcpEvAccept);

        if (ret != -1 && addr) fill_addr(&(ev->addr), addr, *addr_len);
        ACCEPT_NEW_CON;

        TCP_EV_POSTLUDE(TCP_EV_ACCEPT);
error:
        LOG_FUNC_FAIL;
        ra_unlock_elem(fd);
}

void tcp_ev_accept4(int fd, int ret, int err, struct sockaddr *addr,
                    socklen_t *addr_len, int flags) {
        // Inst. local vars TcpConnection *con & TcpEvAccept4 *ev
        TCP_EV_PRELUDE(TCP_EV_ACCEPT4, TcpEvAccept4);

        if (ret != -1 && addr) fill_addr(&(ev->addr), addr, *addr_len);
        ev->flags = flags;
        ACCEPT_NEW_CON;

        TCP_EV_POSTLUDE(TCP_EV_ACCEPT4);
error:
        LOG_FUNC_FAIL;
        ra_unlock_elem(fd);
}

void tcp_ev_getsockopt(int fd, int ret, int err, int level, int optname,
                       const void *optval, socklen_t optlen) {
        // Inst. local vars TcpConnection *con & TcpEvGetsockopt *ev
        TCP_EV_PRELUDE(TCP_EV_GETSOCKOPT, TcpEvGetsockopt);

        fill_sockopt(&ev->sockopt, level, optname, optval, optlen);

        TCP_EV_POSTLUDE(TCP_EV_SETSOCKOPT);
}

void tcp_ev_setsockopt(int fd, int ret, int err, int level, int optname,
                       const void *optval, socklen_t optlen) {
        // Inst. local vars TcpConnection *con & TcpEvSetsockopt *ev
        TCP_EV_PRELUDE(TCP_EV_SETSOCKOPT, TcpEvSetsockopt);

        fill_sockopt(&ev->sockopt, level, optname, optval, optlen);

        TCP_EV_POSTLUDE(TCP_EV_SETSOCKOPT);
}

void tcp_ev_send(int fd, int ret, int err, size_t bytes, int flags) {
        // Inst. local vars TcpConnection *con & TcpEvSend *ev
        TCP_EV_PRELUDE(TCP_EV_SEND, TcpEvSend);

        ev->bytes = bytes;
        ev->flags = flags;
        con->bytes_sent += bytes;

        TCP_EV_POSTLUDE(TCP_EV_SEND);
}

void tcp_ev_recv(int fd, int ret, int err, size_t bytes, int flags) {
        // Inst. local vars TcpConnection *con & TcpEvRecv *ev
        TCP_EV_PRELUDE(TCP_EV_RECV, TcpEvRecv);

        ev->bytes = bytes;
        ev->flags = flags;
        con->bytes_received += bytes;

        TCP_EV_POSTLUDE(TCP_EV_RECV);
}

void tcp_ev_sendto(int fd, int ret, int err, size_t bytes, int flags,
                   const struct sockaddr *addr, socklen_t len) {
        // Inst. local vars TcpConnection *con & TcpEvSendto *ev
        TCP_EV_PRELUDE(TCP_EV_SENDTO, TcpEvSendto);

	ev->bytes = bytes;
	ev->flags = flags;
	con->bytes_sent += bytes;
        if (addr) fill_addr(&(ev->addr), addr, len);

        TCP_EV_POSTLUDE(TCP_EV_SENDTO);
}

void tcp_ev_recvfrom(int fd, int ret, int err, size_t bytes, int flags,
                     const struct sockaddr *addr, socklen_t *len) {
        // Inst. local vars TcpConnection *con & TcpEvRecvfrom *ev
        TCP_EV_PRELUDE(TCP_EV_RECVFROM, TcpEvRecvfrom);

	ev->bytes = bytes;
	ev->flags = flags;
	con->bytes_received += bytes;
        if (ret != -1 && addr) fill_addr(&(ev->addr), addr, *len);

        TCP_EV_POSTLUDE(TCP_EV_RECVFROM);
}

void tcp_ev_sendmsg(int fd, int ret, int err, const struct msghdr *msg,
                    int flags) {
        // Inst. local vars TcpConnection *con & TcpEvSendmsg *ev
        TCP_EV_PRELUDE(TCP_EV_SENDMSG, TcpEvSendmsg);

        ev->bytes = fill_tcp_msghdr(&ev->tcp_msghdr, msg);
        ev->flags = flags;
        con->bytes_sent += ev->bytes;

        TCP_EV_POSTLUDE(TCP_EV_SENDMSG);
}

void tcp_ev_recvmsg(int fd, int ret, int err, const struct msghdr *msg,
                    int flags) {
        // Inst. local vars TcpConnection *con & TcpEvRecvmsg *ev
        TCP_EV_PRELUDE(TCP_EV_RECVMSG, TcpEvRecvmsg);

        ev->bytes = fill_tcp_msghdr(&ev->tcp_msghdr, msg);
        ev->flags = flags;
        con->bytes_received += ev->bytes;

        TCP_EV_POSTLUDE(TCP_EV_RECVMSG);
}

#if !defined(__ANDROID__) || __ANDROID_API__ >= 21

#if !defined(__ANDROID__)
void tcp_ev_sendmmsg(int fd, int ret, int err, struct mmsghdr *vmessages,
                     unsigned int vlen, int flags) {
#elif __ANDROID_API__ >= 21
void tcp_ev_sendmmsg(int fd, int ret, int err, const struct mmsghdr *vmessages,
                     unsigned int vlen, int flags) {
#endif
        // Inst. local vars TcpConnection *con & TcpEvSendmmsg *ev
        TCP_EV_PRELUDE(TCP_EV_SENDMMSG, TcpEvSendmmsg);

        ev->flags = flags;

        ev->mmsghdr_count = vlen;
        ev->mmsghdr_vec = (TcpMmsghdr *)my_malloc(vlen * sizeof(TcpMmsghdr));
        ev->bytes = fill_tcp_mmsghdr_vec(ev->mmsghdr_vec, vmessages, vlen);

        con->bytes_sent += ev->bytes;
        TCP_EV_POSTLUDE(TCP_EV_SENDMMSG);
}

#if !defined(__ANDROID__)
void tcp_ev_recvmmsg(int fd, int ret, int err, struct mmsghdr *vmessages,
                     unsigned int vlen, int flags, struct timespec *tmo) {
#elif __ANDROID_API__ >= 21
void tcp_ev_recvmmsg(int fd, int ret, int err, struct mmsghdr *vmessages,
                     unsigned int vlen, int flags, const struct timespec *tmo) {
#endif
        // Inst. local vars TcpConnection *con & TcpEvRecvmmsg *ev
        TCP_EV_PRELUDE(TCP_EV_RECVMMSG, TcpEvRecvmmsg);

        ev->flags = flags;
        ev->timeout.seconds = tmo ? tmo->tv_sec : 0;
        ev->timeout.nanoseconds = tmo ? tmo->tv_nsec : 0;

        ev->mmsghdr_count = vlen;
        ev->mmsghdr_vec = (TcpMmsghdr *)my_malloc(vlen * sizeof(TcpMmsghdr));
        ev->bytes = fill_tcp_mmsghdr_vec(ev->mmsghdr_vec, vmessages, vlen);

        con->bytes_received += ev->bytes;
        TCP_EV_POSTLUDE(TCP_EV_SENDMMSG);
}

#endif  // #if !defined(__ANDROID__) || __ANDROID_API__ >= 21

void tcp_ev_getsockname(int fd, int ret, int err, struct sockaddr *addr,
                        socklen_t *addrlen) {
        // Inst. local vars TcpConnection *con & TcpEvGetsockname *ev
        TCP_EV_PRELUDE(TCP_EV_GETSOCKNAME, TcpEvGetsockname);

        if (ret != -1) fill_addr(&(ev->addr), addr, *addrlen);

        TCP_EV_POSTLUDE(TCP_EV_GETSOCKNAME);
}

void tcp_ev_getpeername(int fd, int ret, int err, struct sockaddr *addr,
                        socklen_t *addrlen) {
        // Inst. local vars TcpConnection *con & TcpEvGetpeername *ev
        TCP_EV_PRELUDE(TCP_EV_GETPEERNAME, TcpEvGetpeername);

        if (ret != -1) fill_addr(&(ev->addr), addr, *addrlen);

        TCP_EV_POSTLUDE(TCP_EV_GETPEERNAME);
}

void tcp_ev_sockatmark(int fd, int ret, int err) {
        // Inst. local vars TcpConnection *con & TcpEvSockatmark *ev
        TCP_EV_PRELUDE(TCP_EV_SOCKATMARK, TcpEvSockatmark);
        TCP_EV_POSTLUDE(TCP_EV_SOCKATMARK);
}

void tcp_ev_isfdtype(int fd, int ret, int err, int fdtype) {
        // Inst. local vars TcpConnection *con & TcpEvIsfdtype *ev
        TCP_EV_PRELUDE(TCP_EV_ISFDTYPE, TcpEvIsfdtype);

        ev->fdtype = fdtype;

        TCP_EV_POSTLUDE(TCP_EV_ISFDTYPE);
}

void tcp_ev_write(int fd, int ret, int err, size_t bytes) {
        // Inst. local vars TcpConnection *con & TcpEvWrite *ev
        TCP_EV_PRELUDE(TCP_EV_WRITE, TcpEvWrite);

        ev->bytes = bytes;
        con->bytes_sent += bytes;

        TCP_EV_POSTLUDE(TCP_EV_WRITE);
}

void tcp_ev_read(int fd, int ret, int err, size_t bytes) {
        // Inst. local vars TcpConnection *con & TcpEvRead *ev
        TCP_EV_PRELUDE(TCP_EV_READ, TcpEvRead);

        ev->bytes = bytes;
        con->bytes_received += bytes;

        TCP_EV_POSTLUDE(TCP_EV_READ);
}

void tcp_ev_close(int fd, int ret, int err, bool detected) {
        TcpConnection *con = ra_remove_elem(fd);
        if (!con) goto error;

        LOG(INFO, "close on connection %d.", con->id);
        TcpEvClose *ev = (TcpEvClose *)alloc_event(TCP_EV_CLOSE, ret, err,
                                                   con->events_count);
        if (!ev) goto error;

        ev->detected = detected;
        if (con->capture_switch != NULL)
                stop_capture(con->capture_switch, con->rtt * 2);

        push_event(con, (TcpEvent *)ev);
        output_event((TcpEvent *)ev);

        *con->json_dump_switch = false;
        tcp_dump_json(con);
        free_connection(con);
        return;
error:
        LOG_FUNC_FAIL;
        return;
}

void tcp_ev_dup(int fd, int ret, int err) {
        // Inst. local vars TcpConnection *con & TcpEvDup *ev
        TCP_EV_PRELUDE(TCP_EV_DUP, TcpEvDup);
        TCP_EV_POSTLUDE(TCP_EV_DUP);
}

void tcp_ev_dup2(int fd, int ret, int err, int newfd) {
        // Inst. local vars TcpConnection *con & TcpEvDup2 *ev
        TCP_EV_PRELUDE(TCP_EV_DUP2, TcpEvDup2);

        ev->newfd = newfd;

        TCP_EV_POSTLUDE(TCP_EV_DUP2);
}

void tcp_ev_dup3(int fd, int ret, int err, int newfd, int flags) {
        // Inst. local vars TcpConnection *con & TcpEvDup3 *ev
        TCP_EV_PRELUDE(TCP_EV_DUP3, TcpEvDup3);

        ev->newfd = newfd;
        ev->o_cloexec = (flags == O_CLOEXEC);

        TCP_EV_POSTLUDE(TCP_EV_DUP3);
}

void tcp_ev_writev(int fd, int ret, int err, const struct iovec *iovec,
                   int iovec_count) {
        // Inst. local vars TcpConnection *con & TcpEvWritev *ev
        TCP_EV_PRELUDE(TCP_EV_WRITEV, TcpEvWritev);

        ev->bytes = fill_iovec(&ev->iovec, iovec, iovec_count);
        con->bytes_sent += ev->bytes;

        TCP_EV_POSTLUDE(TCP_EV_WRITEV);
}

void tcp_ev_readv(int fd, int ret, int err, const struct iovec *iovec,
                  int iovec_count) {
        // Inst. local vars TcpConnection *con & TcpEvReadv *ev
        TCP_EV_PRELUDE(TCP_EV_READV, TcpEvReadv);

        ev->bytes = fill_iovec(&ev->iovec, iovec, iovec_count);
        con->bytes_received += ev->bytes;

        TCP_EV_POSTLUDE(TCP_EV_READV);
}

#ifdef __ANDROID__
void tcp_ev_ioctl(int fd, int ret, int err, int request) {
#else
void tcp_ev_ioctl(int fd, int ret, int err, unsigned long int request) {
#endif
        // Inst. local vars TcpConnection *con & TcpEvIoctl *ev
        TCP_EV_PRELUDE(TCP_EV_IOCTL, TcpEvIoctl);

        ev->request = request;

        TCP_EV_POSTLUDE(TCP_EV_IOCTL);
}

void tcp_ev_sendfile(int fd, int ret, int err, size_t bytes) {
        // Inst. local vars TcpConnection *con & TcpEvSendfile *ev
        TCP_EV_PRELUDE(TCP_EV_SENDFILE, TcpEvSendfile);

        ev->bytes = bytes;
        con->bytes_received += ev->bytes;

        TCP_EV_POSTLUDE(TCP_EV_SENDFILE);
}

void tcp_ev_poll(int fd, int ret, int err, short requested_events,
                 short returned_events, int timeout) {
        // Inst. local vars TcpConnection *con & TcpEvPoll *ev
        TCP_EV_PRELUDE(TCP_EV_POLL, TcpEvPoll);

        ev->timeout.seconds = (timeout / 1000);
        ev->timeout.nanoseconds = (timeout % 1000) * 1000;
        fill_poll_events(&ev->requested_events, requested_events);
        fill_poll_events(&ev->returned_events, returned_events);

        TCP_EV_POSTLUDE(TCP_EV_POLL);
}

void tcp_ev_ppoll(int fd, int ret, int err, short requested_events,
                  short returned_events, const struct timespec *timeout) {
        // Inst. local vars TcpConnection *con & TcpEvPpoll *ev
        TCP_EV_PRELUDE(TCP_EV_PPOLL, TcpEvPpoll);

        ev->timeout.seconds = timeout ? timeout->tv_sec : 0;
        ev->timeout.nanoseconds = timeout ? timeout->tv_nsec : 0;
        fill_poll_events(&ev->requested_events, requested_events);
        fill_poll_events(&ev->returned_events, returned_events);

        TCP_EV_POSTLUDE(TCP_EV_PPOLL);
}

void tcp_ev_select(int fd, int ret, int err, bool req_read, bool req_write,
                   bool req_except, bool ret_read, bool ret_write,
                   bool ret_except, struct timeval *timeout) {
        // Inst. local vars TcpConnection *con & TcpEvSelect *ev
        TCP_EV_PRELUDE(TCP_EV_SELECT, TcpEvSelect);

        ev->timeout.seconds = timeout ? timeout->tv_sec : 0;
        ev->timeout.nanoseconds = timeout ? timeout->tv_usec * 1000 : 0;
        ev->requested_events.read = req_read;
        ev->requested_events.write = req_write;
        ev->requested_events.except = req_except;
        ev->returned_events.read = ret_read;
        ev->returned_events.write = ret_write;
        ev->returned_events.except = ret_except;

        TCP_EV_POSTLUDE(TCP_EV_SELECT);
}

void tcp_ev_pselect(int fd, int ret, int err, bool req_read, bool req_write,
                    bool req_except, bool ret_read, bool ret_write,
                    bool ret_except, const struct timespec *timeout) {
        // Inst. local vars TcpConnection *con & TcpEvPselect *ev
        TCP_EV_PRELUDE(TCP_EV_PSELECT, TcpEvPselect);

        ev->timeout.seconds = timeout ? timeout->tv_sec : 0;
        ev->timeout.nanoseconds = timeout ? timeout->tv_nsec : 0;
        ev->requested_events.read = req_read;
        ev->requested_events.write = req_write;
        ev->requested_events.except = req_except;
        ev->returned_events.read = ret_read;
        ev->returned_events.write = ret_write;
        ev->returned_events.except = ret_except;

        TCP_EV_POSTLUDE(TCP_EV_PSELECT);
}

void tcp_ev_fcntl(int fd, int ret, int err, int cmd, ...) {
        // Inst. local vars TcpConnection *con & TcpEvFcntl *ev
        TCP_EV_PRELUDE(TCP_EV_FCNTL, TcpEvFcntl);

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

        TCP_EV_POSTLUDE(TCP_EV_FCNTL);
}

void tcp_ev_epoll_ctl(int fd, int ret, int err, int op,
                      uint32_t requested_events) {
        // Inst. local vars TcpConnection *con & TcpEvEpollCtl *ev
        TCP_EV_PRELUDE(TCP_EV_EPOLL_CTL, TcpEvEpollCtl);

        ev->op = op;
        ev->requested_events = requested_events;

        TCP_EV_POSTLUDE(TCP_EV_EPOLL_CTL);
}

void tcp_ev_epoll_wait(int fd, int ret, int err, int timeout,
                       uint32_t returned_events) {
        // Inst. local vars TcpConnection *con & TcpEvEpollWait *ev
        TCP_EV_PRELUDE(TCP_EV_EPOLL_WAIT, TcpEvEpollWait);

        ev->returned_events = returned_events;
        ev->timeout = timeout;

        TCP_EV_POSTLUDE(TCP_EV_EPOLL_WAIT);
}

void tcp_ev_epoll_pwait(int fd, int ret, int err, int timeout,
                        uint32_t returned_events) {
        // Inst. local vars TcpConnection *con & TcpEvEpollPwait *ev
        TCP_EV_PRELUDE(TCP_EV_EPOLL_PWAIT, TcpEvEpollPwait);

        ev->returned_events = returned_events;
        ev->timeout = timeout;

        TCP_EV_POSTLUDE(TCP_EV_EPOLL_PWAIT);
}

void tcp_ev_fdopen(int fd, FILE *_ret, int err, const char *mode) {
        int ret = (_ret != NULL);
        // Inst. local vars TcpConnection *con & TcpEvFdopen *ev
        TCP_EV_PRELUDE(TCP_EV_FDOPEN, TcpEvFdopen);

        int n = strlen(mode) + 1;
        ev->mode = (char *)my_malloc(sizeof(char) * n);
        if (ev->mode) strncpy(ev->mode, mode, n);

        TCP_EV_POSTLUDE(TCP_EV_FDOPEN);
}

void tcp_ev_tcp_info(int fd, int ret, int err, struct tcp_info *info) {
        // Inst. local vars TcpConnection *con & TcpEvTcpInfo *ev
        TCP_EV_PRELUDE(TCP_EV_TCP_INFO, TcpEvTcpInfo);
        LOG_FUNC_D;

        memcpy(&(ev->info), info, sizeof(struct tcp_info));
        con->last_info_dump_bytes = con->bytes_sent + con->bytes_received;
        con->last_info_dump_micros = get_time_micros();
        con->rtt = info->tcpi_rtt;
        free(info);

        TCP_EV_POSTLUDE(TCP_EV_TCP_INFO);
}

void tcp_close_unclosed_connections(void) {
        for (long i = 0; i < ra_get_size(); i++)
                if (ra_is_present(i)) tcp_ev_close(i, 0, 0, false);
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
