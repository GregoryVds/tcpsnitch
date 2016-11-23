#define _GNU_SOURCE

#include "tcp_spy.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include "config.h"
#include "init.h"
#include "lib.h"
#include "logger.h"
#include "packet_sniffer.h"
#include "resizable_array.h"
#include "string_helpers.h"
#include "tcp_spy_json.h"

///////////////////////////////////////////////////////////////////////////////

/*
  ___ _   _ _____ _____ ____  _   _    _    _          _    ____ ___
 |_ _| \ | |_   _| ____|  _ \| \ | |  / \  | |        / \  |  _ \_ _|
  | ||  \| | | | |  _| | |_) |  \| | / _ \ | |       / _ \ | |_) | |
  | || |\  | | | | |___|  _ <| |\  |/ ___ \| |___   / ___ \|  __/| |
 |___|_| \_| |_| |_____|_| \_\_| \_/_/   \_\_____| /_/   \_\_|  |___|

*/

#define MUTEX_ERRORCHECK PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP
static int connections_count = 0;
static pthread_mutex_t connections_count_mutex = MUTEX_ERRORCHECK;

/* CREATING & FREEING OBJECTS */
static char *create_logs_dir(int con_id);
static TcpConnection *alloc_connection(void);
static TcpEvent *alloc_event(TcpEventType type, int return_value, int err);
static void free_events_list(TcpEventNode *head);
static void free_event(TcpEvent *ev);
static void push_event(TcpConnection *con, TcpEvent *ev);

/* HELPERS */
static bool should_dump_tcp_info(TcpConnection *con);
static void fill_send_flags(TcpSendFlags *s, int flags);
static void fill_recv_flags(TcpRecvFlags *s, int flags);
static socklen_t fill_msghdr(TcpMsghdr *m1, const struct msghdr *m2);
static socklen_t fill_iovec(TcpIovec *iov1, const struct iovec *iov2,
                            int iovec_count);

void tcp_dump_json(TcpConnection *con);
int force_bind(int fd, TcpConnection *con, bool IPV6);

///////////////////////////////////////////////////////////////////////////////

// Close all unclosed connections & deallocate any ressource.
void tcp_cleanup(void) {
        for (long i = 0; i < ra_get_size(); i++)
                if (ra_is_present(i)) tcp_ev_close(i, 0, 0, false);
        ra_free();
        mutex_destroy(&connections_count_mutex);
}

// This function is called after fork() in the child process right before fork()
// returns control the the newly created process. Therefore, there is at most
// 1 thread of execution, no need for mutexes.
// Reset all state to 0.
void tcp_reset(void) {
        ra_reset();
        connections_count = 0;
}

///////////////////////////////////////////////////////////////////////////////

char *create_logs_dir(int con_id) {
        if (log_path == NULL) {
                LOG(WARN, "Cannot create logs directory. log_path is NULL.");
                return NULL;
        }

        // Log dir is [LOG_DIR]/[ID]
        int n = get_int_len(con_id) + 1;
        char dirname[n];
        snprintf(dirname, n, "%d", con_id);

        char *dir_path = alloc_concat_path(log_path, dirname);
        if (dir_path == NULL) {
                LOG(ERROR, "alloc_concat_path() failed.");
                return NULL;
        }

        int ret = mkdir(dir_path, 0777);
        if (ret == -1) {
                LOG(ERROR, "mkdir() failed. %s.", strerror(errno));
                return NULL;
        }

        return dir_path;
}

static TcpConnection *alloc_connection(void) {
        TcpConnection *con = (TcpConnection *)my_calloc(sizeof(TcpConnection), 1);
        if (con == NULL) goto error1;

        con->cmdline = alloc_cmdline_str(&(con->app_name));
        con->timestamp = get_time_sec();
        con->kernel = alloc_kernel_str();

        // Increment connections_count
        if (!mutex_lock(&connections_count_mutex)) goto error2;
        con->id = connections_count;
        connections_count++;
        mutex_unlock(&connections_count_mutex);

        con->directory = create_logs_dir(con->id);
        return con;

error2:
        free_connection(con);
        goto error1;
error1:
        LOG_FUNC_FAIL;
        return NULL;
}

static TcpEvent *alloc_event(TcpEventType type, int return_value, int err) {
        bool success;
        TcpEvent *ev;
        switch (type) {
                case TCP_EV_SOCKET:
                        ev = (TcpEvent *)my_calloc(sizeof(TcpEvSocket), 1);
                        success = (return_value != 0);
                        break;
                case TCP_EV_BIND:
                        success = (return_value != -1);
                        ev = (TcpEvent *)my_calloc(sizeof(TcpEvBind), 1);
                        break;
                case TCP_EV_CONNECT:
                        success = (return_value != -1);
                        ev = (TcpEvent *)my_calloc(sizeof(TcpEvConnect), 1);
                        break;
                case TCP_EV_SHUTDOWN:
                        success = (return_value != -1);
                        ev = (TcpEvent *)my_calloc(sizeof(TcpEvShutdown), 1);
                        break;
                case TCP_EV_LISTEN:
                        success = (return_value != -1);
                        ev = (TcpEvent *)my_calloc(sizeof(TcpEvListen), 1);
                        break;
                case TCP_EV_SETSOCKOPT:
                        success = (return_value != -1);
                        ev = (TcpEvent *)my_calloc(sizeof(TcpEvSetsockopt), 1);
                        break;
                case TCP_EV_SEND:
                        success = (return_value != -1);
                        ev = (TcpEvent *)my_calloc(sizeof(TcpEvSend), 1);
                        break;
                case TCP_EV_RECV:
                        success = (return_value != -1);
                        ev = (TcpEvent *)my_calloc(sizeof(TcpEvRecv), 1);
                        break;
                case TCP_EV_SENDTO:
                        success = (return_value != -1);
                        ev = (TcpEvent *)my_calloc(sizeof(TcpEvSendto), 1);
                        break;
                case TCP_EV_RECVFROM:
                        success = (return_value != -1);
                        ev = (TcpEvent *)my_calloc(sizeof(TcpEvRecvfrom), 1);
                        break;
                case TCP_EV_SENDMSG:
                        success = (return_value != -1);
                        ev = (TcpEvent *)my_calloc(sizeof(TcpEvSendmsg), 1);
                        break;
                case TCP_EV_RECVMSG:
                        success = (return_value != -1);
                        ev = (TcpEvent *)my_calloc(sizeof(TcpEvRecvmsg), 1);
                        break;
                case TCP_EV_WRITE:
                        success = (return_value != -1);
                        ev = (TcpEvent *)my_calloc(sizeof(TcpEvWrite), 1);
                        break;
                case TCP_EV_READ:
                        success = (return_value != -1);
                        ev = (TcpEvent *)my_calloc(sizeof(TcpEvRead), 1);
                        break;
                case TCP_EV_CLOSE:
                        success = (return_value == 0);
                        ev = (TcpEvent *)my_calloc(sizeof(TcpEvClose), 1);
                        break;
                case TCP_EV_WRITEV:
                        success = (return_value != -1);
                        ev = (TcpEvent *)my_calloc(sizeof(TcpEvWritev), 1);
                        break;
                case TCP_EV_READV:
                        success = (return_value != -1);
                        ev = (TcpEvent *)my_calloc(sizeof(TcpEvReadv), 1);
                        break;
                case TCP_EV_TCP_INFO:
                        success = (return_value != -1);
                        ev = (TcpEvent *)my_calloc(sizeof(TcpEvTcpInfo), 1);
                        break;
        }

        if (!ev) goto error;

        fill_timeval(&(ev->timestamp));
        ev->type = type;
        ev->return_value = return_value;
        ev->success = success;
        ev->error_str = success ? NULL : alloc_error_str(err);
        return ev;
error:
        LOG_FUNC_FAIL;
        return NULL;
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

static void free_event(TcpEvent *ev) {
        free(ev->error_str);
        switch (ev->type) {
                case TCP_EV_READV:
                        free(((TcpEvReadv *)ev)->iovec.iovec_sizes);
                        break;
                case TCP_EV_WRITEV:
                        free(((TcpEvWritev *)ev)->iovec.iovec_sizes);
                        break;
                default:
                        break;
        }
        free(ev);
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

///////////////////////////////////////////////////////////////////////////////

static bool should_dump_tcp_info(TcpConnection *con) {
        /* Check if time lower bound is set, otherwise assume no lower bound */
        if (tcp_info_time_ival > 0) {
                long cur_time = get_time_micros();
                long time_elasped = cur_time - con->last_info_dump_micros;
                if (time_elasped < tcp_info_time_ival) return false;
        }

        /* Check if bytes lower bound set, otherwise assume no lower bound */
        if (tcp_info_bytes_ival > 0) {
                long cur_bytes = con->bytes_sent + con->bytes_received;
                long bytes_elapsed = cur_bytes - con->last_info_dump_bytes;
                if (bytes_elapsed < tcp_info_bytes_ival) return false;
        }

        /* If we reach this point, no lower bound prevents from dumping */
        return true;
}

///////////////////////////////////////////////////////////////////////////////

static void fill_send_flags(TcpSendFlags *s, int flags) {
        s->msg_confirm = (flags & MSG_CONFIRM);
        s->msg_dontroute = (flags & MSG_DONTROUTE);
        s->msg_dontwait = (flags & MSG_DONTWAIT);
        s->msg_eor = (flags & MSG_EOR);
        s->msg_more = (flags & MSG_MORE);
        s->msg_nosignal = (flags & MSG_NOSIGNAL);
        s->msg_oob = (flags & MSG_OOB);
}

static void fill_recv_flags(TcpRecvFlags *s, int flags) {
        s->msg_cmsg_cloexec = (flags & MSG_CMSG_CLOEXEC);
        s->msg_dontwait = (flags & MSG_DONTWAIT);
        s->msg_errqueue = (flags & MSG_ERRQUEUE);
        s->msg_oob = (flags & MSG_OOB);
        s->msg_peek = (flags & MSG_PEEK);
        s->msg_trunc = (flags & MSG_TRUNC);
        s->msg_waitall = (flags & MSG_WAITALL);
}

static socklen_t fill_msghdr(TcpMsghdr *m1, const struct msghdr *m2) {
        memcpy(&m1->addr, m2->msg_name, m2->msg_namelen);
        m1->control_data = (m2->msg_control != NULL);
        return fill_iovec(&m1->iovec, m2->msg_iov, m2->msg_iovlen);
}

static socklen_t fill_iovec(TcpIovec *iov1, const struct iovec *iov2,
                            int iovec_count) {
        iov1->iovec_count = iovec_count;

        iov1->iovec_sizes = (size_t *)my_malloc(sizeof(size_t *) * iovec_count);
        if (iov1->iovec_sizes == NULL) goto error;

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

///////////////////////////////////////////////////////////////////////////////

void tcp_dump_json(TcpConnection *con) {
        if (con->directory == NULL) {
                LOG(WARN, "Cannot dump JSON to file. con->directory is NULL.");
                return;
        }

        char *json = build_tcp_ev_connection_json(con);
        char *json_file = alloc_json_path_str(con);
        if (json == NULL || json_file == NULL) {
                LOG(ERROR, "Cannot save capture to file.");
                return;
        }

        int ret = append_string_to_file((const char *)json, json_file);
        if (ret != 0) {
                LOG(ERROR, "Error when dumping TcpConnection JSON to file.");
        }

        free(json_file);
}

///////////////////////////////////////////////////////////////////////////////
#define MIN_PORT 32768  // cat /proc/sys/net/ipv4/ip_local_port_range
#define MAX_PORT 60999

int force_bind(int fd, TcpConnection *con, bool IPV6) {
        con->force_bind = true;

        for (int port = MIN_PORT; port <= MAX_PORT; port++) {
                int rc;
                if (IPV6) {
                        struct sockaddr_in6 a;
                        a.sin6_family = AF_INET6;
                        a.sin6_port = htons(port);  // Any port
                        a.sin6_addr = in6addr_any;
                        rc = bind(fd, (struct sockaddr *)&a, sizeof(a));
                } else {
                        struct sockaddr_in a;
                        a.sin_family = AF_INET;
                        a.sin_port = htons(port);
                        a.sin_addr.s_addr = INADDR_ANY;
                        rc = bind(fd, (struct sockaddr *)&a, sizeof(a));
                }
                if (rc == 0) return 0;  // Sucessfull bind. Stop.

                if (errno != EADDRINUSE) {
                        LOG(ERROR, "error code %d", errno);
                        LOG(ERROR, "bind() failed. %s.", strerror(errno));
                        return -1;  // Unexpected error.
                }
                // Error is expected address in use. Try next port.
        }

        return -1;  // Could not bind.
}

///////////////////////////////////////////////////////////////////////////////
/*
  ____  _   _ ____  _     ___ ____      _    ____ ___
 |  _ \| | | | __ )| |   |_ _/ ___|    / \  |  _ \_ _|
 | |_) | | | |  _ \| |    | | |       / _ \ | |_) | |
 |  __/| |_| | |_) | |___ | | |___   / ___ \|  __/| |
 |_|    \___/|____/|_____|___\____| /_/   \_\_|  |___|

*/
///////////////////////////////////////////////////////////////////////////////

void free_connection(TcpConnection *con) {
        if (!con) return;  // NULL
        free_events_list(con->head);
        free(con->app_name);
        free(con->cmdline);
        free(con->kernel);
        free(con->directory);
        free(con);
}

void tcp_start_packet_capture(int fd, const struct sockaddr_storage *addr) {
        TcpConnection *con = ra_get_and_lock_elem(fd);
        if (!con) goto error1;

        if (!con->directory) {
                LOG(ERROR, "con->directory is NULL.");
                goto error2;
        }

        TcpEvBind *bind_ev = con->bind_ev;
        // Unlock (we unlock to avoid recusive mutexes).
        if (!ra_unlock_elem(fd)) goto error1;

        if (bind_ev == NULL &&
            force_bind(fd, con, addr->ss_family == AF_INET6) == -1) {
                LOG(ERROR, "force_bind() failed. Filter DEST IP/PORT only.");
        }

        // Lock
        if (!(con = ra_get_and_lock_elem(fd))) goto error1;

        char *pcap_file = alloc_pcap_path_str(con);
        if (!pcap_file) goto error2;

        char *filter;
        if (con->bind_ev)
                filter = build_capture_filter(&(con->bind_ev->addr), addr);
        else
                filter = build_capture_filter(NULL, addr);

        if (!filter) {
                LOG(ERROR, "filter is NULL.");
                free(pcap_file);
                goto error2;
        }

        con->capture_switch = start_capture(filter, pcap_file);

        free(filter);
        free(pcap_file);
        ra_unlock_elem(fd);
        return;
error2:
        ra_unlock_elem(fd);
        goto error1;
error1:
        LOG(ERROR, "tcp_start_packet_capture() failed.");
        return;
}

void tcp_stop_packet_capture(TcpConnection *con) {
        stop_capture(con->capture_switch, con->rtt * 2);
}

///////////////////////////////////////////////////////////////////////////////

#define FAIL_IF_NULL(var, ev_type_cons) \
        if (var == NULL) {              \
                LOG_FUNC_FAIL;          \
                return;                 \
        }

#define TCP_EV_PRELUDE(ev_type_cons, ev_type)                                  \
        TcpConnection *con = ra_get_and_lock_elem(fd);                         \
        FAIL_IF_NULL(con, ev_type_cons);                                       \
        ev_type *ev = (ev_type *)alloc_event(ev_type_cons, return_value, err); \
        FAIL_IF_NULL(ev, ev_type_cons);

#define TCP_EV_POSTLUDE(ev_type_cons)                         \
        push_event(con, (TcpEvent *)ev);                      \
        bool should_dump = should_dump_tcp_info(con) &&       \
                           ev_type_cons != TCP_EV_TCP_INFO && \
                           ev_type_cons != TCP_EV_CLOSE;      \
        ra_unlock_elem(fd);                                   \
        if (should_dump) {                                    \
                struct tcp_info _i;                           \
                int _r = fill_tcpinfo(fd, &_i);               \
                int _e = errno;                               \
                tcp_ev_tcp_info(fd, _r, _e, &_i);             \
        }

const char *string_from_tcp_event_type(TcpEventType type) {
        static const char *strings[] = {
            "socket()", "bind()",       "connect()", "shutdown()",
            "listen()", "setsockopt()", "send()",    "recv()",
            "sendto()", "recvfrom()",   "sendmsg()", "recvmsg()",
            "write()",  "read()",       "close()",   "writev()",
            "readv()",  "tcp_info"};
        assert(sizeof(strings) / sizeof(char *) == TCP_EV_TCP_INFO + 1);
        return strings[type];
}

///////////////////////////////////////////////////////////////////////////////

#define SOCK_TYPE_MASK 0b1111
void tcp_ev_socket(int fd, int domain, int type, int protocol) {
        /* Check if connection already exits and was not properly closed. */
        if (ra_is_present(fd)) tcp_ev_close(fd, 0, 0, false);

        /* Create new connection */
        TcpConnection *new_con = alloc_connection();
        if (!new_con) goto error;
        if (!ra_put_elem(fd, new_con)) goto error;

        /* Create event */
        int return_value = fd;
        int err = 0;
        TCP_EV_PRELUDE(TCP_EV_SOCKET, TcpEvSocket);

        ev->domain = domain;
        ev->type = type & SOCK_TYPE_MASK;
        ev->protocol = protocol;
        ev->sock_cloexec = type & SOCK_CLOEXEC;
        ev->sock_nonblock = type & SOCK_NONBLOCK;

        TCP_EV_POSTLUDE(TCP_EV_SOCKET)
        return;
error:
        LOG_FUNC_FAIL;
        return;
}

void tcp_ev_bind(int fd, int return_value, int err, const struct sockaddr *addr,
                 socklen_t len) {
        // Instantiate local vars TcpConnection *con & TcpEvBind *ev
        TCP_EV_PRELUDE(TCP_EV_BIND, TcpEvBind);

        memcpy(&(ev->addr), addr, len);
        con->bind_ev = ev;
        ev->force_bind = con->force_bind;

        TCP_EV_POSTLUDE(TCP_EV_BIND)
}

void tcp_ev_connect(int fd, int return_value, int err,
                    const struct sockaddr *addr, socklen_t len) {
        // Instantiate local vars TcpConnection *con & TcpEvConnect *ev
        TCP_EV_PRELUDE(TCP_EV_CONNECT, TcpEvConnect);

        memcpy(&(ev->addr), addr, len);

        TCP_EV_POSTLUDE(TCP_EV_CONNECT)
}

void tcp_ev_shutdown(int fd, int return_value, int err, int how) {
        // Instantiate local vars TcpConnection *con & TcpEvShutdown *ev
        TCP_EV_PRELUDE(TCP_EV_SHUTDOWN, TcpEvShutdown);

        ev->shut_rd = (how == SHUT_RD) || (how == SHUT_RDWR);
        ev->shut_wr = (how == SHUT_WR) || (how == SHUT_RDWR);

        TCP_EV_POSTLUDE(TCP_EV_SHUTDOWN)
}

void tcp_ev_listen(int fd, int return_value, int err, int backlog) {
        // Instantiate local vars TcpConnection *con & TcpEvListen *ev
        TCP_EV_PRELUDE(TCP_EV_LISTEN, TcpEvListen);

        ev->backlog = backlog;

        TCP_EV_POSTLUDE(TCP_EV_LISTEN)
}

void tcp_ev_setsockopt(int fd, int return_value, int err, int level,
                       int optname) {
        // Instantiate local vars TcpConnection *con & TcpEvSetsockopt
        // *ev
        TCP_EV_PRELUDE(TCP_EV_SETSOCKOPT, TcpEvSetsockopt);

        ev->level = level;
        ev->optname = optname;

        TCP_EV_POSTLUDE(TCP_EV_SETSOCKOPT)
}

void tcp_ev_send(int fd, int return_value, int err, size_t bytes, int flags) {
        // Instantiate local vars TcpConnection *con & TcpEvSend *ev
        TCP_EV_PRELUDE(TCP_EV_SEND, TcpEvSend);

        con->bytes_sent += bytes;
        ev->bytes = bytes;
        fill_send_flags(&(ev->flags), flags);

        TCP_EV_POSTLUDE(TCP_EV_SEND)
}

void tcp_ev_recv(int fd, int return_value, int err, size_t bytes, int flags) {
        // Instantiate local vars TcpConnection *con & TcpEvRecv *ev
        TCP_EV_PRELUDE(TCP_EV_RECV, TcpEvRecv);

        con->bytes_received += bytes;
        ev->bytes = bytes;
        fill_recv_flags(&(ev->flags), flags);

        TCP_EV_POSTLUDE(TCP_EV_RECV)
}

void tcp_ev_sendto(int fd, int return_value, int err, size_t bytes, int flags,
                   const struct sockaddr *addr, socklen_t len) {
        // Instantiate local vars TcpConnection *con & TcpEvSendto *ev
        TCP_EV_PRELUDE(TCP_EV_SENDTO, TcpEvSendto);

        con->bytes_sent += bytes;
        ev->bytes = bytes;
        fill_send_flags(&(ev->flags), flags);
        memcpy(&(ev->addr), addr, len);

        TCP_EV_POSTLUDE(TCP_EV_SENDTO)
}

void tcp_ev_recvfrom(int fd, int return_value, int err, size_t bytes, int flags,
                     const struct sockaddr *addr, socklen_t len) {
        // Instantiate local vars TcpConnection *con & TcpEvRecvfrom *ev
        TCP_EV_PRELUDE(TCP_EV_RECVFROM, TcpEvRecvfrom);

        con->bytes_received += bytes;
        ev->bytes = bytes;
        fill_recv_flags(&(ev->flags), flags);
        memcpy(&(ev->addr), addr, len);

        TCP_EV_POSTLUDE(TCP_EV_RECVFROM)
}

void tcp_ev_sendmsg(int fd, int return_value, int err, const struct msghdr *msg,
                    int flags) {
        // Instantiate local vars TcpConnection *con & TcpEvSendmsg *ev
        TCP_EV_PRELUDE(TCP_EV_SENDMSG, TcpEvSendmsg);

        fill_send_flags(&(ev->flags), flags);
        ev->bytes = fill_msghdr(&ev->msghdr, msg);
        con->bytes_sent += ev->bytes;

        TCP_EV_POSTLUDE(TCP_EV_SENDMSG)
}

void tcp_ev_recvmsg(int fd, int return_value, int err, const struct msghdr *msg,
                    int flags) {
        // Instantiate local vars TcpConnection *con & TcpEvRecvmsg *ev
        TCP_EV_PRELUDE(TCP_EV_RECVMSG, TcpEvRecvmsg);

        fill_recv_flags(&(ev->flags), flags);
        ev->bytes = fill_msghdr(&ev->msghdr, msg);
        con->bytes_received += ev->bytes;

        TCP_EV_POSTLUDE(TCP_EV_RECVMSG);
}

void tcp_ev_write(int fd, int return_value, int err, size_t bytes) {
        // Instantiate local vars TcpConnection *con & TcpEvWrite *ev
        TCP_EV_PRELUDE(TCP_EV_WRITE, TcpEvWrite);

        con->bytes_sent += bytes;
        ev->bytes = bytes;

        TCP_EV_POSTLUDE(TCP_EV_WRITE)
}

void tcp_ev_read(int fd, int return_value, int err, size_t bytes) {
        // Instantiate local vars TcpConnection *con & TcpEvRead *ev
        TCP_EV_PRELUDE(TCP_EV_READ, TcpEvRead);

        con->bytes_received += bytes;
        ev->bytes = bytes;

        TCP_EV_POSTLUDE(TCP_EV_READ)
}

void tcp_ev_close(int fd, int return_value, int err, bool detected) {
        // Instantiate local vars TcpConnection *con & TcpEvClose
        // *ev
        TCP_EV_PRELUDE(TCP_EV_CLOSE, TcpEvClose);

        ev->detected = detected;
        if (con->capture_switch != NULL) tcp_stop_packet_capture(con);

        TCP_EV_POSTLUDE(TCP_EV_CLOSE)
        
        // Cleanup
        if (!(con = ra_get_and_lock_elem(fd))) goto error;
        tcp_dump_json(con); // Must be done after POSTLUDE (which add event)
        free_connection(con);
        ra_unlock_elem(fd);
         
        ra_put_elem(fd, NULL);
        return;
error:
        LOG_FUNC_FAIL;
        return;
}

void tcp_ev_writev(int fd, int return_value, int err, const struct iovec *iovec,
                   int iovec_count) {
        // Instantiate local vars TcpConnection *con & TcpEvWritev *ev
        TCP_EV_PRELUDE(TCP_EV_WRITEV, TcpEvWritev);

        ev->bytes = fill_iovec(&ev->iovec, iovec, iovec_count);
        con->bytes_sent += ev->bytes;

        TCP_EV_POSTLUDE(TCP_EV_WRITEV)
}

void tcp_ev_readv(int fd, int return_value, int err, const struct iovec *iovec,
                  int iovec_count) {
        // Instantiate local vars TcpConnection *con & TcpEvReadv *ev
        TCP_EV_PRELUDE(TCP_EV_READV, TcpEvReadv);

        ev->bytes = fill_iovec(&ev->iovec, iovec, iovec_count);
        con->bytes_received += ev->bytes;

        TCP_EV_POSTLUDE(TCP_EV_READV)
}

void tcp_ev_tcp_info(int fd, int return_value, int err, struct tcp_info *info) {
        // Instantiate local vars TcpConnection *con & TcpEvTcpInfo
        // *ev
        TCP_EV_PRELUDE(TCP_EV_TCP_INFO, TcpEvTcpInfo);

        memcpy(&(ev->info), &info, sizeof(struct tcp_info));
        con->last_info_dump_bytes = con->bytes_sent + con->bytes_received;
        con->last_info_dump_micros = get_time_micros();
        con->rtt = info->tcpi_rtt;

        TCP_EV_POSTLUDE(TCP_EV_TCP_INFO);
}
