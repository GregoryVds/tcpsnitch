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

/* We keep a mapping from file descriptors to TCP connections structs for all
 * opened connections. This allows to easily identify to which connection a
 * given function call belongs to.
 *
 * This also allows us to identify when a new TCP connection is started with
 * the same file descriptor as en existing one (meaning we missed the close()
 * call).
 *
 * This data structure is clearly NOT optimal. It could be sparse and will
 * mostly be empty. It is however extremely easy to use and provides O(1)
 * access time. We will see later if we need something else like a hashtable
 * or binary tree.
 */

#define MUTEX_ERRORCHECK PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP
#define MAX_FD 1024
static TcpConnection *fd_con_map[MAX_FD];
static pthread_mutex_t fd_con_map_mutex = MUTEX_ERRORCHECK;

static int connections_count = 0;
static pthread_mutex_t connections_count_mutex = MUTEX_ERRORCHECK;
///////////////////////////////////////////////////////////////////////////////

/* CREATING & FREEING OBJECTS */
static char *create_logs_dir(int con_id);
static TcpConnection *alloc_connection(void);
static TcpEvent *alloc_event(TcpEventType type, int return_value, int err);
static void free_connection(TcpConnection *con);
static void free_events_list(TcpEventNode *head);
static void free_event(TcpEvent *ev);
static void push_event(TcpConnection *con, TcpEvent *ev);

/* HELPERS */
static TcpConnection *get_tcp_connection(int fd);
static TcpConnection *put_tcp_connection(int fd, TcpConnection *con);
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
        int i;
        for (i = 0; i < MAX_FD; i++) {
                if (get_tcp_connection(i) != NULL) {
                        tcp_ev_close(i, 0, 0, false);
                }
        }
}

// This function is called after fork() in the child process right before fork()
// returns control the the newly created process. Therefore, there is at most
// 1 thread of execution, no need for mutexes.
// Reset all state to 0.
void tcp_reset(void) {
        int i;
        for (i = 0; i < MAX_FD; i++) {
                free_connection(fd_con_map[i]);
                fd_con_map[i] = NULL;
        }
        connections_count = 0;
        init_errorcheck_mutex(&fd_con_map_mutex);
        init_errorcheck_mutex(&connections_count_mutex);
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
                D("%s", dir_path);
                return NULL;
        }

        return dir_path;
}

static TcpConnection *alloc_connection(void) {
        TcpConnection *con = (TcpConnection *)calloc(sizeof(TcpConnection), 1);
        if (con == NULL) {
                LOG(ERROR, "calloc() failed. Cannot alloc TcpConnection.");
                return NULL;
        }

        if (!init_errorcheck_mutex(&con->mutex)) goto error;
        con->cmdline = alloc_cmdline_str(&(con->app_name));
        con->timestamp = get_time_sec();
        con->kernel = alloc_kernel_str();

        // Increment connections_count
        if (!lock(&connections_count_mutex)) goto error;
        con->id = connections_count;
        connections_count++;
        unlock(&connections_count_mutex);

        con->directory = create_logs_dir(con->id);
        return con;
error:
        free_connection(con);
        return NULL;
}

static TcpEvent *alloc_event(TcpEventType type, int return_value, int err) {
        bool success;
        TcpEvent *ev;
        switch (type) {
                case TCP_EV_SOCKET:
                        ev = (TcpEvent *)calloc(sizeof(TcpEvSocket), 1);
                        success = (return_value != 0);
                        break;
                case TCP_EV_BIND:
                        success = (return_value != -1);
                        ev = (TcpEvent *)calloc(sizeof(TcpEvBind), 1);
                        break;
                case TCP_EV_CONNECT:
                        success = (return_value != -1);
                        ev = (TcpEvent *)calloc(sizeof(TcpEvConnect), 1);
                        break;
                case TCP_EV_SHUTDOWN:
                        success = (return_value != -1);
                        ev = (TcpEvent *)calloc(sizeof(TcpEvShutdown), 1);
                        break;
                case TCP_EV_LISTEN:
                        success = (return_value != -1);
                        ev = (TcpEvent *)calloc(sizeof(TcpEvListen), 1);
                        break;
                case TCP_EV_SETSOCKOPT:
                        success = (return_value != -1);
                        ev = (TcpEvent *)calloc(sizeof(TcpEvSetsockopt), 1);
                        break;
                case TCP_EV_SEND:
                        success = (return_value != -1);
                        ev = (TcpEvent *)calloc(sizeof(TcpEvSend), 1);
                        break;
                case TCP_EV_RECV:
                        success = (return_value != -1);
                        ev = (TcpEvent *)calloc(sizeof(TcpEvRecv), 1);
                        break;
                case TCP_EV_SENDTO:
                        success = (return_value != -1);
                        ev = (TcpEvent *)calloc(sizeof(TcpEvSendto), 1);
                        break;
                case TCP_EV_RECVFROM:
                        success = (return_value != -1);
                        ev = (TcpEvent *)calloc(sizeof(TcpEvRecvfrom), 1);
                        break;
                case TCP_EV_SENDMSG:
                        success = (return_value != -1);
                        ev = (TcpEvent *)calloc(sizeof(TcpEvSendmsg), 1);
                        break;
                case TCP_EV_RECVMSG:
                        success = (return_value != -1);
                        ev = (TcpEvent *)calloc(sizeof(TcpEvRecvmsg), 1);
                        break;
                case TCP_EV_WRITE:
                        success = (return_value != -1);
                        ev = (TcpEvent *)calloc(sizeof(TcpEvWrite), 1);
                        break;
                case TCP_EV_READ:
                        success = (return_value != -1);
                        ev = (TcpEvent *)calloc(sizeof(TcpEvRead), 1);
                        break;
                case TCP_EV_CLOSE:
                        success = (return_value == 0);
                        ev = (TcpEvent *)calloc(sizeof(TcpEvClose), 1);
                        break;
                case TCP_EV_WRITEV:
                        success = (return_value != -1);
                        ev = (TcpEvent *)calloc(sizeof(TcpEvWritev), 1);
                        break;
                case TCP_EV_READV:
                        success = (return_value != -1);
                        ev = (TcpEvent *)calloc(sizeof(TcpEvReadv), 1);
                        break;
                case TCP_EV_TCP_INFO:
                        success = (return_value != -1);
                        ev = (TcpEvent *)calloc(sizeof(TcpEvTcpInfo), 1);
                        break;
        }

        if (ev == NULL) {
                LOG(ERROR, "malloc() failed. Cannot allocate TcpEvent.");
                return NULL;
        }

        fill_timeval(&(ev->timestamp));
        ev->type = type;
        ev->return_value = return_value;
        ev->success = success;
        ev->error_str = success ? NULL : alloc_error_str(err);
        return ev;
}

static void free_connection(TcpConnection *con) {
        if (!con) return;  // NULL
        free_events_list(con->head);
        free(con->app_name);
        free(con->cmdline);
        free(con->kernel);
        free(con->directory);
        mutex_destroy(&con->mutex);
        free(con);
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
        TcpEventNode *node = (TcpEventNode *)malloc(sizeof(TcpEventNode));
        if (node == NULL) {
                LOG(ERROR, "malloc() failed. Cannot allocate TcpEventNode.");
                return;
        }

        node->data = ev;
        node->next = NULL;
        if (!con->head)
                con->head = node;
        else
                con->tail->next = node;

        con->tail = node;
        con->events_count++;
}

//////////////////////////////////////////////////////////////////////////////

/* Even if at the moment a single lock per fd would be enough, we will change
   the fd_con_map structure in a near future. When the structure will change,
   a single lock per fd will probably not  be enough anymore (for instance if
   the structure becomes a tree. */

static TcpConnection *get_tcp_connection(int fd) {
        if (!(lock(&fd_con_map_mutex))) return NULL;
        TcpConnection *con = fd_con_map[fd];
        unlock(&fd_con_map_mutex);
        return con;
}

static TcpConnection *put_tcp_connection(int fd, TcpConnection *con) {
        if (!(lock(&fd_con_map_mutex))) return NULL;
        fd_con_map[fd] = con;
        unlock(&fd_con_map_mutex);
        return con;
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
        if (flags & MSG_CONFIRM) s->msg_confirm = true;
        if (flags & MSG_DONTROUTE) s->msg_dontroute = true;
        if (flags & MSG_DONTWAIT) s->msg_dontwait = true;
        if (flags & MSG_EOR) s->msg_eor = true;
        if (flags & MSG_MORE) s->msg_more = true;
        if (flags & MSG_NOSIGNAL) s->msg_nosignal = true;
        if (flags & MSG_OOB) s->msg_oob = true;
}

static void fill_recv_flags(TcpRecvFlags *s, int flags) {
        if (flags & MSG_CMSG_CLOEXEC) s->msg_cmsg_cloexec = true;
        if (flags & MSG_DONTWAIT) s->msg_dontwait = true;
        if (flags & MSG_ERRQUEUE) s->msg_errqueue = true;
        if (flags & MSG_OOB) s->msg_oob = true;
        if (flags & MSG_PEEK) s->msg_peek = true;
        if (flags & MSG_TRUNC) s->msg_trunc = true;
        if (flags & MSG_WAITALL) s->msg_waitall = true;
}

static socklen_t fill_msghdr(TcpMsghdr *m1, const struct msghdr *m2) {
        memcpy(&m1->addr, m2->msg_name, m2->msg_namelen);
        m1->control_data = (m2->msg_control != NULL);
        return fill_iovec(&m1->iovec, m2->msg_iov, m2->msg_iovlen);
}

static socklen_t fill_iovec(TcpIovec *iov1, const struct iovec *iov2,
                            int iovec_count) {
        iov1->iovec_count = iovec_count;

        iov1->iovec_sizes = (size_t *)malloc(sizeof(size_t *) * iovec_count);
        if (iov1->iovec_sizes == NULL) LOG(ERROR, "malloc() failed.");

        int i;
        socklen_t bytes = 0;
        for (i = 0; i < iovec_count; i++) {
                if (iov1->iovec_sizes) iov1->iovec_sizes[i] = iov2[i].iov_len;
                bytes += iov2[i].iov_len;
        }

        return bytes;
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

        int port;
        for (port = MIN_PORT; port <= MAX_PORT; port++) {
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

void tcp_start_packet_capture(int fd, const struct sockaddr_storage *addr) {
        TcpConnection *con = get_tcp_connection(fd);
        if (con == NULL) {
                LOG(ERROR, "Cannot find related connection.");
                goto error1;
        }

        // Lock
        if (!lock(&(con->mutex))) goto error1;
        if (con->directory == NULL) {
                LOG(ERROR, "con->directory is NULL.");
                goto error2;
        }

        TcpEvBind *bind_ev = con->bind_ev;
        // Unlock (we unlock to avoid recusive mutexes for the moment).
        if (!unlock(&(con->mutex))) goto error1;

        if (bind_ev == NULL &&
            force_bind(fd, con, addr->ss_family == AF_INET6) == -1) {
                LOG(ERROR, "force_bind() failed. Filter DEST IP/PORT only.");
        }

        // Lock
        if (!lock(&(con->mutex))) goto error1;
        char *pcap_file = alloc_pcap_path_str(con);
        if (pcap_file == NULL) {
                LOG(ERROR, "pcap_file NULL.");
                goto error2;
        }

        char *filter;
        if (con->bind_ev)
                filter = build_capture_filter(&(con->bind_ev->addr), addr);
        else
                filter = build_capture_filter(NULL, addr);

        if (filter == NULL) {
                LOG(ERROR, "filter is NULL.");
                free(pcap_file);
                goto error2;
        }

        con->capture_switch = start_capture(filter, pcap_file);

        free(filter);
        free(pcap_file);
        unlock(&(con->mutex));
        return;
error2:
        unlock(&(con->mutex));
        goto error1;
error1:
        LOG(ERROR, "Abort packet capture");
        return;
}

void tcp_stop_packet_capture(TcpConnection *con) {
        stop_capture(con->capture_switch, con->rtt * 2);
}

///////////////////////////////////////////////////////////////////////////////

#define FAIL_IF_NULL(var, ev_type_cons)                                     \
        if (var == NULL) {                                                  \
                const char *str = string_from_tcp_event_type(ev_type_cons); \
                LOG(ERROR, "Event %s dropped for fd %d. Variable was NULL", \
                    str, fd);                                               \
                return;                                                     \
        }

#define TCP_EV_PRELUDE(ev_type_cons, ev_type)                                  \
        TcpConnection *con = get_tcp_connection(fd);                           \
        FAIL_IF_NULL(con, ev_type_cons);                                       \
        ev_type *ev = (ev_type *)alloc_event(ev_type_cons, return_value, err); \
        FAIL_IF_NULL(ev, ev_type_cons);                                        \
        if (!lock(&(con->mutex))) FAIL_IF_NULL(NULL, ev_type_cons);

#define TCP_EV_POSTLUDE(ev_type_cons)                                          \
        if (ev_type_cons != TCP_EV_TCP_INFO && ev_type_cons != TCP_EV_CLOSE && \
            should_dump_tcp_info(con)) {                                       \
                struct tcp_info _i;                                            \
                int _r = fill_tcpinfo(fd, &_i);                                \
                int _e = errno;                                                \
                unlock(&con->mutex);                                           \
                tcp_ev_tcp_info(fd, _r, _e, &_i);                              \
        } else                                                                 \
                unlock(&con->mutex);

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
        /* Check if connection was not properly closed. */
        if (get_tcp_connection(fd)) tcp_ev_close(fd, 0, 0, false);

        /* Create new connection */
        TcpConnection *new_con = alloc_connection();
        FAIL_IF_NULL(new_con, TCP_EV_SOCKET);
        FAIL_IF_NULL(put_tcp_connection(fd, new_con), TCP_EV_SOCKET);

        /* Create event */
        int return_value = fd;
        int err = 0;
        TCP_EV_PRELUDE(TCP_EV_SOCKET, TcpEvSocket);

        ev->domain = domain;
        ev->type = type & SOCK_TYPE_MASK;
        ev->protocol = protocol;
        ev->sock_cloexec = type & SOCK_CLOEXEC;
        ev->sock_nonblock = type & SOCK_NONBLOCK;
        push_event(con, (TcpEvent *)ev);

        TCP_EV_POSTLUDE(TCP_EV_SOCKET)
}

void tcp_ev_bind(int fd, int return_value, int err, const struct sockaddr *addr,
                 socklen_t len) {
        // Instantiate local vars TcpConnection *con & TcpEvBind *ev
        TCP_EV_PRELUDE(TCP_EV_BIND, TcpEvBind);

        memcpy(&(ev->addr), addr, len);
        con->bind_ev = ev;
        ev->force_bind = con->force_bind;
        push_event(con, (TcpEvent *)ev);

        TCP_EV_POSTLUDE(TCP_EV_BIND)
}

void tcp_ev_connect(int fd, int return_value, int err,
                    const struct sockaddr *addr, socklen_t len) {
        // Instantiate local vars TcpConnection *con & TcpEvConnect *ev
        TCP_EV_PRELUDE(TCP_EV_CONNECT, TcpEvConnect);

        memcpy(&(ev->addr), addr, len);
        push_event(con, (TcpEvent *)ev);

        TCP_EV_POSTLUDE(TCP_EV_CONNECT)
}

void tcp_ev_shutdown(int fd, int return_value, int err, int how) {
        // Instantiate local vars TcpConnection *con & TcpEvShutdown *ev
        TCP_EV_PRELUDE(TCP_EV_SHUTDOWN, TcpEvShutdown);

        ev->shut_rd = (how == SHUT_RD) || (how == SHUT_RDWR);
        ev->shut_wr = (how == SHUT_WR) || (how == SHUT_RDWR);
        push_event(con, (TcpEvent *)ev);

        TCP_EV_POSTLUDE(TCP_EV_SHUTDOWN)
}

void tcp_ev_listen(int fd, int return_value, int err, int backlog) {
        // Instantiate local vars TcpConnection *con & TcpEvListen *ev
        TCP_EV_PRELUDE(TCP_EV_LISTEN, TcpEvListen);

        ev->backlog = backlog;
        push_event(con, (TcpEvent *)ev);

        TCP_EV_POSTLUDE(TCP_EV_LISTEN)
}

void tcp_ev_setsockopt(int fd, int return_value, int err, int level,
                       int optname) {
        // Instantiate local vars TcpConnection *con & TcpEvSetsockopt
        // *ev
        TCP_EV_PRELUDE(TCP_EV_SETSOCKOPT, TcpEvSetsockopt);

        ev->level = level;
        ev->optname = optname;
        push_event(con, (TcpEvent *)ev);

        TCP_EV_POSTLUDE(TCP_EV_SETSOCKOPT)
}

void tcp_ev_send(int fd, int return_value, int err, size_t bytes, int flags) {
        // Instantiate local vars TcpConnection *con & TcpEvSend *ev
        TCP_EV_PRELUDE(TCP_EV_SEND, TcpEvSend);

        con->bytes_sent += bytes;
        ev->bytes = bytes;
        fill_send_flags(&(ev->flags), flags);
        push_event(con, (TcpEvent *)ev);

        TCP_EV_POSTLUDE(TCP_EV_SEND)
}

void tcp_ev_recv(int fd, int return_value, int err, size_t bytes, int flags) {
        // Instantiate local vars TcpConnection *con & TcpEvRecv *ev
        TCP_EV_PRELUDE(TCP_EV_RECV, TcpEvRecv);

        con->bytes_received += bytes;
        ev->bytes = bytes;
        fill_recv_flags(&(ev->flags), flags);
        push_event(con, (TcpEvent *)ev);

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
        push_event(con, (TcpEvent *)ev);

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
        push_event(con, (TcpEvent *)ev);

        TCP_EV_POSTLUDE(TCP_EV_RECVFROM)
}

void tcp_ev_sendmsg(int fd, int return_value, int err, const struct msghdr *msg,
                    int flags) {
        // Instantiate local vars TcpConnection *con & TcpEvSendmsg *ev
        TCP_EV_PRELUDE(TCP_EV_SENDMSG, TcpEvSendmsg);

        fill_send_flags(&(ev->flags), flags);
        ev->bytes = fill_msghdr(&ev->msghdr, msg);
        con->bytes_sent += ev->bytes;

        push_event(con, (TcpEvent *)ev);

        TCP_EV_POSTLUDE(TCP_EV_SENDMSG)
}

void tcp_ev_recvmsg(int fd, int return_value, int err, const struct msghdr *msg,
                    int flags) {
        // Instantiate local vars TcpConnection *con & TcpEvRecvmsg *ev
        TCP_EV_PRELUDE(TCP_EV_RECVMSG, TcpEvRecvmsg);

        fill_recv_flags(&(ev->flags), flags);
        ev->bytes = fill_msghdr(&ev->msghdr, msg);
        con->bytes_received += ev->bytes;

        push_event(con, (TcpEvent *)ev);

        TCP_EV_POSTLUDE(TCP_EV_RECVMSG);
}

void tcp_ev_write(int fd, int return_value, int err, size_t bytes) {
        // Instantiate local vars TcpConnection *con & TcpEvWrite *ev
        TCP_EV_PRELUDE(TCP_EV_WRITE, TcpEvWrite);

        con->bytes_sent += bytes;
        ev->bytes = bytes;
        push_event(con, (TcpEvent *)ev);

        TCP_EV_POSTLUDE(TCP_EV_WRITE)
}

void tcp_ev_read(int fd, int return_value, int err, size_t bytes) {
        // Instantiate local vars TcpConnection *con & TcpEvRead *ev
        TCP_EV_PRELUDE(TCP_EV_READ, TcpEvRead);

        con->bytes_received += bytes;
        ev->bytes = bytes;
        push_event(con, (TcpEvent *)ev);

        TCP_EV_POSTLUDE(TCP_EV_READ)
}

void tcp_ev_close(int fd, int return_value, int err, bool detected) {
        // Instantiate local vars TcpConnection *con & TcpEvClose
        // *ev
        TCP_EV_PRELUDE(TCP_EV_CLOSE, TcpEvClose);

        ev->detected = detected;
        push_event(con, (TcpEvent *)ev);
        if (con->capture_switch != NULL) tcp_stop_packet_capture(con);
        tcp_dump_json(con);

        /* Cleanup */
        put_tcp_connection(fd, NULL);
        // TODO: the following sentence is WRONG.
        // We can unlock the mutex since the con is no longer accessible anyway.
        TCP_EV_POSTLUDE(TCP_EV_CLOSE)
        free_connection(con);
}

void tcp_ev_writev(int fd, int return_value, int err, const struct iovec *iovec,
                   int iovec_count) {
        // Instantiate local vars TcpConnection *con & TcpEvWritev *ev
        TCP_EV_PRELUDE(TCP_EV_WRITEV, TcpEvWritev);

        ev->bytes = fill_iovec(&ev->iovec, iovec, iovec_count);
        con->bytes_sent += ev->bytes;

        push_event(con, (TcpEvent *)ev);

        TCP_EV_POSTLUDE(TCP_EV_WRITEV)
}

void tcp_ev_readv(int fd, int return_value, int err, const struct iovec *iovec,
                  int iovec_count) {
        // Instantiate local vars TcpConnection *con & TcpEvReadv *ev
        TCP_EV_PRELUDE(TCP_EV_READV, TcpEvReadv);

        ev->bytes = fill_iovec(&ev->iovec, iovec, iovec_count);
        con->bytes_received += ev->bytes;

        push_event(con, (TcpEvent *)ev);

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
        push_event(con, (TcpEvent *)ev);

        TCP_EV_POSTLUDE(TCP_EV_TCP_INFO);
}
