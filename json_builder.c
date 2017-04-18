#define _GNU_SOURCE

#include "json_builder.h"
#include <jansson.h>
#include <netdb.h>
#include "constants.h"
#include "fcntl.h"
#include "init.h"
#include "lib.h"
#include "logger.h"
#include "string_builders.h"
#include "sys/epoll.h"

static json_t *my_json_object(void) {
        json_t *obj = json_object();
        if (!obj) {
                LOG(ERROR, "json_object() failed.");
                LOG_FUNC_ERROR;
                abort();
        }
        return obj;
}

static json_t *my_json_array(void) {
        json_t *array = json_array();
        if (!array) {
                LOG(ERROR, "json_array() failed.");
                LOG_FUNC_ERROR;
                abort();
        }
        return array;
}

/* Save reference to pointer with shorter name */
typedef int (*add_type)(json_t *o, const char *k, json_t *v);
static add_type add = &json_object_set_new;

static json_t *build_sock_info(const SockInfo *sock_info) {
        // We only fill it when the event is the first of the trace.
        if (!sock_info->filled) return NULL;
        json_t *json_si = my_json_object();

        char *domain = alloc_sock_domain_str(sock_info->domain);
        add(json_si, "domain", json_string(domain));
        free(domain);

        char *type = alloc_sock_type_str(sock_info->type);
        add(json_si, "type", json_string(type));
        free(type);

        struct protoent *p = NULL;
        if (sock_info->protocol) p = getprotobynumber(sock_info->protocol);
        if (p) add(json_si, "protocol", json_string(p->p_name));
        else {
                char *proto_str = alloc_str_from_int(sock_info->protocol);
                add(json_si, "protocol", json_string(proto_str));
                free(proto_str);
        }

        add(json_si, "SOCK_CLOEXEC", json_boolean(sock_info->sock_cloexec));
        add(json_si, "SOCK_NONBLOCK", json_boolean(sock_info->sock_nonblock));

        return json_si;
}

static json_t *build_addr(const Addr *addr) {
        if (!addr->len) return NULL;

        json_t *json_addr = my_json_object();

        const struct sockaddr *sockaddr =
            (const struct sockaddr *)&addr->sockaddr_sto;
        if (sockaddr->sa_family == AF_INET)
                add(json_addr, "sa_family", json_string("AF_INET"));
        else if (sockaddr->sa_family == AF_INET6)
                add(json_addr, "sa_family", json_string("AF_INET6"));

        char *ip = alloc_ip_str(sockaddr);
        add(json_addr, "ip", json_string(ip));
        free(ip);
        char *port = alloc_port_str(sockaddr);
        add(json_addr, "port", json_string(port));
        free(port);

        // char *hostname, *service;
        // alloc_name_str(sockaddr, addr->len, &hostname, &service);
        // add(json_addr, "hostname", json_string(hostname));
        // add(json_addr, "service", json_string(service));
        // free(hostname);
        // free(service);

        return json_addr;
}

static json_t *build_send_flags(int flags) {
        json_t *json_flags = my_json_object();
        add(json_flags, "MSG_CONFIRM", json_boolean(flags & MSG_CONFIRM));
        add(json_flags, "MSG_DONTROUTE", json_boolean(flags & MSG_DONTROUTE));
        add(json_flags, "MSG_DONTWAIT", json_boolean(flags & MSG_DONTWAIT));
        add(json_flags, "MSG_EOR", json_boolean(flags & MSG_EOR));
        add(json_flags, "MSG_MORE", json_boolean(flags & MSG_MORE));
        add(json_flags, "MSG_NOSIGNAL", json_boolean(flags & MSG_NOSIGNAL));
        add(json_flags, "MSG_OOB", json_boolean(flags & MSG_OOB));
        return json_flags;
}

static json_t *build_recv_flags(int flags) {
        json_t *json_flags = my_json_object();

#if !defined(__ANDROID__) || __ANDROID_API__ >= 21
        add(json_flags, "MSG_CMSG_CLOEXEC",
            json_boolean(flags & MSG_CMSG_CLOEXEC));
#else
        add(json_flags, "MSG_CMSG_CLOEXEC", json_boolean(false));
#endif
        add(json_flags, "MSG_DONTWAIT", json_boolean(flags & MSG_DONTWAIT));
        add(json_flags, "MSG_ERRQUEUE", json_boolean(flags & MSG_ERRQUEUE));
        add(json_flags, "MSG_OOB", json_boolean(flags & MSG_OOB));
        add(json_flags, "MSG_PEEK", json_boolean(flags & MSG_PEEK));
        add(json_flags, "MSG_TRUNC", json_boolean(flags & MSG_TRUNC));
        add(json_flags, "MSG_WAITALL", json_boolean(flags & MSG_WAITALL));

        return json_flags;
}

static json_t *build_timeout(const Timeout *timeout) {
        json_t *json_timeout = my_json_object();
        add(json_timeout, "seconds", json_integer(timeout->seconds));
        add(json_timeout, "nanoseconds", json_integer(timeout->nanoseconds));
        return json_timeout;
}

static json_t *build_poll_events(const PollEvents *events) {
        json_t *json_events = my_json_object();
        add(json_events, "POLLIN", json_boolean(events->pollin));
        add(json_events, "POLLPRI", json_boolean(events->pollpri));
        add(json_events, "POLLOUT", json_boolean(events->pollout));
        add(json_events, "POLLRDHUP", json_boolean(events->pollrdhup));
        add(json_events, "POLLERR", json_boolean(events->pollerr));
        add(json_events, "POLLHUP", json_boolean(events->pollhup));
        add(json_events, "POLLNVAL", json_boolean(events->pollnval));
        return json_events;
}

static json_t *build_select_events(const SelectEvents *events) {
        json_t *json_events = my_json_object();
        add(json_events, "READ", json_boolean(events->read));
        add(json_events, "WRITE", json_boolean(events->write));
        add(json_events, "EXCEPT", json_boolean(events->except));
        return json_events;
}

static json_t *build_epoll_events(uint32_t events) {
        json_t *json_events = my_json_object();
        add(json_events, "EPOLLIN", json_boolean(events & EPOLLIN));
        add(json_events, "EPOLLOUT", json_boolean(events & EPOLLOUT));
        add(json_events, "EPOLLRDHUP", json_boolean(events & EPOLLRDHUP));
        add(json_events, "EPOLLPRI", json_boolean(events & EPOLLPRI));
        add(json_events, "EPOLLERR", json_boolean(events & EPOLLERR));
        add(json_events, "EPOLLHUP", json_boolean(events & EPOLLHUP));
        add(json_events, "EPOLLET", json_boolean(events & EPOLLET));
        add(json_events, "EPOLLONESHOT", json_boolean(events & EPOLLONESHOT));
        add(json_events, "EPOLLWAKEUP", json_boolean(events & EPOLLWAKEUP));
        return json_events;
}

static json_t *build_iovec(const Iovec *iovec) {
        json_t *json_iovec = my_json_object();
        add(json_iovec, "iovec_count", json_integer(iovec->iovec_count));
        json_t *iovec_sizes = my_json_array();
        for (int i = 0; i < iovec->iovec_count; i++)
                json_array_append_new(iovec_sizes,
                                      json_integer(iovec->iovec_sizes[i]));
        add(json_iovec, "iovec_sizes", iovec_sizes);
        return json_iovec;
}

static json_t *build_control_data(struct msghdr *msgh) {
        json_t *json_cd_list = my_json_array();
        // TODO: Can't find where the problem is... Can't properly extract the
        // ancillary data.
        struct cmsghdr *cmsg;
        cmsg = CMSG_FIRSTHDR(msgh);
        if (cmsg) {
                json_t *json_cd = my_json_object();
                add(json_cd, "cmsg_level", json_integer(cmsg->cmsg_level));
                add(json_cd, "cmsg_type", json_integer(cmsg->cmsg_type));
                json_array_append_new(json_cd_list, json_cd);
        }
        //        cmsg = CMSG_NXTHDR(msgh, cmsg);
        //        for (cmsg = CMSG_FIRSTHDR(msgh); cmsg != NULL;
        //           cmsg = CMSG_NXTHDR(msgh, cmsg)) {
        //              json_t *json_cd = my_json_object();
        //              add(json_cd, "cmsg_level",
        // json_integer(cmsg->cmsg_level));
        //              add(json_cd, "cmsg_type",
        // json_integer(cmsg->cmsg_type));
        //              json_array_append_new(json_cd_list, json_cd);
        //      }

        return json_cd_list;
}

static json_t *build_msghdr(const Msghdr *msg) {
        json_t *json_msghdr = my_json_object();
        // Flags are only for recvmsg()
        if (msg->flags) add(json_msghdr, "flags", build_recv_flags(msg->flags));
        add(json_msghdr, "iovec", build_iovec(&msg->iovec));
        add(json_msghdr, "control_data_len",
            json_integer(msg->msghdr->msg_controllen));
        add(json_msghdr, "control_data", build_control_data(msg->msghdr));
        return json_msghdr;
}

static json_t *build_mmsghdr_vec(const Mmsghdr *mmsghdr_vec,
                                 int mmsghdr_count) {
        json_t *json_mmsghdr_vec = my_json_array();
        for (int i = 0; i < mmsghdr_count; i++) {
                json_t *json_mmsghdr = my_json_object();
                const Mmsghdr *mmsghder = (mmsghdr_vec + i);
                add(json_mmsghdr, "transmitted_bytes",
                    json_integer(mmsghder->bytes_transmitted));
                add(json_mmsghdr, "msghdr", build_msghdr(&mmsghder->msghdr));
                json_array_append_new(json_mmsghdr_vec, json_mmsghdr);
        }
        return json_mmsghdr_vec;
}

static json_t *build_timeval(const struct timeval *tv) {
        json_t *json_timeval = my_json_object();
        add(json_timeval, "tv_sec", json_integer(tv->tv_sec));
        add(json_timeval, "tv_usec", json_integer(tv->tv_usec));
        return json_timeval;
}

static json_t *build_linger(const struct linger *linger) {
        json_t *json_linger = my_json_object();
        add(json_linger, "l_onoff", json_integer(linger->l_onoff));
        add(json_linger, "l_linger", json_integer(linger->l_linger));
        return json_linger;
}

static json_t *build_optval(const Sockopt *sockopt) {
        switch (sockopt->level) {
                case SOL_SOCKET:
                        switch (sockopt->optname) {
                                case SO_RCVTIMEO:
                                case SO_SNDTIMEO:
                                        return build_timeval(
                                            (struct timeval *)sockopt->optval);
                                        break;
                                case SO_LINGER:
                                        return build_linger(
                                            (struct linger *)sockopt->optval);
                                        break;
                                case SO_RCVBUF:
                                case SO_SNDBUF:
                                case SO_ERROR:
                                        return json_integer(
                                            *((int *)sockopt->optval));
                                        break;
                                case SO_KEEPALIVE:
                                case SO_DEBUG:
                                case SO_REUSEADDR:
                                        return json_boolean(
                                            *((int *)sockopt->optval));
                                        break;
                        }
                        break;
                case IPPROTO_TCP:
                        switch (sockopt->optname) {
                                case TCP_KEEPINTVL:
                                case TCP_KEEPIDLE:
                                        return json_integer(
                                            *((int *)sockopt->optval));
                                        break;
                                case TCP_NODELAY:
                                        return json_boolean(
                                            *((int *)sockopt->optval));
                                        break;
                        }
                        break;
                case IPPROTO_IPV6:
                        switch (sockopt->optname) {
                                case IPV6_V6ONLY:
                                        return json_boolean(
                                            *((int *)sockopt->optval));
                                        break;
                        }
                        break;
        }
        return NULL;
}

static void add_sockopt(json_t *details, const Sockopt *sockopt) {
        char *level = alloc_sockopt_level(sockopt->level);
        add(details, "level", json_string(level));
        free(level);

        char *optname = alloc_sockopt_name(sockopt->level, sockopt->optname);
        add(details, "optname", json_string(optname));
        free(optname);

        add(details, "optlen", json_integer(sockopt->optlen));
        if (sockopt->optlen) add(details, "optval", build_optval(sockopt));
}

static void add_fd_flags(json_t *details, int flags) {
        add(details, "O_CLOEXEC", json_boolean(flags & O_CLOEXEC));
}

static void add_fl_flags(json_t *details, int flags) {
        add(details, "O_APPEND", json_boolean(flags & O_APPEND));
        add(details, "O_ASYNC", json_boolean(flags & O_ASYNC));
        add(details, "O_DIRECT", json_boolean(flags & O_DIRECT));
        add(details, "O_NOATIME", json_boolean(flags & O_NOATIME));
        add(details, "O_NONBLOCK", json_boolean(flags & O_NONBLOCK));
}

static void build_shared_fields(json_t *json_ev, const SockEvent *ev) {
        const char *type_str = string_from_sock_event_type(ev->type);
        add(json_ev, "type", json_string(type_str));
        add(json_ev, "timestamp_usec", json_integer(ev->timestamp_usec));
        add(json_ev, "return_value", json_integer(ev->return_value));
        add(json_ev, "success", json_boolean(ev->success));
        if (!ev->success) {
                char *errno_str = alloc_errno_str(ev->err);
                add(json_ev, "errno", json_string(errno_str));
                free(errno_str);
        }
        add(json_ev, "thread_id", json_integer(ev->thread_id));
        add(json_ev, "fake_call", json_boolean(false));
}

#define DETAILS_FAILURE "json_object() failed. Cannot build event details."

#define BUILD_EV_PRELUDE()                                   \
        json_t *json_ev = my_json_object();                  \
        build_shared_fields(json_ev, (const SockEvent *)ev); \
        json_t *json_details = my_json_object();             \
        add(json_ev, "details", json_details);

static json_t *build_sock_ev_socket(const SockEvSocket *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "sock_info", build_sock_info(&ev->sock_info));
        return json_ev;
}

static json_t *build_sock_ev_forked_socket(const SockEvForkedSocket *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_ev, "fake_call", json_boolean(true));
        add(json_details, "sock_info", build_sock_info(&ev->sock_info));
        return json_ev;
}

static json_t *build_sock_ev_ghost_socket(const SockEvGhostSocket *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_ev, "fake_call", json_boolean(true));
        add(json_details, "sock_info", build_sock_info(&ev->sock_info));
        return json_ev;
}

static json_t *build_sock_ev_bind(const SockEvBind *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "addr", build_addr(&ev->addr));
        return json_ev;
}

static json_t *build_sock_ev_connect(const SockEvConnect *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "addr", build_addr(&ev->addr));
        return json_ev;
}

static json_t *build_sock_ev_shutdown(const SockEvShutdown *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "SHUT_RD", json_boolean(ev->shut_rd));
        add(json_details, "SHUT_WR", json_boolean(ev->shut_wr));
        return json_ev;
}

static json_t *build_sock_ev_listen(const SockEvListen *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "backlog", json_integer(ev->backlog));
        return json_ev;
}

static json_t *build_sock_ev_accept(const SockEvAccept *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "addr", build_addr(&ev->addr));
        add(json_details, "sock_info", build_sock_info(&ev->sock_info));
        return json_ev;
}

static json_t *build_sock_ev_accept4(const SockEvAccept4 *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "addr", build_addr(&ev->addr));
        add(json_details, "flags", json_integer(ev->flags));
        add(json_details, "sock_info", build_sock_info(&ev->sock_info));
        return json_ev;
}

static json_t *build_sock_ev_getsockopt(const SockEvGetsockopt *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add_sockopt(json_details, &ev->sockopt);
        return json_ev;
}

static json_t *build_sock_ev_setsockopt(const SockEvSetsockopt *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add_sockopt(json_details, &ev->sockopt);
        return json_ev;
}

static json_t *build_sock_ev_send(const SockEvSend *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "bytes", json_integer(ev->bytes));
        add(json_details, "flags", build_send_flags(ev->flags));
        return json_ev;
}

static json_t *build_sock_ev_recv(const SockEvRecv *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "bytes", json_integer(ev->bytes));
        add(json_details, "flags", build_recv_flags(ev->flags));
        return json_ev;
}

static json_t *build_sock_ev_sendto(const SockEvSendto *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "bytes", json_integer(ev->bytes));
        add(json_details, "flags", build_send_flags(ev->flags));
        add(json_details, "addr", build_addr(&ev->addr));
        return json_ev;
}

static json_t *build_sock_ev_recvfrom(const SockEvRecvfrom *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "bytes", json_integer(ev->bytes));
        add(json_details, "flags", build_recv_flags(ev->flags));
        add(json_details, "addr", build_addr(&ev->addr));
        return json_ev;
}

static json_t *build_sock_ev_sendmsg(const SockEvSendmsg *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "bytes", json_integer(ev->bytes));
        add(json_details, "flags", build_send_flags(ev->flags));
        add(json_details, "msghdr", build_msghdr(&(ev->msghdr)));
        return json_ev;
}

static json_t *build_sock_ev_recvmsg(const SockEvRecvmsg *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "bytes", json_integer(ev->bytes));
        add(json_details, "flags", build_recv_flags(ev->flags));
        add(json_details, "msghdr", build_msghdr(&(ev->msghdr)));
        return json_ev;
}

#if !defined(__ANDROID__) || __ANDROID_API__ >= 21
static json_t *build_sock_ev_sendmmsg(const SockEvSendmmsg *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "bytes", json_integer(ev->bytes));
        add(json_details, "flags", build_send_flags(ev->flags));
        add(json_details, "mmsghdr_count", json_integer(ev->mmsghdr_count));
        add(json_details, "mmsghdr_vec",
            build_mmsghdr_vec(ev->mmsghdr_vec, ev->mmsghdr_count));
        return json_ev;
}

static json_t *build_sock_ev_recvmmsg(const SockEvRecvmmsg *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "bytes", json_integer(ev->bytes));
        add(json_details, "flags", build_recv_flags(ev->flags));
        add(json_details, "mmsghdr_count", json_integer(ev->mmsghdr_count));
        add(json_details, "mmsghdr_vec",
            build_mmsghdr_vec(ev->mmsghdr_vec, ev->mmsghdr_count));
        add(json_details, "timeout", build_timeout(&ev->timeout));
        return json_ev;
}
#endif

static json_t *build_sock_ev_getsockname(const SockEvGetsockname *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "addr", build_addr(&ev->addr));
        return json_ev;
}

static json_t *build_sock_ev_getpeername(const SockEvGetpeername *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "addr", build_addr(&ev->addr));
        return json_ev;
}

static json_t *build_sock_ev_sockatmark(const SockEvSockatmark *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        return json_ev;
}

static json_t *build_sock_ev_isfdtype(const SockEvIsfdtype *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "fdtype", json_integer(ev->fdtype));
        return json_ev;
}

static json_t *build_sock_ev_write(const SockEvWrite *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "bytes", json_integer(ev->bytes));
        return json_ev;
}

static json_t *build_sock_ev_read(const SockEvRead *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "bytes", json_integer(ev->bytes));
        return json_ev;
}

static json_t *build_sock_ev_close(const SockEvClose *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        return json_ev;
}

static json_t *build_sock_ev_dup(const SockEvDup *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "sock_info", build_sock_info(&ev->sock_info));
        return json_ev;
}

static json_t *build_sock_ev_dup2(const SockEvDup2 *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "newfd", json_integer(ev->newfd));
        add(json_details, "sock_info", build_sock_info(&ev->sock_info));
        return json_ev;
}

static json_t *build_sock_ev_dup3(const SockEvDup3 *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "newfd", json_integer(ev->newfd));
        add(json_details, "O_CLOEXEC", json_boolean(ev->o_cloexec));
        add(json_details, "sock_info", build_sock_info(&ev->sock_info));
        return json_ev;
}

static json_t *build_sock_ev_writev(const SockEvWritev *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "bytes", json_integer(ev->bytes));
        add(json_details, "iovec", build_iovec(&ev->iovec));
        return json_ev;
}

static json_t *build_sock_ev_readv(const SockEvReadv *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "bytes", json_integer(ev->bytes));
        add(json_details, "iovec", build_iovec(&ev->iovec));
        return json_ev;
}

static json_t *build_sock_ev_ioctl(const SockEvIoctl *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        char *request = alloc_ioctl_request_str(ev->request);
        add(json_details, "request", json_string(request));
        free(request);
        return json_ev;
}

static json_t *build_sock_ev_sendfile(const SockEvSendfile *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "bytes", json_integer(ev->bytes));
        return json_ev;
}

static json_t *build_sock_ev_poll(const SockEvPoll *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "timeout", build_timeout(&ev->timeout));
        add(json_details, "requested_events",
            build_poll_events(&ev->requested_events));
        add(json_details, "returned_events",
            build_poll_events(&ev->returned_events));
        return json_ev;
}

static json_t *build_sock_ev_ppoll(const SockEvPpoll *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "timeout", build_timeout(&ev->timeout));
        add(json_details, "requested_events",
            build_poll_events(&ev->requested_events));
        add(json_details, "returned_events",
            build_poll_events(&ev->returned_events));
        return json_ev;
}

static json_t *build_sock_ev_select(const SockEvSelect *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "timeout", build_timeout(&ev->timeout));
        add(json_details, "requested_events",
            build_select_events(&ev->requested_events));
        add(json_details, "returned_events",
            build_select_events(&ev->returned_events));
        return json_ev;
}

static json_t *build_sock_ev_pselect(const SockEvPselect *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "timeout", build_timeout(&ev->timeout));
        add(json_details, "requested_events",
            build_select_events(&ev->requested_events));
        add(json_details, "returned_events",
            build_select_events(&ev->returned_events));
        return json_ev;
}

static json_t *build_sock_ev_fcntl(const SockEvFcntl *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        json_t *d = json_details;

        char *cmd_str = alloc_fcntl_cmd_str(ev->cmd);
        add(json_details, "cmd", json_string(cmd_str));
        free(cmd_str);

        switch (ev->cmd) {
                case F_GETFD:
                        add_fd_flags(d, ev->super.return_value);
                        break;
                case F_GETFL:
                        add_fl_flags(d, ev->super.return_value);
                        break;
                case F_GETOWN:
                case F_GETSIG:
                case F_GETLEASE:
                case F_GETPIPE_SZ:
                        break;  // Arg: void
                case F_SETFD:
                        add_fd_flags(d, ev->arg);
                        break;
                case F_SETFL:
                        add_fl_flags(d, ev->arg);
                        break;
                case F_DUPFD:
                case F_DUPFD_CLOEXEC:
                case F_SETOWN:
                case F_SETSIG:
                case F_SETLEASE:
                case F_NOTIFY:
                case F_SETPIPE_SZ:  // Arg: int
                        add(d, "arg", json_integer(ev->arg));
                        break;
        }
        if (ev->cmd == F_DUPFD || ev->cmd == F_DUPFD_CLOEXEC)
                add(json_details, "sock_info", build_sock_info(&ev->sock_info));
        return json_ev;
}

static json_t *build_sock_ev_epoll_ctl(const SockEvEpollCtl *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details

        const char *op;
        switch (ev->op) {
                case EPOLL_CTL_ADD:
                        op = "EPOLL_CTL_ADD";
                        break;
                case EPOLL_CTL_MOD:
                        op = "EPOLL_CTL_MOD";
                        break;
                case EPOLL_CTL_DEL:
                        op = "EPOLL_CTL_DEL";
                        break;
        }
        add(json_details, "op", json_string(op));
        add(json_details, "requested_events",
            build_epoll_events(ev->requested_events));

        return json_ev;
}

static json_t *build_sock_ev_epoll_wait(const SockEvEpollWait *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "timeout", json_integer(ev->timeout));
        add(json_details, "returned_events",
            build_epoll_events(ev->returned_events));
        return json_ev;
}

static json_t *build_sock_ev_epoll_pwait(const SockEvEpollPwait *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "timeout", json_integer(ev->timeout));
        add(json_details, "returned_events",
            build_epoll_events(ev->returned_events));
        return json_ev;
}

static json_t *build_sock_ev_fdopen(const SockEvFdopen *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_details, "mode", json_string(ev->mode));
        return json_ev;
}

static json_t *build_sock_ev_tcp_info(const SockEvTcpInfo *ev) {
        BUILD_EV_PRELUDE()  // Inst. json_t *json_ev & json_t *json_details
        add(json_ev, "fake_call", json_boolean(true));

        struct tcp_info i = ev->info;

        add(json_details, "state", json_integer(i.tcpi_state));
        add(json_details, "ca_state", json_integer(i.tcpi_ca_state));
        add(json_details, "retransmits", json_integer(i.tcpi_retransmits));
        add(json_details, "probes", json_integer(i.tcpi_probes));
        add(json_details, "backoff", json_integer(i.tcpi_backoff));
        add(json_details, "options", json_integer(i.tcpi_options));
        add(json_details, "snd_wscale", json_integer(i.tcpi_snd_wscale));
        add(json_details, "rcv_wscale", json_integer(i.tcpi_rcv_wscale));

        add(json_details, "rto", json_integer(i.tcpi_rto));
        add(json_details, "ato", json_integer(i.tcpi_ato));
        add(json_details, "snd_mss", json_integer(i.tcpi_snd_mss));
        add(json_details, "rcv_mss", json_integer(i.tcpi_rcv_mss));

        add(json_details, "unacked", json_integer(i.tcpi_unacked));
        add(json_details, "sacked", json_integer(i.tcpi_sacked));
        add(json_details, "lost", json_integer(i.tcpi_lost));
        add(json_details, "retrans", json_integer(i.tcpi_retrans));
        add(json_details, "fackets", json_integer(i.tcpi_fackets));

        /* Times */
        add(json_details, "last_data_sent",
            json_integer(i.tcpi_last_data_sent));
        add(json_details, "last_ack_sent", json_integer(i.tcpi_last_ack_sent));
        add(json_details, "last_data_recv",
            json_integer(i.tcpi_last_data_recv));
        add(json_details, "last_ack_recv", json_integer(i.tcpi_last_ack_recv));

        /* Metrics */
        add(json_details, "pmtu", json_integer(i.tcpi_pmtu));
        add(json_details, "rcv_ssthresh", json_integer(i.tcpi_rcv_ssthresh));
        add(json_details, "rtt", json_integer(i.tcpi_rtt));
        add(json_details, "rttvar", json_integer(i.tcpi_rttvar));
        add(json_details, "snd_ssthresh", json_integer(i.tcpi_snd_ssthresh));
        add(json_details, "snd_cwnd", json_integer(i.tcpi_snd_cwnd));
        add(json_details, "advmss", json_integer(i.tcpi_advmss));
        add(json_details, "reordering", json_integer(i.tcpi_reordering));

        add(json_details, "rcv_rtt", json_integer(i.tcpi_rcv_rtt));
        add(json_details, "rcv_space", json_integer(i.tcpi_rcv_space));

        add(json_details, "total_retrans", json_integer(i.tcpi_total_retrans));

        return json_ev;
}

static json_t *build_sock_ev(const SockEvent *ev) {
        json_t *r;
        switch (ev->type) {
                case SOCK_EV_SOCKET:
                        r = build_sock_ev_socket((const SockEvSocket *)ev);
                        break;
                case SOCK_EV_FORKED_SOCKET:
                        r = build_sock_ev_forked_socket(
                            (const SockEvForkedSocket *)ev);
                        break;
                case SOCK_EV_GHOST_SOCKET:
                        r = build_sock_ev_ghost_socket((const SockEvGhostSocket *)ev);
                        break;
                case SOCK_EV_BIND:
                        r = build_sock_ev_bind((const SockEvBind *)ev);
                        break;
                case SOCK_EV_CONNECT:
                        r = build_sock_ev_connect((const SockEvConnect *)ev);
                        break;
                case SOCK_EV_SHUTDOWN:
                        r = build_sock_ev_shutdown((const SockEvShutdown *)ev);
                        break;
                case SOCK_EV_LISTEN:
                        r = build_sock_ev_listen((const SockEvListen *)ev);
                        break;
                case SOCK_EV_ACCEPT:
                        r = build_sock_ev_accept((const SockEvAccept *)ev);
                        break;
                case SOCK_EV_ACCEPT4:
                        r = build_sock_ev_accept4((const SockEvAccept4 *)ev);
                        break;
                case SOCK_EV_GETSOCKOPT:
                        r = build_sock_ev_getsockopt(
                            (const SockEvGetsockopt *)ev);
                        break;
                case SOCK_EV_SETSOCKOPT:
                        r = build_sock_ev_setsockopt(
                            (const SockEvSetsockopt *)ev);
                        break;
                case SOCK_EV_SEND:
                        r = build_sock_ev_send((const SockEvSend *)ev);
                        break;
                case SOCK_EV_RECV:
                        r = build_sock_ev_recv((const SockEvRecv *)ev);
                        break;
                case SOCK_EV_SENDTO:
                        r = build_sock_ev_sendto((const SockEvSendto *)ev);
                        break;
                case SOCK_EV_RECVFROM:
                        r = build_sock_ev_recvfrom((const SockEvRecvfrom *)ev);
                        break;
                case SOCK_EV_SENDMSG:
                        r = build_sock_ev_sendmsg((const SockEvSendmsg *)ev);
                        break;
                case SOCK_EV_RECVMSG:
                        r = build_sock_ev_recvmsg((const SockEvRecvmsg *)ev);
                        break;
#if !defined(__ANDROID__) || __ANDROID_API__ >= 21
                case SOCK_EV_SENDMMSG:
                        r = build_sock_ev_sendmmsg((const SockEvSendmmsg *)ev);
                        break;
                case SOCK_EV_RECVMMSG:
                        r = build_sock_ev_recvmmsg((const SockEvRecvmmsg *)ev);
                        break;
#endif
                case SOCK_EV_GETSOCKNAME:
                        r = build_sock_ev_getsockname(
                            (const SockEvGetsockname *)ev);
                        break;
                case SOCK_EV_GETPEERNAME:
                        r = build_sock_ev_getpeername(
                            (const SockEvGetpeername *)ev);
                        break;
                case SOCK_EV_SOCKATMARK:
                        r = build_sock_ev_sockatmark(
                            (const SockEvSockatmark *)ev);
                        break;
                case SOCK_EV_ISFDTYPE:
                        r = build_sock_ev_isfdtype((const SockEvIsfdtype *)ev);
                        break;
                case SOCK_EV_WRITE:
                        r = build_sock_ev_write((const SockEvWrite *)ev);
                        break;
                case SOCK_EV_READ:
                        r = build_sock_ev_read((const SockEvRead *)ev);
                        break;
                case SOCK_EV_CLOSE:
                        r = build_sock_ev_close((const SockEvClose *)ev);
                        break;
                case SOCK_EV_DUP:
                        r = build_sock_ev_dup((const SockEvDup *)ev);
                        break;
                case SOCK_EV_DUP2:
                        r = build_sock_ev_dup2((const SockEvDup2 *)ev);
                        break;
                case SOCK_EV_DUP3:
                        r = build_sock_ev_dup3((const SockEvDup3 *)ev);
                        break;
                case SOCK_EV_WRITEV:
                        r = build_sock_ev_writev((const SockEvWritev *)ev);
                        break;
                case SOCK_EV_READV:
                        r = build_sock_ev_readv((const SockEvReadv *)ev);
                        break;
                case SOCK_EV_IOCTL:
                        r = build_sock_ev_ioctl((const SockEvIoctl *)ev);
                        break;
                case SOCK_EV_SENDFILE:
                        r = build_sock_ev_sendfile((const SockEvSendfile *)ev);
                        break;
                case SOCK_EV_POLL:
                        r = build_sock_ev_poll((const SockEvPoll *)ev);
                        break;
                case SOCK_EV_PPOLL:
                        r = build_sock_ev_ppoll((const SockEvPpoll *)ev);
                        break;
                case SOCK_EV_SELECT:
                        r = build_sock_ev_select((const SockEvSelect *)ev);
                        break;
                case SOCK_EV_PSELECT:
                        r = build_sock_ev_pselect((const SockEvPselect *)ev);
                        break;
                case SOCK_EV_FCNTL:
                        r = build_sock_ev_fcntl((const SockEvFcntl *)ev);
                        break;
                case SOCK_EV_EPOLL_CTL:
                        r = build_sock_ev_epoll_ctl((const SockEvEpollCtl *)ev);
                        break;
                case SOCK_EV_EPOLL_WAIT:
                        r = build_sock_ev_epoll_wait(
                            (const SockEvEpollWait *)ev);
                        break;
                case SOCK_EV_EPOLL_PWAIT:
                        r = build_sock_ev_epoll_pwait(
                            (const SockEvEpollPwait *)ev);
                        break;
                case SOCK_EV_FDOPEN:
                        r = build_sock_ev_fdopen((const SockEvFdopen *)ev);
                        break;
                case SOCK_EV_TCP_INFO:
                        r = build_sock_ev_tcp_info((const SockEvTcpInfo *)ev);
                        break;
        }
        return r;
}

/* Public functions */

char *alloc_sock_ev_json(const SockEvent *ev) {
        json_t *json_ev = build_sock_ev(ev);
        if (!json_ev) goto error;
        char *json_string = json_dumps(json_ev, 0);
        json_decref(json_ev);
        return json_string;
error:
        LOG_FUNC_ERROR;
        return NULL;
}
