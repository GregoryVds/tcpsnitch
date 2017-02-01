#define _GNU_SOURCE

#include <jansson.h>
#include <netdb.h>
#include "init.h"
#include "lib.h"
#include "logger.h"
#include "string_builders.h"
#include "json_builder.h"

/* Save reference to pointer with shorter name */
typedef int (*add_type)(json_t *o, const char *k, json_t *v);
static add_type add = &json_object_set_new;

static json_t *build_addr(const TcpAddr *addr) {
        json_t *json_addr = json_object();
        if (!json_addr) goto error;

        add(json_addr, "ip", json_string(addr->ip));
        add(json_addr, "port", json_string(addr->port));
        add(json_addr, "name", json_string(addr->name));
        add(json_addr, "serv", json_string(addr->serv));

        return json_addr;
error:
        LOG(ERROR, "json_object() failed.");
        LOG_FUNC_FAIL;
        return NULL;
}

static json_t *build_send_flags(const TcpSendFlags *flags) {
        json_t *json_flags = json_object();
        if (!json_flags) goto error;

        add(json_flags, "msg_confirm", json_boolean(flags->msg_confirm));
        add(json_flags, "msg_dontroute", json_boolean(flags->msg_dontroute));
        add(json_flags, "msg_dontwait", json_boolean(flags->msg_dontwait));
        add(json_flags, "msg_eor", json_boolean(flags->msg_eor));
        add(json_flags, "msg_more", json_boolean(flags->msg_more));
        add(json_flags, "msg_nosignal", json_boolean(flags->msg_nosignal));
        add(json_flags, "msg_oob", json_boolean(flags->msg_oob));

        return json_flags;
error:
        LOG(ERROR, "json_object() failed.");
        LOG_FUNC_FAIL;
        return NULL;
}

static json_t *build_recv_flags(const TcpRecvFlags *flags) {
        json_t *json_flags = json_object();
        if (!json_flags) goto error;

        add(json_flags, "msg_cmsg_cloexec",
            json_boolean(flags->msg_cmsg_cloexec));
        add(json_flags, "msg_dontwait", json_boolean(flags->msg_dontwait));
        add(json_flags, "msg_errqueue", json_boolean(flags->msg_errqueue));
        add(json_flags, "msg_oob", json_boolean(flags->msg_oob));
        add(json_flags, "msg_peek", json_boolean(flags->msg_peek));
        add(json_flags, "msg_trunc", json_boolean(flags->msg_trunc));
        add(json_flags, "msg_waitall", json_boolean(flags->msg_waitall));

        return json_flags;
error:
        LOG(ERROR, "json_object() failed.");
        LOG_FUNC_FAIL;
        return NULL;
}

static json_t *build_iovec(const TcpIovec *iovec) {
        json_t *json_iovec = json_object();
        if (!json_iovec) goto error;

        add(json_iovec, "iovec_count", json_integer(iovec->iovec_count));
        json_t *iovec_sizes = json_array();
        if (iovec_sizes) {
                for (int i = 0; i < iovec->iovec_count; i++) {
                        json_array_append_new(
                            iovec_sizes, json_integer(iovec->iovec_sizes[i]));
                }
        }
        add(json_iovec, "iovec_sizes", iovec_sizes);

        return json_iovec;
error:
        LOG(ERROR, "json_object() failed.");
        LOG_FUNC_FAIL;
        return NULL;
}

static json_t *build_msghdr(const TcpMsghdr *msg) {
        json_t *json_msghdr = json_object();
        if (!json_msghdr) goto error;

        add(json_msghdr, "control_data", json_boolean(msg->control_data));
        add(json_msghdr, "iovec", build_iovec(&msg->iovec));

        return json_msghdr;
error:
        LOG(ERROR, "json_object() failed.");
        LOG_FUNC_FAIL;
        return NULL;
}

static void build_shared_fields(json_t *json_ev, const TcpEvent *ev) {
        const char *type_str = string_from_tcp_event_type(ev->type);
        add(json_ev, "type", json_string(type_str));

        /* Time stamp */
        json_t *timestamp_json = json_object();
        if (timestamp_json) {
                add(timestamp_json, "sec", json_integer(ev->timestamp.tv_sec));
                add(timestamp_json, "usec",
                    json_integer(ev->timestamp.tv_usec));
        }
        add(json_ev, "timestamp", timestamp_json);

        /* Return value & err string */
        add(json_ev, "return_value", json_integer(ev->return_value));
        add(json_ev, "success", json_boolean(ev->success));
        add(json_ev, "error_str", json_string(ev->error_str));
}

#define DETAILS_FAILURE "json_object() failed. Cannot build event details."

#define BUILD_EV_PRELUDE()                                  \
        json_t *json_ev = json_object();                    \
        if (!json_ev) {                                     \
                LOG(ERROR, "json_object() failed.");        \
                LOG_FUNC_FAIL;                              \
                return NULL;                                \
        }                                                   \
        build_shared_fields(json_ev, (const TcpEvent *)ev); \
        json_t *json_details = json_object();               \
        if (json_details == NULL) {                         \
                LOG(ERROR, DETAILS_FAILURE);                \
                return json_ev;                             \
        }                                                   \
        add(json_ev, "details", json_details);

static json_t *build_tcp_ev_socket(const TcpEvSocket *ev) {
        BUILD_EV_PRELUDE()  // Instant json_t *json_ev & json_t *json_details
        char *dom_str = alloc_sock_domain_str(ev->domain);
        char *type_str = alloc_sock_type_str(ev->type);

        add(json_details, "domain", json_string(dom_str));
        add(json_details, "type", json_string(type_str));
        add(json_details, "protocol", json_integer(ev->protocol));
        add(json_details, "sock_cloexec", json_boolean(ev->sock_cloexec));
        add(json_details, "sock_nonblock", json_boolean(ev->sock_nonblock));

        free(dom_str);
        free(type_str);
        return json_ev;
}

static json_t *build_tcp_ev_bind(const TcpEvBind *ev) {
        BUILD_EV_PRELUDE()  // Instant json_t *json_ev & json_t *json_details

        add(json_details, "addr", build_addr(&ev->addr));
        add(json_details, "force_bind", json_boolean(ev->force_bind));

        return json_ev;
}

static json_t *build_tcp_ev_connect(const TcpEvConnect *ev) {
        BUILD_EV_PRELUDE()  // Instant json_t *json_ev & json_t *json_details

        add(json_details, "addr", build_addr(&ev->addr));

        return json_ev;
}

static json_t *build_tcp_ev_shutdown(const TcpEvShutdown *ev) {
        BUILD_EV_PRELUDE()  // Instant json_t *json_ev & json_t *json_details

        add(json_details, "shut_rd", json_boolean(ev->shut_rd));
        add(json_details, "shut_wr", json_boolean(ev->shut_wr));

        return json_ev;
}

static json_t *build_tcp_ev_listen(const TcpEvListen *ev) {
        BUILD_EV_PRELUDE()  // Instant json_t *json_ev & json_t *json_details

        add(json_details, "backlog", json_integer(ev->backlog));

        return json_ev;
}

static json_t *build_tcp_ev_accept(const TcpEvAccept *ev) {
        BUILD_EV_PRELUDE()  // Instant json_t *json_ev & json_t *json_details

        add(json_details, "addr", build_addr(&ev->addr));

        return json_ev;
}

static json_t *build_tcp_ev_setsockopt(const TcpEvSetsockopt *ev) {
        BUILD_EV_PRELUDE()  // Instant json_t *json_ev & json_t *json_details

        add(json_details, "level", json_integer(ev->level));
        add(json_details, "level_str", json_string(ev->level_str));
        add(json_details, "optname", json_integer(ev->optname));
        add(json_details, "optname_str", json_string(ev->optname_str));

        return json_ev;
}

static json_t *build_tcp_ev_send(const TcpEvSend *ev) {
        BUILD_EV_PRELUDE()  // Instant json_t *json_ev & json_t *json_details

        add(json_details, "bytes", json_integer(ev->bytes));
        add(json_details, "flags", build_send_flags(&(ev->flags)));

        return json_ev;
}

static json_t *build_tcp_ev_recv(const TcpEvRecv *ev) {
        BUILD_EV_PRELUDE()  // Instant json_t *json_ev & json_t *json_details

        add(json_details, "bytes", json_integer(ev->bytes));
        add(json_details, "flags", build_recv_flags(&(ev->flags)));

        return json_ev;
}

static json_t *build_tcp_ev_sendto(const TcpEvSendto *ev) {
        BUILD_EV_PRELUDE()  // Instant json_t *json_ev & json_t *json_details
        // char *addr_str = alloc_host_str(&(ev->addr));
        // char *port_str = alloc_port_str(&(ev->addr));

        // add(json_details, "addr", json_string(addr_str));
        // add(json_details, "port", json_string(port_str));
        add(json_details, "bytes", json_integer(ev->bytes));
        add(json_details, "flags", build_send_flags(&(ev->flags)));

        // free(addr_str);
        // free(port_str);
        return json_ev;
}

static json_t *build_tcp_ev_recvfrom(const TcpEvRecvfrom *ev) {
        BUILD_EV_PRELUDE()  // Instant json_t *json_ev & json_t *json_details
        // char *addr_str = alloc_host_str(&(ev->addr));
        // char *port_str = alloc_port_str(&(ev->addr));

        // add(json_details, "addr", json_string(addr_str));
        // add(json_details, "port", json_string(port_str));
        add(json_details, "bytes", json_integer(ev->bytes));
        add(json_details, "flags", build_recv_flags(&(ev->flags)));

        // free(addr_str);
        // free(port_str);
        return json_ev;
}

static json_t *build_tcp_ev_sendmsg(const TcpEvSendmsg *ev) {
        BUILD_EV_PRELUDE()  // Instant json_t *json_ev & json_t *json_details

        add(json_details, "bytes", json_integer(ev->bytes));
        add(json_details, "flags", build_send_flags(&(ev->flags)));
        add(json_details, "msghdr", build_msghdr(&(ev->msghdr)));

        return json_ev;
}

static json_t *build_tcp_ev_recvmsg(const TcpEvRecvmsg *ev) {
        BUILD_EV_PRELUDE()  // Instant json_t *json_ev & json_t *json_details

        add(json_details, "bytes", json_integer(ev->bytes));
        add(json_details, "flags", build_recv_flags(&(ev->flags)));
        add(json_details, "msghdr", build_msghdr(&(ev->msghdr)));

        return json_ev;
}

#if !defined(__ANDROID__) || __ANDROID_API__ >= 21
static json_t *build_tcp_ev_sendmmsg(const TcpEvSendmmsg *ev) {
        BUILD_EV_PRELUDE()  // Instant json_t *json_ev & json_t *json_details
        return json_ev;
}

static json_t *build_tcp_ev_recvmmsg(const TcpEvRecvmmsg *ev) {
        BUILD_EV_PRELUDE()  // Instant json_t *json_ev & json_t *json_details
        return json_ev;
}
#endif

static json_t *build_tcp_ev_write(const TcpEvWrite *ev) {
        BUILD_EV_PRELUDE()  // Instant json_t *json_ev & json_t *json_details

        add(json_details, "bytes", json_integer(ev->bytes));

        return json_ev;
}

static json_t *build_tcp_ev_read(const TcpEvRead *ev) {
        BUILD_EV_PRELUDE()  // Instant json_t *json_ev & json_t *json_details

        add(json_details, "bytes", json_integer(ev->bytes));

        return json_ev;
}

static json_t *build_tcp_ev_close(const TcpEvClose *ev) {
        BUILD_EV_PRELUDE()  // Instant json_t *json_ev & json_t *json_details

        add(json_details, "detected", json_boolean(ev->detected));

        return json_ev;
}

static json_t *build_tcp_ev_writev(const TcpEvWritev *ev) {
        BUILD_EV_PRELUDE()  // Instant json_t *json_ev & json_t *json_details

        add(json_details, "bytes", json_integer(ev->bytes));
        add(json_details, "iovec", build_iovec(&ev->iovec));

        return json_ev;
}

static json_t *build_tcp_ev_readv(const TcpEvReadv *ev) {
        BUILD_EV_PRELUDE()  // Instant json_t *json_ev & json_t *json_details

        add(json_details, "bytes", json_integer(ev->bytes));
        add(json_details, "iovec", build_iovec(&ev->iovec));

        return json_ev;
}

static json_t *build_tcp_ev_tcp_info(const TcpEvTcpInfo *ev) {
        BUILD_EV_PRELUDE()  // Instant json_t *json_ev & json_t *json_details
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

static json_t *build_tcp_ev(const TcpEvent *ev) {
        json_t *r;
        switch (ev->type) {
                case TCP_EV_SOCKET:
                        r = build_tcp_ev_socket((const TcpEvSocket *)ev);
                        break;
                case TCP_EV_BIND:
                        r = build_tcp_ev_bind((const TcpEvBind *)ev);
                        break;
                case TCP_EV_CONNECT:
                        r = build_tcp_ev_connect((const TcpEvConnect *)ev);
                        break;
                case TCP_EV_SHUTDOWN:
                        r = build_tcp_ev_shutdown((const TcpEvShutdown *)ev);
                        break;
                case TCP_EV_LISTEN:
                        r = build_tcp_ev_listen((const TcpEvListen *)ev);
                        break;
                case TCP_EV_ACCEPT:
                        r = build_tcp_ev_accept((const TcpEvAccept *)ev);
                        break;
                case TCP_EV_SETSOCKOPT:
                        r = build_tcp_ev_setsockopt(
                            (const TcpEvSetsockopt *)ev);
                        break;
                case TCP_EV_SEND:
                        r = build_tcp_ev_send((const TcpEvSend *)ev);
                        break;
                case TCP_EV_RECV:
                        r = build_tcp_ev_recv((const TcpEvRecv *)ev);
                        break;
                case TCP_EV_SENDTO:
                        r = build_tcp_ev_sendto((const TcpEvSendto *)ev);
                        break;
                case TCP_EV_RECVFROM:
                        r = build_tcp_ev_recvfrom((const TcpEvRecvfrom *)ev);
                        break;
                case TCP_EV_SENDMSG:
                        r = build_tcp_ev_sendmsg((const TcpEvSendmsg *)ev);
                        break;
                case TCP_EV_RECVMSG:
                        r = build_tcp_ev_recvmsg((const TcpEvRecvmsg *)ev);
                        break;
#if !defined(__ANDROID__) || __ANDROID_API__ >= 21
                case TCP_EV_SENDMMSG:
                        r = build_tcp_ev_sendmmsg((const TcpEvSendmmsg *)ev);
                        break;
                case TCP_EV_RECVMMSG:
                        r = build_tcp_ev_recvmmsg((const TcpEvRecvmmsg *)ev);
                        break;
#endif
                case TCP_EV_WRITE:
                        r = build_tcp_ev_write((const TcpEvWrite *)ev);
                        break;
                case TCP_EV_READ:
                        r = build_tcp_ev_read((const TcpEvRead *)ev);
                        break;
                case TCP_EV_CLOSE:
                        r = build_tcp_ev_close((const TcpEvClose *)ev);
                        break;
                case TCP_EV_WRITEV:
                        r = build_tcp_ev_writev((const TcpEvWritev *)ev);
                        break;
                case TCP_EV_READV:
                        r = build_tcp_ev_readv((const TcpEvReadv *)ev);
                        break;
                case TCP_EV_TCP_INFO:
                        r = build_tcp_ev_tcp_info((const TcpEvTcpInfo *)ev);
                        break;
        }
        return r;
}

/* Public functions */

char *alloc_tcp_ev_json(const TcpEvent *ev) {
        json_t *json_ev = build_tcp_ev(ev);
        if (!json_ev) goto error;
        size_t flags = conf_opt_p ? JSON_INDENT(2) : 0; 
        char *json_string = json_dumps(json_ev, flags);
        json_decref(json_ev);
        return json_string;
error:
        LOG_FUNC_FAIL;
        return NULL;
}

