#define _GNU_SOURCE

#include "verbose_mode.h"
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include "constants.h"
#include "init.h"
#include "lib.h"
#include "logger.h"

#define BUF_SIZE 512

#define MKSTR(var, format, args...)                                 \
        char var[BUF_SIZE];                                         \
        if (snprintf(var, sizeof(var), format, ##args) >= BUF_SIZE) \
                LOG(ERROR, "snprintf() failed. Truncated");

#define STDOUT(format, args...)               \
        MKSTR(_str, format, ##args);          \
        if (_stdout)                          \
                fprintf(_stdout, "%s", _str); \
        else                                  \
                write(STDOUT_FD, _str, sizeof(_str));

#define OUTPUT_EV(format, args...)  \
        MKSTR(_ev, format, ##args); \
        STDOUT("[pid %d] %s\n", getpid(), _ev);

static void output_ev_socket(const TcpEvSocket *ev) {
        OUTPUT_EV("socket()=%d", ev->super.return_value);
}

static void output_ev_bind(const TcpEvBind *ev) {
        OUTPUT_EV("bind()=%d", ev->super.return_value);
}

static void output_ev_connect(const TcpEvConnect *ev) {
        OUTPUT_EV("connect()=%d", ev->super.return_value);
}

static void output_ev_shutdown(const TcpEvShutdown *ev) {
        OUTPUT_EV("shutdown()=%d", ev->super.return_value);
}

static void output_ev_listen(const TcpEvListen *ev) {
        OUTPUT_EV("listen()=%d", ev->super.return_value);
}

static void output_ev_accept(const TcpEvAccept *ev) {
        OUTPUT_EV("accept()=%d", ev->super.return_value);
}

static void output_ev_setsockopt(const TcpEvSetsockopt *ev) {
        OUTPUT_EV("setsockopt()=%d", ev->super.return_value);
}

static void output_ev_send(const TcpEvSend *ev) {
        OUTPUT_EV("send()=%d", ev->super.return_value);
}

static void output_ev_recv(const TcpEvRecv *ev) {
        OUTPUT_EV("recv()=%d", ev->super.return_value);
}

static void output_ev_sendto(const TcpEvSendto *ev) {
        OUTPUT_EV("sendto()=%d", ev->super.return_value);
}

static void output_ev_recvfrom(const TcpEvRecvfrom *ev) {
        OUTPUT_EV("recvfrom()=%d", ev->super.return_value);
}

static void output_ev_sendmsg(const TcpEvSendmsg *ev) {
        OUTPUT_EV("sendmsg()=%d", ev->super.return_value);
}

static void output_ev_recvmsg(const TcpEvRecvmsg *ev) {
        OUTPUT_EV("recvmsg()=%d", ev->super.return_value);
}

static void output_ev_sendmmsg(const TcpEvSendmmsg *ev) {
        OUTPUT_EV("sendmmsg()=%d", ev->super.return_value);
}

static void output_ev_recvmmsg(const TcpEvRecvmmsg *ev) {
        OUTPUT_EV("recvmmsg()=%d", ev->super.return_value);
}

static void output_ev_write(const TcpEvWrite *ev) {
        OUTPUT_EV("write()=%d", ev->super.return_value);
}

static void output_ev_read(const TcpEvRead *ev) {
        OUTPUT_EV("read()=%d", ev->super.return_value);
}

static void output_ev_close(const TcpEvClose *ev) {
        OUTPUT_EV("close()=%d", ev->super.return_value);
}

static void output_ev_writev(const TcpEvWritev *ev) {
        OUTPUT_EV("writev()=%d", ev->super.return_value);
}

static void output_ev_readv(const TcpEvReadv *ev) {
        OUTPUT_EV("readv()=%d", ev->super.return_value);
}

static void output_ev_tcpinfo(const TcpEvTcpInfo *ev) {
        OUTPUT_EV("tcp_info=%d", ev->super.return_value);
}

void output_event(const TcpEvent *ev) {
        if (!_stdout) return;  // We don't bother handling a fdopen() fail.
        if (!conf_opt_v) return;

        switch (ev->type) {
                case TCP_EV_SOCKET:
                        output_ev_socket((const TcpEvSocket *)ev);
                        break;
                case TCP_EV_BIND:
                        output_ev_bind((const TcpEvBind *)ev);
                        break;
                case TCP_EV_CONNECT:
                        output_ev_connect((const TcpEvConnect *)ev);
                        break;
                case TCP_EV_SHUTDOWN:
                        output_ev_shutdown((const TcpEvShutdown *)ev);
                        break;
                case TCP_EV_LISTEN:
                        output_ev_listen((const TcpEvListen *)ev);
                        break;
                case TCP_EV_ACCEPT:
                        output_ev_accept((const TcpEvAccept *)ev);
                        break;
                case TCP_EV_SETSOCKOPT:
                        output_ev_setsockopt((const TcpEvSetsockopt *)ev);
                        break;
                case TCP_EV_SEND:
                        output_ev_send((const TcpEvSend *)ev);
                        break;
                case TCP_EV_RECV:
                        output_ev_recv((const TcpEvRecv *)ev);
                        break;
                case TCP_EV_SENDTO:
                        output_ev_sendto((const TcpEvSendto *)ev);
                        break;
                case TCP_EV_RECVFROM:
                        output_ev_recvfrom((const TcpEvRecvfrom *)ev);
                        break;
                case TCP_EV_SENDMSG:
                        output_ev_sendmsg((const TcpEvSendmsg *)ev);
                        break;
                case TCP_EV_RECVMSG:
                        output_ev_recvmsg((const TcpEvRecvmsg *)ev);
                        break;
                case TCP_EV_SENDMMSG:
                        output_ev_sendmmsg((const TcpEvSendmmsg *)ev);
                        break;
                case TCP_EV_RECVMMSG:
                        output_ev_recvmmsg((const TcpEvRecvmmsg *)ev);
                        break;
                case TCP_EV_WRITE:
                        output_ev_write((const TcpEvWrite *)ev);
                        break;
                case TCP_EV_READ:
                        output_ev_read((const TcpEvRead *)ev);
                        break;
                case TCP_EV_CLOSE:
                        output_ev_close((const TcpEvClose *)ev);
                        break;
                case TCP_EV_WRITEV:
                        output_ev_writev((const TcpEvWritev *)ev);
                        break;
                case TCP_EV_READV:
                        output_ev_readv((const TcpEvReadv *)ev);
                        break;
                case TCP_EV_TCP_INFO:
                        output_ev_tcpinfo((const TcpEvTcpInfo *)ev);
                        break;
        }
}
