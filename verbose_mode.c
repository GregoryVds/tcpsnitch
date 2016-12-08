#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include "config.h"
#include "init.h"
#include "lib.h"
#include "logger.h"
#include "verbose_mode.h"

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

static void output_ev_socket(TcpEvSocket *ev) {
        OUTPUT_EV("socket()=%d", ev->super.return_value);
}

static void output_ev_bind(TcpEvBind *ev) {
        OUTPUT_EV("bind()=%d", ev->super.return_value);
}

static void output_ev_connect(TcpEvConnect *ev) {
        OUTPUT_EV("connect()=%d", ev->super.return_value);
}

static void output_ev_shutdown(TcpEvShutdown *ev) {
        OUTPUT_EV("shutdown()=%d", ev->super.return_value);
}

static void output_ev_listen(TcpEvListen *ev) {
        OUTPUT_EV("listen()=%d", ev->super.return_value);
}

static void output_ev_setsockopt(TcpEvSetsockopt *ev) {
        OUTPUT_EV("setsockopt()=%d", ev->super.return_value);
}

static void output_ev_send(TcpEvSend *ev) {
        OUTPUT_EV("send()=%d", ev->super.return_value);
}

static void output_ev_recv(TcpEvRecv *ev) {
        OUTPUT_EV("recv()=%d", ev->super.return_value);
}

static void output_ev_sendto(TcpEvSendto *ev) {
        OUTPUT_EV("sendto()=%d", ev->super.return_value);
}

static void output_ev_recvfrom(TcpEvRecvfrom *ev) {
        OUTPUT_EV("recvfrom()=%d", ev->super.return_value);
}

static void output_ev_sendmsg(TcpEvSendmsg *ev) {
        OUTPUT_EV("sendmsg()=%d", ev->super.return_value);
}

static void output_ev_recvmsg(TcpEvRecvmsg *ev) {
        OUTPUT_EV("recvmsg()=%d", ev->super.return_value);
}

static void output_ev_write(TcpEvWrite *ev) {
        OUTPUT_EV("write()=%d", ev->super.return_value);
}

static void output_ev_read(TcpEvRead *ev) {
        OUTPUT_EV("read()=%d", ev->super.return_value);
}

static void output_ev_close(TcpEvClose *ev) {
        OUTPUT_EV("close()=%d", ev->super.return_value);
}

static void output_ev_writev(TcpEvWritev *ev) {
        OUTPUT_EV("writev()=%d", ev->super.return_value);
}

static void output_ev_readv(TcpEvReadv *ev) {
        OUTPUT_EV("readv()=%d", ev->super.return_value);
}

static void output_ev_tcpinfo(TcpEvTcpInfo *ev) {
        OUTPUT_EV("tcp_info=%d", ev->super.return_value);
}

void output_event(TcpEvent *ev) {
        if (!_stdout) return;  // We don't bother handling a fdopen() fail.
        if (!conf_opt_v) return;

        switch (ev->type) {
                case TCP_EV_SOCKET:
                        output_ev_socket((TcpEvSocket *)ev);
                        break;
                case TCP_EV_BIND:
                        output_ev_bind((TcpEvBind *)ev);
                        break;
                case TCP_EV_CONNECT:
                        output_ev_connect((TcpEvConnect *)ev);
                        break;
                case TCP_EV_SHUTDOWN:
                        output_ev_shutdown((TcpEvShutdown *)ev);
                        break;
                case TCP_EV_LISTEN:
                        output_ev_listen((TcpEvListen *)ev);
                        break;
                case TCP_EV_SETSOCKOPT:
                        output_ev_setsockopt((TcpEvSetsockopt *)ev);
                        break;
                case TCP_EV_SEND:
                        output_ev_send((TcpEvSend *)ev);
                        break;
                case TCP_EV_RECV:
                        output_ev_recv((TcpEvRecv *)ev);
                        break;
                case TCP_EV_SENDTO:
                        output_ev_sendto((TcpEvSendto *)ev);
                        break;
                case TCP_EV_RECVFROM:
                        output_ev_recvfrom((TcpEvRecvfrom *)ev);
                        break;
                case TCP_EV_SENDMSG:
                        output_ev_sendmsg((TcpEvSendmsg *)ev);
                        break;
                case TCP_EV_RECVMSG:
                        output_ev_recvmsg((TcpEvRecvmsg *)ev);
                        break;
                case TCP_EV_WRITE:
                        output_ev_write((TcpEvWrite *)ev);
                        break;
                case TCP_EV_READ:
                        output_ev_read((TcpEvRead *)ev);
                        break;
                case TCP_EV_CLOSE:
                        output_ev_close((TcpEvClose *)ev);
                        break;
                case TCP_EV_WRITEV:
                        output_ev_writev((TcpEvWritev *)ev);
                        break;
                case TCP_EV_READV:
                        output_ev_readv((TcpEvReadv *)ev);
                        break;
                case TCP_EV_TCP_INFO:
                        output_ev_tcpinfo((TcpEvTcpInfo *)ev);
                        break;
        }
}
