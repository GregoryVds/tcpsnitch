#include <stdio.h>

#include "config.h"
#include "init.h"
#include "lib.h"
#include "logger.h"
#include "verbose_mode.h"

#define STDOUT(format, args...)                                                \
        {                                                                      \
                int _str_size = 1024;                                          \
                char _str[_str_size];                                          \
                if (snprintf(_str, sizeof(_str), format, ##args) >= _str_size) \
                        LOG(ERROR, "snprintf() failed. Truncated");            \
                if (_stdout)                                                   \
                        fprintf(_stdout, "%s", _str);                          \
                else                                                           \
                        write(STDOUT_FD, _str, sizeof(_str));                  \
        }

static const char *meta = "[Curl - pid 23344]";

static void output_ev_socket(TcpEvSocket *ev) {
        STDOUT("%s socket()=%d\n", meta, ev->super.return_value);
}

static void output_ev_bind(TcpEvBind *ev) {
        STDOUT("%s bind()=%d\n", meta, ev->super.return_value);
}

static void output_ev_connect(TcpEvConnect *ev) {
        STDOUT("%s connect()=%d\n", meta, ev->super.return_value);
}

static void output_ev_shutdown(TcpEvShutdown *ev) {
        STDOUT("%s shutdown()=%d\n", meta, ev->super.return_value);
}

static void output_ev_listen(TcpEvListen *ev) {
        STDOUT("%s listen()=%d\n", meta, ev->super.return_value);
}

static void output_ev_setsockopt(TcpEvSetsockopt *ev) {
        STDOUT("%s setsockopt()=%d\n", meta, ev->super.return_value);
}

static void output_ev_send(TcpEvSend *ev) {
        STDOUT("%s send()=%d\n", meta, ev->super.return_value);
}

static void output_ev_recv(TcpEvRecv *ev) {
        STDOUT("%s recv()=%d\n", meta, ev->super.return_value);
}

static void output_ev_sendto(TcpEvSendto *ev) {
        STDOUT("%s sendto()=%d\n", meta, ev->super.return_value);
}

static void output_ev_recvfrom(TcpEvRecvfrom *ev) {
        STDOUT("%s recvfrom()=%d\n", meta, ev->super.return_value);
}

static void output_ev_sendmsg(TcpEvSendmsg *ev) {
        STDOUT("%s sendmsg()=%d\n", meta, ev->super.return_value);
}

static void output_ev_recvmsg(TcpEvRecvmsg *ev) {
        STDOUT("%s recvmsg()=%d\n", meta, ev->super.return_value);
}

static void output_ev_write(TcpEvWrite *ev) {
        STDOUT("%s write()=%d\n", meta, ev->super.return_value);
}

static void output_ev_read(TcpEvRead *ev) {
        STDOUT("%s read()=%d\n", meta, ev->super.return_value);
}

static void output_ev_close(TcpEvClose *ev) {
        STDOUT("%s close()=%d\n", meta, ev->super.return_value);
}

static void output_ev_writev(TcpEvWritev *ev) {
        STDOUT("%s writev()=%d\n", meta, ev->super.return_value);
}

static void output_ev_readv(TcpEvReadv *ev) {
        STDOUT("%s readv()=%d\n", meta, ev->super.return_value);
}

static void output_ev_tcpinfo(TcpEvTcpInfo *ev) {
        STDOUT("%s tcp_info=%d\n", meta, ev->super.return_value);
}

void output_event(TcpEvent *ev) {
        if (!_stdout) return;  // We don't bother handling a fdopen() fail.
        if (!conf_verbosity) return;

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
