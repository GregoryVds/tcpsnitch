#include <stdio.h>

#include "verbose_mode.h"
#include "lib.h"
#include "init.h"

static const char *format = "%s %s\n";
static const char *meta = "[Curl - pid 23344]";
FILE* out_stream;
#define OUT_STREAM_FD 3

static void output_ev_socket(TcpEvSocket *ev) {
        const char *syscall = "socket()";
        fprintf(out_stream, format, meta, syscall);
}

static void output_ev_bind(TcpEvBind *ev) {
        const char *syscall = "bind()";
        fprintf(out_stream, format, meta, syscall);
}

static void output_ev_connect(TcpEvConnect *ev) {
        const char *syscall = "connect()";
        fprintf(out_stream, format, meta, syscall);
}

static void output_ev_shutdown(TcpEvShutdown *ev) {
        const char *syscall = "shutdown()";
        fprintf(out_stream, format, meta, syscall);
}

static void output_ev_listen(TcpEvListen *ev) {
        const char *syscall = "listen()";
        fprintf(out_stream, format, meta, syscall);
}

static void output_ev_setsockopt(TcpEvSetsockopt *ev) {
        const char *syscall = "setsockopt()";
        fprintf(out_stream, format, meta, syscall);
}

static void output_ev_send(TcpEvSend *ev) {
        const char *syscall = "send()";
        fprintf(out_stream, format, meta, syscall);
}

static void output_ev_recv(TcpEvRecv *ev) {
        const char *syscall = "recv()";
        fprintf(out_stream, format, meta, syscall);
}

static void output_ev_sendto(TcpEvSendto *ev) {
        const char *syscall = "sendto()";
        fprintf(out_stream, format, meta, syscall);
}

static void output_ev_recvfrom(TcpEvRecvfrom *ev) {
        const char *syscall = "recvfrom()";
        fprintf(out_stream, format, meta, syscall);
}

static void output_ev_sendmsg(TcpEvSendmsg *ev) {
        const char *syscall = "sendmsg()";
        fprintf(out_stream, format, meta, syscall);
}

static void output_ev_recvmsg(TcpEvRecvmsg *ev) {
        const char *syscall = "recvmsg()";
        fprintf(out_stream, format, meta, syscall);
}

static void output_ev_write(TcpEvWrite *ev) {
        const char *syscall = "write()";
        fprintf(out_stream, format, meta, syscall);
}

static void output_ev_read(TcpEvRead *ev) {
        const char *syscall = "read()";
        fprintf(out_stream, format, meta, syscall);
}

static void output_ev_close(TcpEvClose *ev) {
        const char *syscall = "close()";
        fprintf(out_stream, format, meta, syscall);
}

static void output_ev_writev(TcpEvWritev *ev) {
        const char *syscall = "writev()";
        fprintf(out_stream, format, meta, syscall);
}

static void output_ev_readv(TcpEvReadv *ev) {
        const char *syscall = "readv()";
        fprintf(out_stream, format, meta, syscall);
}

static void output_ev_tcpinfo(TcpEvTcpInfo *ev) {
        const char *syscall = "tcp_info";
        fprintf(out_stream, format, meta, syscall);
}

void output_event(TcpEvent *ev) {
        if (!conf_verbosity) return;
        if (!out_stream) out_stream = fdopen(OUT_STREAM_FD, "w");

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
