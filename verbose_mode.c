#include "verbose_mode.h"
#include "lib.h"

static void output_ev_socket(TcpEvSocket *ev);
static void output_ev_bind(TcpEvBind *ev);
static void output_ev_connect(TcpEvConnect*ev);
static void output_ev_shutdown(TcpEvShutdown*ev);
static void output_ev_listen(TcpEvListen *ev);
static void output_ev_setsockopt(TcpEvSetsockopt *ev);
static void output_ev_send(TcpEvSend *ev);
static void output_ev_recv(TcpEvRecv *ev);
static void output_ev_sendto(TcpEvSendto *ev);
static void output_ev_recvfrom(TcpEvRecvfrom *ev);
static void output_ev_sendmsg(TcpEvSendmsg *ev);
static void output_ev_recvmsg(TcpEvRecvmsg *ev);
static void output_ev_write(TcpEvWrite *ev);
static void output_ev_read(TcpEvRead *ev);
static void output_ev_close(TcpEvClose *ev);
static void output_ev_writev(TcpEvWritev *ev);
static void output_ev_readv(TcpEvReadv *ev);
static void output_ev_tcpinfo(TcpEvTcpInfo *ev);

static void output_ev_socket(TcpEvSocket *ev) {
}

static void output_ev_bind(TcpEvBind *ev) {
}

static void output_ev_connect(TcpEvConnect*ev) {
}

static void output_ev_shutdown(TcpEvShutdown*ev) {
}

static void output_ev_listen(TcpEvListen *ev) {
}

static void output_ev_setsockopt(TcpEvSetsockopt *ev) {
}

static void output_ev_send(TcpEvSend *ev) {
}

static void output_ev_recv(TcpEvRecv *ev) {
}

static void output_ev_sendto(TcpEvSendto *ev) {
}

static void output_ev_recvfrom(TcpEvRecvfrom *ev) {
}

static void output_ev_sendmsg(TcpEvSendmsg *ev) {
}

static void output_ev_recvmsg(TcpEvRecvmsg *ev) {
}

static void output_ev_write(TcpEvWrite *ev) {
}

static void output_ev_read(TcpEvRead *ev) {
}

static void output_ev_close(TcpEvClose *ev) {
}

static void output_ev_writev(TcpEvWritev *ev) {
}

static void output_ev_readv(TcpEvReadv *ev) {
}

static void output_ev_tcpinfo(TcpEvTcpInfo *ev) {
}

void output_event(TcpEvent *ev) {
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

