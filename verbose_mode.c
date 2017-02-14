#define _GNU_SOURCE

#include "verbose_mode.h"
#ifdef __ANDROID__
#include <android/log.h>
#endif
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include "constants.h"
#include "init.h"
#include "lib.h"
#include "logger.h"

#ifdef __ANDROID__
#define OUTPUT_EV(format, args...) \
        __android_log_print(ANDROID_LOG_VERBOSE, "tcpsnitch", format, ##args);

#else  // Not Android
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
#endif  // #ifdef __ANDROID__

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

static void output_ev_getsockopt(const TcpEvGetsockopt *ev) {
        OUTPUT_EV("getsockopt()=%d", ev->super.return_value);
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

#if !defined(__ANDROID__) || __ANDROID_API__ >= 21
static void output_ev_sendmmsg(const TcpEvSendmmsg *ev) {
        OUTPUT_EV("sendmmsg()=%d", ev->super.return_value);
}

static void output_ev_recvmmsg(const TcpEvRecvmmsg *ev) {
        OUTPUT_EV("recvmmsg()=%d", ev->super.return_value);
}
#endif

static void output_ev_getsockname(const TcpEvGetsockname *ev) {
        OUTPUT_EV("getsockname()=%d", ev->super.return_value);
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

static void output_ev_dup(const TcpEvDup *ev) {
        OUTPUT_EV("dup()=%d", ev->super.return_value);
}

static void output_ev_dup2(const TcpEvDup2 *ev) {
        OUTPUT_EV("dup2()=%d", ev->super.return_value);
}

static void output_ev_dup3(const TcpEvDup3 *ev) {
        OUTPUT_EV("dup3()=%d", ev->super.return_value);
}

static void output_ev_writev(const TcpEvWritev *ev) {
        OUTPUT_EV("writev()=%d", ev->super.return_value);
}

static void output_ev_readv(const TcpEvReadv *ev) {
        OUTPUT_EV("readv()=%d", ev->super.return_value);
}

static void output_ev_ioctl(const TcpEvIoctl *ev) {
        OUTPUT_EV("iotctl()=%d", ev->super.return_value);
}

static void output_ev_sendfile(const TcpEvSendfile *ev) {
        OUTPUT_EV("sendfile()=%d", ev->super.return_value);
}

static void output_ev_poll(const TcpEvPoll *ev) {
        OUTPUT_EV("poll()=%d", ev->super.return_value);
}

static void output_ev_ppoll(const TcpEvPpoll *ev) {
        OUTPUT_EV("ppoll()=%d", ev->super.return_value);
}

static void output_ev_select(const TcpEvSelect *ev) {
        OUTPUT_EV("select()=%d", ev->super.return_value);
}

static void output_ev_pselect(const TcpEvPselect *ev) {
        OUTPUT_EV("pselect()=%d", ev->super.return_value);
}

static void output_ev_tcpinfo(const TcpEvTcpInfo *ev) {
        OUTPUT_EV("tcp_info=%d", ev->super.return_value);
}

void output_event(const TcpEvent *ev) {
#ifndef __ANDROID__
        if (!_stdout) return;  // We don't bother handling a fdopen() fail.
#endif
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
                case TCP_EV_GETSOCKOPT:
                        output_ev_getsockopt((const TcpEvGetsockopt *)ev);
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
#if !defined(__ANDROID__) || __ANDROID_API__ >= 21
                case TCP_EV_SENDMMSG:
                        output_ev_sendmmsg((const TcpEvSendmmsg *)ev);
                        break;
                case TCP_EV_RECVMMSG:
                        output_ev_recvmmsg((const TcpEvRecvmmsg *)ev);
                        break;
#endif
		case TCP_EV_GETSOCKNAME:
			output_ev_getsockname((const TcpEvGetsockname *)ev);
			break;
                case TCP_EV_DUP:
                        output_ev_dup((const TcpEvDup *)ev);
                        break;
                case TCP_EV_DUP2:
                        output_ev_dup2((const TcpEvDup2 *)ev);
                        break;
                case TCP_EV_DUP3:
                        output_ev_dup3((const TcpEvDup3 *)ev);
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
                case TCP_EV_IOCTL:
                        output_ev_ioctl((const TcpEvIoctl *)ev);
                        break;
	        case TCP_EV_SENDFILE:
                        output_ev_sendfile((const TcpEvSendfile *)ev);
                        break;
                case TCP_EV_POLL:
                        output_ev_poll((const TcpEvPoll *)ev);
                        break;
                case TCP_EV_PPOLL:
                        output_ev_ppoll((const TcpEvPpoll *)ev);
                        break;
                case TCP_EV_SELECT:
                        output_ev_select((const TcpEvSelect *)ev);
                        break;
                case TCP_EV_PSELECT:
                        output_ev_pselect((const TcpEvPselect *)ev);
                        break;
                case TCP_EV_TCP_INFO:
                        output_ev_tcpinfo((const TcpEvTcpInfo *)ev);
                        break;
        }
}
