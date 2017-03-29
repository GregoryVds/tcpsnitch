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

static void output_ev_socket(const SockEvSocket *ev) {
        OUTPUT_EV("socket()=%d", ev->super.return_value);
}

static void output_ev_forked_socket(const SockEvForkedSocket *ev) {
        OUTPUT_EV("forked_socket()=%d", ev->super.return_value);
}

static void output_ev_bind(const SockEvBind *ev) {
        OUTPUT_EV("bind()=%d", ev->super.return_value);
}

static void output_ev_connect(const SockEvConnect *ev) {
        OUTPUT_EV("connect()=%d", ev->super.return_value);
}

static void output_ev_shutdown(const SockEvShutdown *ev) {
        OUTPUT_EV("shutdown()=%d", ev->super.return_value);
}

static void output_ev_listen(const SockEvListen *ev) {
        OUTPUT_EV("listen()=%d", ev->super.return_value);
}

static void output_ev_accept(const SockEvAccept *ev) {
        OUTPUT_EV("accept()=%d", ev->super.return_value);
}

static void output_ev_accept4(const SockEvAccept4 *ev) {
        OUTPUT_EV("accept4()=%d", ev->super.return_value);
}

static void output_ev_getsockopt(const SockEvGetsockopt *ev) {
        OUTPUT_EV("getsockopt()=%d", ev->super.return_value);
}

static void output_ev_setsockopt(const SockEvSetsockopt *ev) {
        OUTPUT_EV("setsockopt()=%d", ev->super.return_value);
}

static void output_ev_send(const SockEvSend *ev) {
        OUTPUT_EV("send()=%d", ev->super.return_value);
}

static void output_ev_recv(const SockEvRecv *ev) {
        OUTPUT_EV("recv()=%d", ev->super.return_value);
}

static void output_ev_sendto(const SockEvSendto *ev) {
        OUTPUT_EV("sendto()=%d", ev->super.return_value);
}

static void output_ev_recvfrom(const SockEvRecvfrom *ev) {
        OUTPUT_EV("recvfrom()=%d", ev->super.return_value);
}

static void output_ev_sendmsg(const SockEvSendmsg *ev) {
        OUTPUT_EV("sendmsg()=%d", ev->super.return_value);
}

static void output_ev_recvmsg(const SockEvRecvmsg *ev) {
        OUTPUT_EV("recvmsg()=%d", ev->super.return_value);
}

#if !defined(__ANDROID__) || __ANDROID_API__ >= 21
static void output_ev_sendmmsg(const SockEvSendmmsg *ev) {
        OUTPUT_EV("sendmmsg()=%d", ev->super.return_value);
}

static void output_ev_recvmmsg(const SockEvRecvmmsg *ev) {
        OUTPUT_EV("recvmmsg()=%d", ev->super.return_value);
}
#endif

static void output_ev_getsockname(const SockEvGetsockname *ev) {
        OUTPUT_EV("getsockname()=%d", ev->super.return_value);
}

static void output_ev_getpeername(const SockEvGetpeername *ev) {
        OUTPUT_EV("getpeername()=%d", ev->super.return_value);
}

static void output_ev_sockatmark(const SockEvSockatmark *ev) {
        OUTPUT_EV("sockatmark()=%d", ev->super.return_value);
}

static void output_ev_isfdtype(const SockEvIsfdtype *ev) {
        OUTPUT_EV("isfdtype()=%d", ev->super.return_value);
}

static void output_ev_write(const SockEvWrite *ev) {
        OUTPUT_EV("write()=%d", ev->super.return_value);
}

static void output_ev_read(const SockEvRead *ev) {
        OUTPUT_EV("read()=%d", ev->super.return_value);
}

static void output_ev_close(const SockEvClose *ev) {
        OUTPUT_EV("close()=%d", ev->super.return_value);
}

static void output_ev_dup(const SockEvDup *ev) {
        OUTPUT_EV("dup()=%d", ev->super.return_value);
}

static void output_ev_dup2(const SockEvDup2 *ev) {
        OUTPUT_EV("dup2()=%d", ev->super.return_value);
}

static void output_ev_dup3(const SockEvDup3 *ev) {
        OUTPUT_EV("dup3()=%d", ev->super.return_value);
}

static void output_ev_writev(const SockEvWritev *ev) {
        OUTPUT_EV("writev()=%d", ev->super.return_value);
}

static void output_ev_readv(const SockEvReadv *ev) {
        OUTPUT_EV("readv()=%d", ev->super.return_value);
}

static void output_ev_ioctl(const SockEvIoctl *ev) {
        OUTPUT_EV("iotctl()=%d", ev->super.return_value);
}

static void output_ev_sendfile(const SockEvSendfile *ev) {
        OUTPUT_EV("sendfile()=%d", ev->super.return_value);
}

static void output_ev_poll(const SockEvPoll *ev) {
        OUTPUT_EV("poll()=%d", ev->super.return_value);
}

static void output_ev_ppoll(const SockEvPpoll *ev) {
        OUTPUT_EV("ppoll()=%d", ev->super.return_value);
}

static void output_ev_select(const SockEvSelect *ev) {
        OUTPUT_EV("select()=%d", ev->super.return_value);
}

static void output_ev_pselect(const SockEvPselect *ev) {
        OUTPUT_EV("pselect()=%d", ev->super.return_value);
}

static void output_ev_tcpinfo(const SockEvTcpInfo *ev) {
        OUTPUT_EV("tcp_info=%d", ev->super.return_value);
}

static void output_ev_fcntl(const SockEvFcntl *ev) {
        OUTPUT_EV("fcntl=%d", ev->super.return_value);
}

static void output_ev_epoll_ctl(const SockEvEpollCtl *ev) {
        OUTPUT_EV("epoll_ctl=%d", ev->super.return_value);
}

static void output_ev_epoll_wait(const SockEvEpollWait *ev) {
        OUTPUT_EV("epoll_wait=%d", ev->super.return_value);
}

static void output_ev_epoll_pwait(const SockEvEpollPwait *ev) {
        OUTPUT_EV("epoll_pwait=%d", ev->super.return_value);
}

static void output_ev_fdopen(const SockEvFdopen *ev) {
        OUTPUT_EV("fdopen()=%d", ev->super.return_value);
}

void output_event(const SockEvent *ev) {
#ifndef __ANDROID__
        if (!_stdout) return;  // We don't bother handling a fdopen() fail.
#endif
        if (!conf_opt_v) return;

        switch (ev->type) {
                case SOCK_EV_SOCKET:
                        output_ev_socket((const SockEvSocket *)ev);
                        break;
                case SOCK_EV_FORKED_SOCKET:
                        output_ev_forked_socket((const SockEvForkedSocket *)ev);
                        break;
                case SOCK_EV_BIND:
                        output_ev_bind((const SockEvBind *)ev);
                        break;
                case SOCK_EV_CONNECT:
                        output_ev_connect((const SockEvConnect *)ev);
                        break;
                case SOCK_EV_SHUTDOWN:
                        output_ev_shutdown((const SockEvShutdown *)ev);
                        break;
                case SOCK_EV_LISTEN:
                        output_ev_listen((const SockEvListen *)ev);
                        break;
                case SOCK_EV_ACCEPT:
                        output_ev_accept((const SockEvAccept *)ev);
                        break;
                case SOCK_EV_ACCEPT4:
                        output_ev_accept4((const SockEvAccept4 *)ev);
                        break;
                case SOCK_EV_GETSOCKOPT:
                        output_ev_getsockopt((const SockEvGetsockopt *)ev);
                        break;
                case SOCK_EV_SETSOCKOPT:
                        output_ev_setsockopt((const SockEvSetsockopt *)ev);
                        break;
                case SOCK_EV_SEND:
                        output_ev_send((const SockEvSend *)ev);
                        break;
                case SOCK_EV_RECV:
                        output_ev_recv((const SockEvRecv *)ev);
                        break;
                case SOCK_EV_SENDTO:
                        output_ev_sendto((const SockEvSendto *)ev);
                        break;
                case SOCK_EV_RECVFROM:
                        output_ev_recvfrom((const SockEvRecvfrom *)ev);
                        break;
                case SOCK_EV_SENDMSG:
                        output_ev_sendmsg((const SockEvSendmsg *)ev);
                        break;
                case SOCK_EV_RECVMSG:
                        output_ev_recvmsg((const SockEvRecvmsg *)ev);
                        break;
#if !defined(__ANDROID__) || __ANDROID_API__ >= 21
                case SOCK_EV_SENDMMSG:
                        output_ev_sendmmsg((const SockEvSendmmsg *)ev);
                        break;
                case SOCK_EV_RECVMMSG:
                        output_ev_recvmmsg((const SockEvRecvmmsg *)ev);
                        break;
#endif
                case SOCK_EV_GETSOCKNAME:
                        output_ev_getsockname((const SockEvGetsockname *)ev);
                        break;
                case SOCK_EV_GETPEERNAME:
                        output_ev_getpeername((const SockEvGetpeername *)ev);
                        break;
                case SOCK_EV_SOCKATMARK:
                        output_ev_sockatmark((const SockEvSockatmark *)ev);
                        break;
                case SOCK_EV_ISFDTYPE:
                        output_ev_isfdtype((const SockEvIsfdtype *)ev);
                        break;
                case SOCK_EV_DUP:
                        output_ev_dup((const SockEvDup *)ev);
                        break;
                case SOCK_EV_DUP2:
                        output_ev_dup2((const SockEvDup2 *)ev);
                        break;
                case SOCK_EV_DUP3:
                        output_ev_dup3((const SockEvDup3 *)ev);
                        break;
                case SOCK_EV_WRITE:
                        output_ev_write((const SockEvWrite *)ev);
                        break;
                case SOCK_EV_READ:
                        output_ev_read((const SockEvRead *)ev);
                        break;
                case SOCK_EV_CLOSE:
                        output_ev_close((const SockEvClose *)ev);
                        break;
                case SOCK_EV_WRITEV:
                        output_ev_writev((const SockEvWritev *)ev);
                        break;
                case SOCK_EV_READV:
                        output_ev_readv((const SockEvReadv *)ev);
                        break;
                case SOCK_EV_IOCTL:
                        output_ev_ioctl((const SockEvIoctl *)ev);
                        break;
                case SOCK_EV_SENDFILE:
                        output_ev_sendfile((const SockEvSendfile *)ev);
                        break;
                case SOCK_EV_POLL:
                        output_ev_poll((const SockEvPoll *)ev);
                        break;
                case SOCK_EV_PPOLL:
                        output_ev_ppoll((const SockEvPpoll *)ev);
                        break;
                case SOCK_EV_SELECT:
                        output_ev_select((const SockEvSelect *)ev);
                        break;
                case SOCK_EV_PSELECT:
                        output_ev_pselect((const SockEvPselect *)ev);
                        break;
                case SOCK_EV_FCNTL:
                        output_ev_fcntl((const SockEvFcntl *)ev);
                        break;
                case SOCK_EV_EPOLL_CTL:
                        output_ev_epoll_ctl((const SockEvEpollCtl *)ev);
                        break;
                case SOCK_EV_EPOLL_WAIT:
                        output_ev_epoll_wait((const SockEvEpollWait *)ev);
                        break;
                case SOCK_EV_EPOLL_PWAIT:
                        output_ev_epoll_pwait((const SockEvEpollPwait *)ev);
                        break;
                case SOCK_EV_FDOPEN:
                        output_ev_fdopen((const SockEvFdopen *)ev);
                        break;
                case SOCK_EV_TCP_INFO:
                        output_ev_tcpinfo((const SockEvTcpInfo *)ev);
                        break;
        }
}
