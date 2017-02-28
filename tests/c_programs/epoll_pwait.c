#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/unistd.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
  int sock;
  if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
    fprintf(stderr, "socket() failed: %s", strerror(errno));
    return(EXIT_FAILURE);
  }

  int efd = epoll_create1(0);
  struct epoll_event event;
  event.data.fd = sock;
  event.events = EPOLLIN|EPOLLOUT;
  if (epoll_ctl(efd, EPOLL_CTL_ADD, sock, &event) < 0) {
    fprintf(stderr, "epoll_ctl() failed: %s", strerror(errno));
    return(EXIT_FAILURE);
  }

  struct epoll_event events[2];
  if (epoll_pwait(efd, events, 2, 0, NULL) < 0) {
    fprintf(stderr, "epoll_pwait() failed: %s", strerror(errno));
    return(EXIT_FAILURE);
  }
          
  return(EXIT_SUCCESS);
}
