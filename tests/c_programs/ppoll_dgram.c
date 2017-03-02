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
  int sock1, sock2;
  if ((sock1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    return(EXIT_FAILURE);
  if ((sock2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    return(EXIT_FAILURE);

  struct pollfd pollfds[2];
  pollfds[0].fd = sock1;
  pollfds[0].events = POLLHUP;
  pollfds[1].fd = sock2;
  pollfds[1].events = POLLIN;

  struct timespec timeout;
  timeout.tv_sec = 1;
  timeout.tv_nsec = 1000;

  if (ppoll(pollfds, sizeof(pollfds)/sizeof(struct pollfd), &timeout, NULL) < 0) {
    fprintf(stderr, "ppoll() failed: %s\n.", strerror(errno));
    return(EXIT_FAILURE);
  }
          
  return(EXIT_SUCCESS);
}
