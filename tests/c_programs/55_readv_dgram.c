#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/unistd.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
  int sock;
  if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    return(EXIT_FAILURE);

  char iovec_buf0[20];
  char iovec_buf1[30];
  char iovec_buf2[40];
  struct iovec iovec[3];

  iovec[0].iov_base = iovec_buf0;
  iovec[0].iov_len = sizeof(iovec_buf0);
  iovec[1].iov_base = iovec_buf1;
  iovec[1].iov_len = sizeof(iovec_buf1);
  iovec[2].iov_base = iovec_buf2;
  iovec[2].iov_len = sizeof(iovec_buf2);

  fcntl(sock, F_SETFL, O_NONBLOCK);
  if (readv(sock, iovec, sizeof(iovec)/sizeof(struct iovec)) != -1)
    return(EXIT_FAILURE);
          
  return(EXIT_SUCCESS);
}
