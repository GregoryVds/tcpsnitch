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
  if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    fprintf(stderr, "socket() failed: %s\n.", strerror(errno));
    return(EXIT_FAILURE);
  }

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(8000);
  inet_aton("127.0.0.1", &addr.sin_addr);

  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    fprintf(stderr, "connect() failed: %s\n.", strerror(errno)); 
    return(EXIT_FAILURE);
  }

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

  struct msghdr msg;
  memset(&msg, '\0', sizeof(msg));
  msg.msg_iov = iovec;
  msg.msg_iovlen = sizeof(iovec)/sizeof(struct iovec);

  fcntl(sock, F_SETFL, O_NONBLOCK);
  if (recvmsg(sock, &msg, 0) != -1)
    return(EXIT_FAILURE);
          
  return(EXIT_SUCCESS);
}
