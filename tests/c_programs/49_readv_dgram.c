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

  char buf0[20];
  char buf1[30];
  char buf2[40];
  struct iovec iov[3];

  iov[0].iov_base = buf0;
  iov[0].iov_len = sizeof(buf0);
  iov[1].iov_base = buf1;
  iov[1].iov_len = sizeof(buf1);
  iov[2].iov_base = buf2;
  iov[2].iov_len = sizeof(buf2);

  fcntl(sock, F_SETFL, O_NONBLOCK);
  if (readv(sock, iov, sizeof(iov)/sizeof(struct iovec)) != -1)
    return(EXIT_FAILURE); 
          
  return(EXIT_SUCCESS);
}
