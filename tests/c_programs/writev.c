#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/unistd.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
  int sock;
  if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    return(EXIT_FAILURE);

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(8000);
  inet_aton("127.0.0.1", &addr.sin_addr);

  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    return(EXIT_FAILURE);

  char *iovec_buf0 = "short string\n";
  char *iovec_buf1 = "This is a longer string\n";
  char *iovec_buf2 = "This is the longest string in this example\n";

  struct iovec iovec[3];
  iovec[0].iov_base = iovec_buf0;
  iovec[0].iov_len = strlen(iovec_buf0);
  iovec[1].iov_base = iovec_buf1;
  iovec[1].iov_len = strlen(iovec_buf1);
  iovec[2].iov_base = iovec_buf2;
  iovec[2].iov_len = strlen(iovec_buf2);

  if (writev(sock, iovec, sizeof(iovec)/sizeof(struct iovec)) < 0)
    return(EXIT_FAILURE);
          
  return(EXIT_SUCCESS);
}
