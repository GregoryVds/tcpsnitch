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

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(8000);
  inet_aton("127.0.0.1", &addr.sin_addr);

  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    return(EXIT_FAILURE);

  char *buf0 = "short string\n";
  char *buf1 = "This is a longer string\n";
  char *buf2 = "This is the longest string in this example\n";

  struct iovec iov[3];
  iov[0].iov_base = buf0;
  iov[0].iov_len = strlen(buf0);
  iov[1].iov_base = buf1;
  iov[1].iov_len = strlen(buf1);
  iov[2].iov_base = buf2;
  iov[2].iov_len = strlen(buf2);

  if (writev(sock, iov, sizeof(iov)/sizeof(struct iovec)) < 0)
    return(EXIT_FAILURE);
          
  return(EXIT_SUCCESS);
}
