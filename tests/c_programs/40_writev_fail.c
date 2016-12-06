#include <sys/socket.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/sendfile.h>
#include <poll.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/unistd.h>
#include <sys/fcntl.h>
#include <string.h>

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

  if (writev(sock, iov, -1) != -1)
    return(EXIT_FAILURE);
          
  return(EXIT_SUCCESS);
}
