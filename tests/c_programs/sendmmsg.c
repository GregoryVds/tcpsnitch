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

  char *iovec1_buf0 = "short string\n";
  char *iovec1_buf1 = "This is a longer string\n";
  char *iovec1_buf2 = "This is the longest string in this example\n";

  struct iovec iovec1[3];
  iovec1[0].iov_base = iovec1_buf0;
  iovec1[0].iov_len = strlen(iovec1_buf0);
  iovec1[1].iov_base = iovec1_buf1;
  iovec1[1].iov_len = strlen(iovec1_buf1);
  iovec1[2].iov_base = iovec1_buf2;
  iovec1[2].iov_len = strlen(iovec1_buf2);

  struct msghdr msg1;
  memset(&msg1, '\0', sizeof(msg1));
  msg1.msg_iov = iovec1;
  msg1.msg_iovlen = sizeof(iovec1)/sizeof(struct iovec);

  char *iovec2_buf0 = "short string\n";
  char *iovec2_buf1 = "This is a longer string\n";
  char *iovec2_buf2 = "This is the longest string in this example\n";

  struct iovec iovec2[3];
  iovec2[0].iov_base = iovec2_buf0;
  iovec2[0].iov_len = strlen(iovec2_buf0);
  iovec2[1].iov_base = iovec2_buf1;
  iovec2[1].iov_len = strlen(iovec2_buf1);
  iovec2[2].iov_base = iovec2_buf2;
  iovec2[2].iov_len = strlen(iovec2_buf2);

  struct msghdr msg2;
  memset(&msg2, '\0', sizeof(msg2));
  msg2.msg_iov = iovec2;
  msg2.msg_iovlen = sizeof(iovec2)/sizeof(struct iovec);

  struct mmsghdr mmsg[2];
	memset(mmsg, 0, sizeof(mmsg));
	mmsg[0].msg_hdr = msg1;
	mmsg[0].msg_len = 3;
	mmsg[1].msg_hdr = msg2;
	mmsg[1].msg_len = 3;

	if (sendmmsg(sock, mmsg, 2, 0) < 0)
		return(EXIT_FAILURE);
          
  return(EXIT_SUCCESS);
}
