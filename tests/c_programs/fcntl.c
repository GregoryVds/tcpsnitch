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

  if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
    fprintf(stderr, "fcntl() failed: %s", strerror(errno));
    return(EXIT_FAILURE);
  }
          
  return(EXIT_SUCCESS);
}
