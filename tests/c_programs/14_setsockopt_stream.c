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
  if (!((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) >-1))
    return(EXIT_FAILURE);


  int optval = 1;
  if (!(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, 
                   sizeof(optval)) ==0)) {
    return(EXIT_FAILURE);
  }

          
  return(EXIT_SUCCESS);
}
