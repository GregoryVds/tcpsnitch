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


  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(8000);
  inet_aton("127.0.0.1", &addr.sin_addr);

  if (!(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) ==0))
    return(EXIT_FAILURE);


  int data = 42;
  if (!(write(sock, &data, sizeof(data)) >0))
    return(EXIT_FAILURE);

          
  return(EXIT_SUCCESS);
}
