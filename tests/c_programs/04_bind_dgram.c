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
  addr.sin_port = htons(55555);
  inet_aton("127.0.0.1", &addr.sin_addr);

  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    return(EXIT_FAILURE);
          
  return(EXIT_SUCCESS);
}
