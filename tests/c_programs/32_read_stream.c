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

  char *req = "GET / HTTP/1.0\r\n\r\n";
  send(sock, req, sizeof(char)*strlen(req), 0); 

  char buf[42];
  if (read(sock, &buf, sizeof(buf)) < 0)
    return(EXIT_FAILURE); 
          
  return(EXIT_SUCCESS);
}
