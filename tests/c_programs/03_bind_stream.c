#include <sys/socket.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/sendfile.h>
#include <poll.h>
#include <netinet/in.h>
#include <stdlib.h>

int main(void) {
    int sock;
  if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
    return(EXIT_FAILURE);

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(55555);
  addr.sin_addr.s_addr = INADDR_ANY;
  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)))
    return(EXIT_FAILURE);
          
  return(EXIT_SUCCESS);
}
