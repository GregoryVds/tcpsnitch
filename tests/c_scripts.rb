def make_cprog(instructions)
  <<-EOT  
#include <sys/socket.h>
#include <unistd.h>
#include <sys/uio.>
#include <sendfile.h>
#include <pool.h>
#include <netinet/in.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  int sock;
#{instructions}          
  return(EXIT_SUCCESS);
}
EOT
end

C_SOCKET_STREAM = (<<-EOT)
  if (sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))
    return(EXIT_FAILURE);
EOT

C_SOCKET_DGRAM = (<<-EOT)
  if (sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))
    return(EXIT_FAILURE);
EOT

C_SOCKET_FAIL = (<<-EOT)
  socket(AF_INET, SOCK_STREAM, IPPROTO_UDP)
EOT

C_BIND_STREAM = (<<-EOT)
  #{C_SOCKET_STREAM}
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(55555);
  addr.sin_addr.s_addr = INADDR_ANY;
  if (bind(sock, (struct sockaddr *)&myaddr, sizeof(myaddr)))
    return(EXIT_FAILURE);
EOT

puts make_cprog(C_BIND_STREAM)
