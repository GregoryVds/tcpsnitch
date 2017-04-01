class CProg
  @@programs_path = "./c_programs/"
  @@count = 0

  def initialize(instructions, name)
    @instructions = instructions
    @name = name
    write_to_file
    @@count += 1
  end

  def program
<<-EOT
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
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
#{@instructions}
  return(EXIT_SUCCESS);
}
EOT
  end

  def path
    @@programs_path + @name + ".c"
  end

  def write_to_file
    f = File.open(path, "w")
    f.puts program
    f.close
  end

  def to_s
    @instructions
  end

  def assert_success
    if !system(exec_path) then puts "#{exec_path} failed!" end
  end
end

