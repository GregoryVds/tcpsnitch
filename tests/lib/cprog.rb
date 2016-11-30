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
#{@instructions}          
  return(EXIT_SUCCESS);
}
EOT
  end

  def numbered_name
    format('%02d', @@count) + '_' + @name
  end
  
  def path
    @@programs_path + numbered_name + ".c"
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

