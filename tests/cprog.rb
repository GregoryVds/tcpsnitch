class CProg
  @@programs_path = "./c_programs/"
  @@count = 0
  
  def initialize(instructions, name)
    @instructions = instructions
    @name = name
    write_to_file
    compile
    assert_success
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

int main(void) {
#{@instructions}          
  return(EXIT_SUCCESS);
}
EOT
  end

  def numbered_name
    format('%02d', @@count) + '_' + @name
  end
  
  def c_path
    @@programs_path + numbered_name + ".c"
  end

  def exec_path
    @@programs_path + numbered_name + ".out"
  end

  def write_to_file
    f = File.open(c_path, "w")
    f.puts program
    f.close
  end
  
  def compile
    system("gcc -Wall -Wextra #{c_path} -o #{exec_path} >/dev/null") 
  end

  def to_s
    @instructions
  end

  def assert_success
    if !system(exec_path) then puts "#{exec_path} failed!" end 
  end
end

