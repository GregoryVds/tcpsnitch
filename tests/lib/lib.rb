require 'json_expressions/minitest'
require 'tempfile'
require './lib/constants.rb'
require './lib/webserver.rb'

# Create Boolean module as suggested by Jansson library.
# http://stackoverflow.com/questions/3028243/check-if-ruby-object-is-a-boolean
module Boolean; end
class TrueClass; include Boolean; end
class FalseClass; include Boolean; end

###########################
# Directory manipulations #
###########################

def mkdir(path)
  system("test -d #{path} || mkdir #{path}")
end

def rmdir(path)
  system("rm -rf #{path}")
end

def file_exists?(path)
  system("test -f #{path}")
end

def contains?(dir, el)
  system("ls #{dir}/#{el} >/dev/null 2>&1")
end

def dir_empty?(path)
  !system("ls #{path}/* >/dev/null 2>&1")
end

def reset_dir(path)
  rmdir(path)
  mkdir(path)
end

###########################
# Log files manipulations #
###########################

def process_dirs
  Dir[TEST_DIR+"/"+PROCESS_DIR_REGEX]
end

# Assumes the TEST_DIR was cleared before running the prog.
def dir_str 
  process_dirs.last
end

def log_file_str
  dir_str+"/"+LOG_FILE
end

def json_file_str(con_id=0)
  dir_str+"/#{con_id}.json"
end

def pcap_file_str(con_id=0)
  dir_str+"/#{con_id}.pcap"
end

def read_json_trace(con_id=0)
  File.read(json_file_str(con_id))
end

def wrap_as_array(json_trace)
  json_trace.split("\n").join(',').insert(0,"[").insert(-1,"]")
end

# This builds a valid JSON array from the JSON object in the file
def read_json_as_array(con_id=0)
  wrap_as_array(read_json_trace(con_id))
end

##################
# Others helpers #
##################

def run_exec(exec, env='')
  system("#{env} #{LD_PRELOAD} #{exec} >/dev/null 2>&1") 
end

def tcpsnitch(options='', cmd='')
  system("#{EXECUTABLE} #{options} #{cmd} >/dev/null 2>&1")
end

def tcpsnitch_output(options='', cmd='')
  `#{EXECUTABLE} #{options} #{cmd} 2>&1`
end

def run_c_program(name, opts='')
  reset_dir(TEST_DIR) 
  tcpsnitch("-d #{TEST_DIR} #{opts}", "./c_programs/#{name}.out")
end

def run_curl
  run_exec("curl -s google.com", "NETSPY_DEV=enp0s3")
#  system("#{LD_PRELOAD} NETSPY_DEV=enp0s3 curl -s google.com > /dev/null 2>&1") 
end

def errors_in_log?(log_file=log_file_str)
  system("grep \"#{LOG_LABEL_ERROR}\" #{log_file}")
end

#######################
# Packetdrill helpers #
#######################

PKT_CONNECTED_SOCKET = <<-EOT
  0 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3
  0.0...0.1 connect(3, ..., ...) = 0
  *  > S  0:0(0) <...>
  +0 < S. 0:0(0) ack 1 win 1000
  *  > .  1:1(0) ack 1
EOT
