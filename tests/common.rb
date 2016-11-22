require 'json_expressions/minitest'
require 'tempfile'
require 'packetfu'
require './constants.rb'
require './pkt_scripts.rb'

# Create Boolean module as suggested by Jansson library.
# http://stackoverflow.com/questions/3028243/check-if-ruby-object-is-a-boolean#answer-3028378
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

def dir_exists?(path)
  system("test -d #{path}")
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

# Assumes the DEFAULT_PATH was cleared before running the prog.
def log_dir_str(prog)
  Dir[DEFAULT_PATH+"/#{prog}_*"].last
end

def log_file_str(prog)
  log_dir_str(prog)+"/"+LOG_FILE
end

def con_dir_str(prog, con_id)
  log_dir_str(prog)+"/#{con_id}/"
end

def json_file_str(prog, con_id)
  con_dir_str(prog, con_id)+JSON_FILE
end

def pcap_file_str(prog, con_id)
  con_dir_str(prog, con_id)+PCAP_FILE
end

def read_json(prog, con_id)
  File.read(json_file_str(prog, con_id))
end

##################
# Others helpers #
##################

def run_exec(exec, env='')
  system("#{env} #{LD_PRELOAD} #{exec} >/dev/null 2>&1") 
end

def run_pkt_script(script, env='')
  file = Tempfile.new("foo")
  file.write(script)
  file.close
  cmd = env + " #{LD_PRELOAD} #{PACKET_DRILL} #{file.path} >/dev/null 2>&1" 
  rc = system(cmd) 
  file.unlink
  rc
end

def run_curl
  run_exec("curl -s google.com", "NETSPY_DEV=enp0s3")
#  system("#{LD_PRELOAD} NETSPY_DEV=enp0s3 curl -s google.com > /dev/null 2>&1") 
end

def errors_in_log?(log_path)
  system("grep \"#{LOG_LVL_ERROR}\" #{log_path}")
end

