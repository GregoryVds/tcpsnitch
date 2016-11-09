require 'tempfile'

NETSPY_PATH=`pwd`.chomp("\n")+"/../libnetspy.so"
puts NETSPY_PATH

LD_PRELOAD="LD_PRELOAD=../libnetspy.so"
PACKET_DRILL="packetdrill --tolerance_usecs=10000000"

# packetdrill scripts
PKT_SCRIPTS_PATH="./pkt_scripts"

DEFAULT_PATH="/tmp/netspy"
JSON_FILE="dump.json"
PCAP_FILE="dump.pcap"
LOG_FILE="log.txt"

# Env variables
ENV_PATH="NETSPY_PATH"
ENV_BYTES_IVAL="NETSPY_BYTES_IVAL"
ENV_MICROS_IVAL="NETSPY_MICROS_IVAL"

def mkdir(path)
  system("test -d #{path} || mkdir #{path}")
end

def rmdir(path)
  system("rm -rf #{dir}")
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

def run_pkt_cmd_str(path, env='')
  cmd = "#{LD_PRELOAD} #{PACKET_DRILL} #{path} 2>/dev/null" 
  if env then env+' '+cmd else cmd end
end

def run_pkt_script(script, env='')
  file = Tempfile.new("foo")
  file.write(script)
  file.close
  rc = system(run_pkt_cmd_str(file.path, env)) 
  file.unlink
  rc
end

