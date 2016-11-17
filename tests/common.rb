require 'json_expressions/minitest'
require 'tempfile'
require './constants.rb'
require './pkt_scripts.rb'

# Create Boolean module as suggested by Jansson library.
# http://stackoverflow.com/questions/3028243/check-if-ruby-object-is-a-boolean#answer-3028378
module Boolean; end
class TrueClass; include Boolean; end
class FalseClass; include Boolean; end

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

# Packetdrill forks a bunch of programs such as ip, sh, etc. Assuming the 
# DEFAULT_PATH was emptied before executing the test, then our log should be
# in the ONLY directory starting with packetdrill_*. In case it was not emptied, we should NOT expect last to be the last created directory.
def log_dir_str
  Dir[DEFAULT_PATH+"/packetdrill_*"].last
end

# Not very robust but it seems that packetdrill always open another TCP connection
# before the script. So the first connection we are interested in is at /1/
def json_dump(con_id=1)
  File.read(log_dir_str+"/#{con_id}/"+JSON_FILE)
end

def assert_event_present(type, success=true)
  pattern = {
    events: [
      {
        type: type,
        success: success
      }.ignore_extra_keys!
    ].ignore_extra_values!
  }.ignore_extra_keys!
  assert_json_match(pattern, json_dump)
end

def log_file_str
  log_dir_str+"/"+LOG_FILE
end

def no_error_log
  !system("grep \"#{LOG_LVL_ERROR}\" #{log_file_str}")
end

