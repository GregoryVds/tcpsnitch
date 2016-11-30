class WebServer
  PORT = 8000
  @@pid
 
  def self.start
    cmd = "ruby -run -e httpd . -p #{PORT} >/dev/null 2>&1 & echo $!" 
    @@pid = `#{cmd}`.chomp("\n")
  end

  def self.stop
    system("kill #{@@pid}")
  end
end

