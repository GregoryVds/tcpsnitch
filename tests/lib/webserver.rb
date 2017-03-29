class WebServer
  PORT = 8000
  @@started = false

  def self.start
    unless @@started
      cmd = "ruby -run -e httpd . -p #{PORT} >/dev/null 2>&1 & echo $!"
      @@pid = `#{cmd}`.chomp("\n")
      @@started = true
      sleep 0.01
    end
  end

  def self.stop
    system("kill #{@@pid}")
    @@started = false
  end
end

