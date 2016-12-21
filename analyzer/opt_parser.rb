class OptParser 
  def self.parse(args)
    options = OpenStruct.new
    options.verbose = false

    begin
      OptionParser.new do |opts|
        opts.banner = "Usage: #{EXECUTABLE} [-h] [options] [file]..."
        opts.separator ""
        opts.separator "Analyze tcpsnitch JSON traces."
        opts.separator ""
        opts.separator "Options:"

        opts.on_tail("-h", "--help", "show this help text") do 
          puts opts
          exit
        end
      
        opts.on_tail("-v", "--verbose", "verbose mode") do
          options.verbose = true
        end

        opts.on_tail("--version", "show version") do 
          puts VERSION
          exit
        end
      end.parse!(args) # OptionParser
    rescue Exception => e 
      error(e)
      exit 1 
    end

    options
  end # parse
end

