class OptParser 
  def self.parse(args)
    options = OpenStruct.new
    options.aggregate = false
    options.verbose = false
    options.filter = nil 
    options.node_path = "type"
      
    begin
      OptionParser.new do |opts|
        opts.banner = "Usage: #{EXECUTABLE} [-aehn] [options] [file]..."
        opts.separator ""
        opts.separator "Analyze tcpsnitch JSON traces."
        opts.separator ""
        opts.separator "Options:"

        opts.on_tail("-a", "--agreggate", "stats for numeric valued node") do
          options.aggregate = true
        end
  
        opts.on("-f", "--filter [EVENT]", "filter on events of type EVENT") do |ev|
          options.filter = ev          
        end

        opts.on_tail("-h", "--help", "show this help text") do 
          puts opts
          exit
        end
 
        opts.on("-n", "--node [PATH]", "compute on node at PATH") do |node| 
          options.node_path = node 
        end
  
        opts.on_tail("-v", "--verbose", "verbose mode") do
          options.verbose = true
        end

        opts.on_tail("--version", "show version") do 
          puts VERSION
          exit
        end
      end.parse!(args) # OptionParser
    rescue OptionParser::ParseError => e 
      error(e)
      exit 1 
    end

    options
  end # parse
end

