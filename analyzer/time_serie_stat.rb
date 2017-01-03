class TimeSerieStat
  @@x = []
  @@y = []

  def self.add_point(timestamp, y)
    usec = timestamp[:sec] * 1000000 + timestamp[:usec]
    @@min ||= usec
    @@x.push(usec-@@min)
    @@y.push(y)
  end

  def self.print(options)
    puts "Time serie plot"
    
    if @@x.empty? then 
      no_data_error
      return
    end

		Gnuplot.open do |gp|
  		Gnuplot::Plot.new(gp) do |plot|
				plot.title  "Time serie: #{options.node_path}(t)"
				plot.xlabel "Micro seconds"
				plot.ylabel options.node_path.split('.').last.capitalize
			
				plot.data << Gnuplot::DataSet.new([@@x,@@y]) do |ds|
					ds.with = "lines"
					ds.linewidth = 4
          ds.notitle
				end
			end
  	end
  end

end
