require 'descriptive_statistics'
require 'gnuplot'

class DescriptiveStat
  @@data = []

  def self.add_val(val)
    if val.is_a? Integer
      @@data.push(val)
    else
      error("invalid value for descriptive statistics: '#{val}'")
      exit 1
    end
  end

  def self.print(options)
    puts "Descriptive statistics:"
    @@data.descriptive_statistics.each do |key, value|
      puts "#{key}".ljust(20) + "#{value}" 
    end
    
    # Only plot CDF is we have a range
    return unless @@data.range > 0 

    x = @@data.sort
    n = x.size
    y = x.map do |el|
      ((x.rindex { |v| v <= el } || -1.0) + 1.0) / n * 100.0
    end

    Gnuplot.open do |gp|
      Gnuplot::Plot.new(gp) do |plot|
        plot.xrange "[#{@@data.min}:#{@@data.max}]; set logscale x"
        plot.title  "CDF for #{options.node_path} (#{options.filter} events)"
        plot.xlabel "Value"
        plot.ylabel "Normal CDF"
        plot.data << Gnuplot::DataSet.new([x,y]) do |ds|
          ds.with = "lines"
          ds.linewidth = 4
          ds.title = options.node_path.split('.').last
        end
      end
    end
  end
end
