require 'descriptive_statistics'

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

  def self.print
    puts "Descriptive statistics:"
    @@data.descriptive_statistics.each do |key, value|
      puts "#{key}".ljust(20) + "#{value}" 
    end
  end
end

