class ProportionStat
  @@count = 0
  @@hash = Hash.new(0)

  def initialize(val)
    @@count += 1
    @@hash[val] += 1
  end

  def self.print
    puts "Proportion analysis:"
    @@hash.sort_by { |val, count| -count }.each do |val, count|
      pc = ((count.to_f/@@count) * 100).round(2)
      puts "#{val}".ljust(20) + "#{pc}%".ljust(7) + "(#{count})"
    end
    puts "TOTAL".ljust(20) + "100%".ljust(7) + "(#{@@count})" 
  end

end
