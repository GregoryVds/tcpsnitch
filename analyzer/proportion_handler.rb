class ProportionHandler
  @@count = 0
  @@hash = Hash.new(0)

  def initialize(init)
    @@count += 1
    @@hash[init] += 1
  end

  def self.print
    @@hash.sort_by { |val, count| -count }.each do |val, count|
      pc = ((count.to_f/@@count) * 100).round(1)
      puts "#{val}".ljust(20) + "#{pc}%".ljust(7) + "(#{count})"
    end
    puts "TOTAL".ljust(20) + "100%".ljust(7) + "(#{@@count})" 
  end

end
