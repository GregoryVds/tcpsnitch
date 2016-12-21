def camelize(str)
  str.split('_').collect(&:capitalize).join
end

def error(msg)
  puts "#{EXECUTABLE}: #{msg}."
  puts "Try '#{EXECUTABLE} -h' for more information."
end


