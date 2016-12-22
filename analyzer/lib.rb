def camelize(str)
  str.split('_').collect(&:capitalize).join
end

def error(msg)
  puts "#{EXECUTABLE}: #{msg}."
  puts "Try '#{EXECUTABLE} -h' for more information."
end

def filter(hash, filter)
  if filter then
    hash[:type] == filter ? hash : nil
  else
    hash
  end
end

def val_for(hash, keys)
    keys.reduce(hash) { |h, key| h[key] }
end

def keys_from_path(path)
  path.split('.').collect(&:to_sym)
end

def node_val(hash, path)
  val_for(hash, keys_from_path(path))
end
