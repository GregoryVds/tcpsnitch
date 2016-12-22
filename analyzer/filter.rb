class Filter
  def self.trim(hash, filter)
    hash[:type] == filter ? hash[:type] : nil
  end
end
