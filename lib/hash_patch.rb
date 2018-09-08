class Hash
  def nested_each(father=nil)
    self.each_pair do |k,v|
      if v.is_a?(Hash)
        v.nested_each(k) { |k, v, f| yield k, v, f }
      else
        yield(k, v, father)
      end
    end
  end
end
