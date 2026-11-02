def kernel_functions(value)
  Array(value)
  Hash(value)
  raise "boom" if value.nil?
  (..10).cover?(value)
  Array.new(2)
end
