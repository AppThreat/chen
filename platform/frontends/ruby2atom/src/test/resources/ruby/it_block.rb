items = [1, 2, 3]
evens = items.select { it.even? }
items.each do
  puts it * 10
end
