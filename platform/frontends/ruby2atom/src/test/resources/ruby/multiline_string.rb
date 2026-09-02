msg = "line one
line two"
sql = <<~SQL
  select * from users
SQL
puts msg
puts sql
