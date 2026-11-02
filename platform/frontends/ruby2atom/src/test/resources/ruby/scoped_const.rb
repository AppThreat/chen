module Outer
  class Inner
    MAX = 3
    def ping = :pong
  end
end
service = Outer::Inner.new
puts service.ping
puts Outer::Inner::MAX
