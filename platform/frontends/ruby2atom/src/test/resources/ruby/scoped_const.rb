module Outer
  class Inner
    def ping = :pong
  end
end
service = Outer::Inner.new
puts service.ping
puts Outer::Inner::MAX
