LIMIT = 3

module Shop
  class Cart; end

  def self.build(items)
    Cart.new
    Receipt.new
    LIMIT.times { }
    Json::Schema.check(items)
  end

  module Inner
    def self.lookup
      Cart.find(1)
      Cache.fetch(2)
    end
  end
end

module Other
  def self.build
    Cart.new
  end
end

class Reopened
  def go
    ::Absolute.run
    Absolute.run
  end
end

class String
  def shout
    Settings::LEVEL
  end
end

def risky
  yield
rescue Net::ReadTimeout, ::Timeout::Error => e
  e
rescue Shop::Cart
  nil
end

def refs(x)
  x.is_a?(Faraday::Error)
  Foo::Bar::BAZ
end

def tail
  Rails.root
end
