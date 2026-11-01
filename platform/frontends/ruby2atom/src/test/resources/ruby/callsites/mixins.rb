module Helpers; end
class Base; end

class Handler < Faraday::Middleware
  include Rack::Utils
  include Helpers
  extend Forwardable
  prepend Observable
  include Left, Right::Mixin

  def setup
    include Late
  end
end

class Project < Base
  include Helpers
end
