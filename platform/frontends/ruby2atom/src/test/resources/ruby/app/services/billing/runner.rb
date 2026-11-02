module Billing
  class Runner
    def go
      Invoice.build
    end
  end
end

class Elsewhere
  def go
    Invoice.build
  end
end
