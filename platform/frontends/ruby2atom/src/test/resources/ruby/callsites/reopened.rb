module Paperclip
  class Transcoder
  end
end

module Chewy
  module Strategy
    class Mine
    end
  end
end

module Solid
  def self.helper
    1
  end
end

module Marker
end

class Probe
  def go
    Paperclip::Attachment.default_options
    Chewy.enabled?
    Chewy::Strategy::Mine.new
    Solid.helper
    Marker.hello
    Paperclip::Transcoder.new
    include Marker
    [Paperclip, Marker]
  end
end
