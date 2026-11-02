class Migrate < ActiveRecord::Migration[7.2]
end

class Pair < Struct.new(:left, :right)
end

class Logs
  def go
    Rails.logger.info("x")
    Rails.application.config.mode.managed?
    Faraday::Utils::CONFIG[:key]
  end
end

class Failure < StandardError
end

class Slots
  def current
    ::Thread.current[:slot]
  end
end
