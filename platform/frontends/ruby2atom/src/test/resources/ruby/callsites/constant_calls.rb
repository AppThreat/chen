class Client
  def fetch(i, url)
    Faraday::Utils.escape(i)
    Faraday::Connection.new(url)
    conn = Faraday::Connection.new(url)
    conn.get("/x")
    conn[:a]
    conn.timeout = 3
  end

  def reassigned(url)
    client = Net::HTTP.new(url)
    client = Net::HTTP::Post.new(url)
    client.start
  end

  def parameter(client)
    client = Net::HTTP.new("x")
    client.start
  end

  def blocky(url)
    http = Net::HTTP.new(url)
    [1].each { |http| http.start }
    http.finish
  end

  def project
    Local.new
  end
end

class Local; end
