class ProfileLoader
  def load
    UserProfile.find(1)
    Missing.find(2)
    STATUSES.each { |status| status }
  end
end
