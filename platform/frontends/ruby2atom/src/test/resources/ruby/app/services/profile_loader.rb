class ProfileLoader
  def load
    UserProfile.find(1)
    Missing.find(2)
  end
end
