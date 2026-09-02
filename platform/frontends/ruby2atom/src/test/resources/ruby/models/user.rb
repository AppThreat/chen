class User
  attr_accessor :email

  def name
    @email.to_s
  end
end
