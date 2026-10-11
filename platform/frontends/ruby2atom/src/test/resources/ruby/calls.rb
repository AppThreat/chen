class Benefits
  def self.save(file, backup)
    system("cp #{file} #{backup}")
  end

  def helper(x)
    x
  end

  def run(y)
    helper(y)
  end
end

module Admin
  class User
    def self.find_by_token(t)
      t
    end
  end
end

class BenefitFormsController
  def upload
    Benefits.save(params[:file], params[:backup])
    Admin::User.find_by_token(params[:t])
    User.find_by(id: params[:id])
  end
end
