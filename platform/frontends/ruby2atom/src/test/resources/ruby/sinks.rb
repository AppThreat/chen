class UsersController < ApplicationController
  def show
    id = params[:id]
    User.where("id = '#{id}'")
    User.where(id: id)
    system("ls #{id}")
    `cat #{id}`
    Marshal.load(Base64.decode64(params[:data]))
    File.open(params[:path])
    send_file params[:file]
    redirect_to params[:url]
    redirect_to "/home"
    render inline: params[:tpl]
    render "show"
    eval(params[:code])
    params[:klass].constantize
    current_user.send(params[:m])
    ActiveRecord::Base.send(:include, Auditing)
    IO.popen(params[:cmd])
    Open3.capture2("git", params[:ref])
    ActiveRecord::Base.connection.execute("SELECT * FROM t WHERE c = #{id}")
    params[:html].html_safe
    redirect_to root_url
  end
end
